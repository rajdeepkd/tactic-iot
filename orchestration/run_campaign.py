#!/usr/bin/env python3
"""
run_campaign.py -- orchestrate ONE labelled campaign run from the Windows control
box. Reads campaigns.yaml, generates a hub-side bash script of run_action.sh calls
(network stages run on the hub; host stages ssh into the victim via the hub->victim
key), ships + runs it on the hub so ALL labels.csv timestamps are on the master
clock. Scale the dataset by calling this many times with different --run-idx across
both victims.

Sub-labels: labels.csv attack_type = fine (recon_synscan, bruteforce_slow, ...),
stage = coarse (recon, bruteforce, ...). No schema change; align carries both.

Usage:
  python run_campaign.py --scenario R01 --run-idx 0 --victim-ip 192.168.0.32 \
      --vname rpi3b1 --victim2-ip 192.168.0.33 --hub cnc@192.168.0.50 \
      [--stages recon_synscan,execution_lolbin] [--baseline-gap 20] [--timeout 900]
"""
import argparse, os, random, re, subprocess, sys, tempfile
import yaml

KEY = os.path.expanduser("~/.ssh/obj3_testbed")
HERE = os.path.dirname(os.path.abspath(__file__))


def _single_shot(cmd, iters):
    """B3 fix: collapse a looped host/protocol action to a few iterations so a
    single-shot run exists alongside the looped runs. Train-on-looped / test-on-
    single-shot then shows whether telemetry's role was a looping artifact. Only
    the per-stage loop bound `seq 1 N` is reduced; setup lines are untouched because
    this is applied to the stage cmd only, after placeholder substitution."""
    return re.sub(r"seq 1 \d+", "seq 1 %d" % iters, cmd)


def _extend(cmd, mult):
    """TOP-UP duration extension: repeat the WHOLE attack `mult` times so each labelled
    instance lasts ~mult x longer and yields proportionally more windows (a realistic
    longer scan/flood/brute). Wrapping the whole command works for ANY loop style --
    `seq 1 N`, a literal `for i in 1 2 3`, a time-bounded `while [-lt N]`, or an hping3
    `-c N` -- unlike rewriting one internal loop, which misses the others."""
    if mult <= 1:
        return cmd
    return "for _rep in $(seq 1 %d); do %s; done" % (mult, cmd)


def build_script(cfg, a):
    gap = a.baseline_gap if a.baseline_gap is not None else cfg["defaults"]["baseline_gap_s"]
    L = ["#!/bin/bash", "set -u",
         'OUT="$HOME/campaigns/%s"; SCEN="%s"; RUN="%s"' % (a.scenario, a.scenario, a.run_idx),
         'RA="bash $HOME/orchestrator/run_action.sh $OUT $SCEN $RUN"',
         'VIP="%s"; V2IP="%s"; VN="%s"; VK="$HOME/.ssh/hub_to_victim"' % (a.victim_ip, a.victim2_ip, a.vname),
         'seq -f wrongpw%g 1 150 > /tmp/wl.txt',   # 150 WRONG passwords -> dict-brute spans ~130s (bottleneck stage, boosted for yield); none is the real pw',
         'echo "== campaign $SCEN run $RUN =="', 'sleep %d' % gap]
    sel = None if a.stages == "all" else set(a.stages.split(","))
    # C2 fix: randomise stage order per run with a run-seeded shuffle, so the fixed
    # catalogue order no longer lets long-memory gauges (load5/15, temp) carry one
    # stage's state into the next on every run. The seed defaults to run_idx, so the
    # order is reproducible and recorded (build_dual_layout --order-seed <run_idx>).
    stages = [st for st in cfg["stages"]
              if not (sel and st["attack_type"] not in sel and st["stage"] not in sel)]
    # D2 fix: held-out OOD variants (masscan/medusa) are NOT part of the seen
    # training distribution. Drop them unless --include-held-out, or the run
    # explicitly names that attack_type/stage (a dedicated OOD collection run).
    def _explicit(st):
        return bool(sel and (st["attack_type"] in sel or st["stage"] in sel))
    stages = [st for st in stages
              if not st.get("held_out") or a.include_held_out or _explicit(st)]
    seed = a.order_seed if a.order_seed is not None else a.run_idx
    if a.shuffle_stages:
        random.Random(seed).shuffle(stages)
    ran = []
    for st in stages:
        at, stg = st["attack_type"], st["stage"]
        ran.append(at)
        if st.get("mode") == "slow":
            n = 1 if a.single_shot else st.get("attempts", 12) * a.duration_mult
            mn, mx = st.get("min_gap_s", 5), st.get("max_gap_s", 12)
            L += ['# low-and-slow: one labelled interval PER attempt (sparse signal in benign)',
                  'for i in $(seq 1 %d); do' % n,
                  '  $RA %s %s $VN -- hydra -l pi -p wrongslow$i -t1 -f ssh://$VIP' % (at, stg),
                  '  sleep $(( %d + RANDOM %% %d ))' % (mn, mx - mn + 1),
                  'done']
        else:
            # substitute LITERAL ips/paths (not shell vars): a wrapped victim-side
            # command is single-quoted, so $VIP would not expand there -- the target
            # must be baked in, while victim-side $(...)/$$ stay literal for the victim.
            cmd = (st["cmd"].replace("{VIP}", a.victim_ip).replace("{V2IP}", a.victim2_ip)
                   .replace("{WL}", "/tmp/wl.txt").replace("{VN}", a.vname))
            if a.single_shot:
                cmd = _single_shot(cmd, a.single_shot_iters)
            cmd = _extend(cmd, a.duration_mult)
            if st.get("on_victim"):
                cmd = "ssh -i $VK -o BatchMode=yes pi@$VIP '%s'" % cmd
            elif st.get("run_on") == "victim2":   # victim-as-attacker: run on the OTHER victim
                cmd = "ssh -i $VK -o BatchMode=yes pi@$V2IP '%s'" % cmd
            else:
                # hub-side: wrap in bash -c so COMPOUND commands (for-loops, ;, pipes)
                # exec as one unit (run_action.sh runs argv directly, no shell).
                # SINGLE-quote the payload (with '->'\'' escaping) so $(seq 1 N), $i,
                # $$, $RANDOM etc. are expanded by the INNER bash, not the outer set -u
                # hub shell. Double quotes were fatal: a bare body $i tripped set -u
                # ("i: unbound variable") and a multi-line $(seq 1 N) expansion broke
                # parsing (rc=2 syntax error) -- which silently killed EVERY IoT
                # $(seq) stage. All {VIP}/{V2IP}/{WL}/{VN} are already literal here, so
                # nothing in cmd needs the outer shell.
                cmd = "bash -c '%s'" % cmd.replace("'", "'\\''")
            L += ['$RA %s %s $VN -- %s' % (at, stg, cmd), 'sleep %d' % gap]
    L += ['echo "== done: %d actions =="' % len(ran)]
    return "\n".join(L) + "\n", ran


def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--scenario", required=True)
    ap.add_argument("--run-idx", type=int, default=0)
    ap.add_argument("--victim-ip", required=True)
    ap.add_argument("--vname", required=True)
    ap.add_argument("--victim2-ip", default="192.168.0.33")
    ap.add_argument("--hub", default="cnc@192.168.0.50")
    ap.add_argument("--stages", default="all", help="comma list of attack_type/stage, or 'all'")
    ap.add_argument("--baseline-gap", type=int, default=None)
    ap.add_argument("--shuffle-stages", action="store_true",
                    help="C2 fix: randomise stage order with a run-seeded shuffle")
    ap.add_argument("--order-seed", type=int, default=None,
                    help="stage-order seed (default: run_idx), for reproducibility")
    ap.add_argument("--single-shot", action="store_true",
                    help="B3 fix: collapse looped actions to --single-shot-iters iterations")
    ap.add_argument("--single-shot-iters", type=int, default=1)
    ap.add_argument("--duration-mult", type=int, default=1,
                    help="TOP-UP: multiply attack loop sizes/time-bounds by this factor so "
                         "each instance yields more labelled windows (longer scans/floods/brutes)")
    ap.add_argument("--hub-tag", default="",
                    help="unique tag for the hub script path + abort check, so per-victim "
                         "campaigns can run IN PARALLEL (e.g. the victim name)")
    ap.add_argument("--include-held-out", action="store_true",
                    help="D2: also run held_out OOD variants (default: skip them in normal runs)")
    ap.add_argument("--catalogue", default=os.path.join(HERE, "campaigns.yaml"))
    ap.add_argument("--timeout", type=int, default=3600)  # raised: full-port + scan-delay + 4 ddos subclasses + slow-brute run long, esp. on rpi3b2
    ap.add_argument("--poll-interval", type=int, default=20,
                    help="seconds between .done-marker polls for the detached campaign")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    cfg = yaml.safe_load(open(a.catalogue, encoding="utf-8"))
    script, ran = build_script(cfg, a)
    seed = a.order_seed if a.order_seed is not None else a.run_idx
    print("[campaign %s#%d] shuffle=%s seed=%d single_shot=%s stages: %s"
          % (a.scenario, a.run_idx, a.shuffle_stages, seed, a.single_shot, ", ".join(ran)))
    if a.dry_run:
        print(script); return

    # pre-flight: refuse to start if a campaign is ALREADY running on the hub.
    # (TaskStop/reap of a local driver does NOT kill the SSH-launched remote
    # hub_campaign.sh; a blind relaunch then runs CONCURRENT campaigns and
    # interleaves labels.csv -- exactly the contamination seen on 2026-09-29.)
    # bracket-trick pattern so the check's OWN remote shell (whose cmdline contains
    # the pattern) is not matched -- a plain 'hub_campaign.sh' pattern self-matches
    # and always reports BUSY.
    # --hub-tag gives this campaign its OWN hub script path + abort check, so two
    # campaigns (one per victim) can run IN PARALLEL without clashing. labels.csv
    # appends are atomic single lines (run_action.sh) and run_idx is unique per loop,
    # so the shared scenario labels stay clean.
    tag = ("_" + a.hub_tag) if a.hub_tag else ""
    hub_script = "/tmp/hub_campaign%s.sh" % tag
    chk = run('ssh -i "%s" -o BatchMode=yes %s "pgrep -f \'[h]ub_campaign%s.sh\' >/dev/null 2>&1 && echo BUSY || echo IDLE"' % (KEY, a.hub, tag))
    if "BUSY" in chk.stdout:
        print("ABORT: a %s is already running on %s -- refusing a concurrent "
              "campaign with this tag. Clean it up (sudo pkill -9 -f %s) first."
              % (os.path.basename(hub_script), a.hub, os.path.basename(hub_script)), file=sys.stderr)
        sys.exit(2)

    tmp = tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False, newline="\n")
    tmp.write(script); tmp.close()
    # SSH with keepalive so short network blips do not tear the control channel.
    SB = ('ssh -i "%s" -o BatchMode=yes -o ServerAliveInterval=20 -o ServerAliveCountMax=3 '
          '-o ConnectTimeout=20 %s') % (KEY, a.hub)
    rc = run('scp -i "%s" -o BatchMode=yes -o ConnectTimeout=20 "%s" %s:%s' % (KEY, tmp.name, a.hub, hub_script))
    os.unlink(tmp.name)
    if rc.returncode:
        print("scp failed:", rc.stderr, file=sys.stderr); sys.exit(1)

    # DISCONNECT-RESILIENT EXECUTION. The user's Wi-Fi drops mid-run. Running the
    # campaign THROUGH the live ssh session (ssh "timeout bash script") means a
    # disconnect SIGHUPs the remote campaign and it dies part-way (seen 2026-11-06:
    # "Connection reset by peer" after 5/27 stages). Instead launch it DETACHED with
    # setsid+nohup so it keeps running on the hub if the link drops, write a .done
    # marker on completion, then POLL for that marker and tolerate ssh read failures.
    out, done = hub_script + ".out", hub_script + ".done"
    launch = ('%s "rm -f %s %s; nohup setsid bash -c \'timeout %d bash %s > %s 2>&1; '
              'echo RC=\\$? > %s\' >/dev/null 2>&1 & echo LAUNCHED"'
              % (SB, out, done, a.timeout, hub_script, out, done))
    lr = run(launch)
    if "LAUNCHED" not in lr.stdout:
        print("launch failed:", lr.stdout, lr.stderr, file=sys.stderr); sys.exit(1)
    print("[campaign] launched DETACHED on hub (timeout %ds, script %s); polling .done..." % (a.timeout, hub_script))
    import time
    deadline = time.time() + a.timeout + 600   # grace over the remote timeout
    poll = max(10, a.poll_interval)
    status, fails = None, 0
    while time.time() < deadline:
        time.sleep(poll)
        chk = run('%s "cat %s 2>/dev/null"' % (SB, done))
        if chk.returncode == 0 and "RC=" in chk.stdout:
            status = chk.stdout.strip(); break
        # ssh itself failed (link down) -> tolerate, keep polling; the hub campaign runs on
        if chk.returncode != 0:
            fails += 1
            if fails % 10 == 0:
                print("[campaign] (poll: %d consecutive ssh read failures, hub campaign still running)" % fails, file=sys.stderr)
        else:
            fails = 0
    # fetch the campaign output for the log (best effort)
    o = run('%s "cat %s 2>/dev/null"' % (SB, out))
    if o.stdout:
        sys.stdout.write(o.stdout)
    if status is None:
        print("[campaign] NO .done marker before deadline -- campaign hung or was killed; "
              "cleaning any leftover on hub", file=sys.stderr)
        run('%s "sudo pkill -9 -f %s 2>/dev/null; true"' % (SB, os.path.basename(hub_script)))
        print("[campaign] rc=TIMEOUT ; labels -> %s:~/campaigns/%s/labels.csv" % (a.hub, a.scenario))
        sys.exit(2)
    # Success = the script printed its final "== done:" line (every stage ran). The
    # wrapper's own RC=$? is unreliable (a trailing sleep/`set -u` quirk makes a fully
    # completed script report 1), so we key off the completion marker in the output, not
    # the exit code. A timeout-killed run writes .done but never prints "== done:".
    ok = ("== done:" in (o.stdout or ""))
    m = re.search(r"RC=(\d+)", status)
    rawrc = m.group(1) if m else "?"
    print("[campaign] %s (wrapper RC=%s) ; labels -> %s:~/campaigns/%s/labels.csv"
          % ("COMPLETE" if ok else "INCOMPLETE", rawrc, a.hub, a.scenario))
    sys.exit(0 if ok else 2)


if __name__ == "__main__":
    main()
