#!/usr/bin/env python3
"""
benignd.py -- per-node HARD BENIGN WORKLOAD daemon (systemd service on each board).

Runs ALWAYS-ON for the whole campaign, concurrently with attacks, so no attack
window is separable by activity level (Phase-0 anti-sessionisation principle #1).
It reads workloads.yaml, and for every workload whose `hosts` list contains this
device it schedules invocations at Poisson-distributed inter-arrivals (seeded for
reproducibility), launches the workload's command, and appends a ground-truth
row to benign_activity.csv. Long-lived (`rate_s: 0`) workloads are started once
and supervised (restarted if they die).

Design obligations it satisfies (from P4-P7):
  * SAME-CAMPAIGN concurrency  -> started at campaign start, never per-attack.
  * SESSION grouping key       -> each invocation gets a unique session_id so the
                                  pipeline can group splits by session (no window
                                  leakage; P7c).
  * STATIC/DYNAMIC linkage mix -> `linkage` rotated per invocation, recorded per
                                  row (P7a loader-signature shortcut).
  * DUAL CLOCK + device_id      -> every row carries CLOCK_REALTIME + CLOCK_MONOTONIC
                                  + device_id, matching orchestrator.py / telemetry_reader.py.
  * Reproducibility            -> RNG seeded from campaign_seed ^ hash(device_id, workload_id).

Placeholders in cmd (resolved from nodes.yaml roles / an --extra k=v map):
  {mirror_ip} {mqtt_broker} {svc_host} {ipcam_ip} {backup_host} {health_host}
  {health_port} {linkage}

Usage:
  python3 benignd.py --workloads workloads.yaml --nodes ../nodes.yaml \
        --self rpi3b-1 --extra mirror_ip=10.0.0.1 mqtt_broker=10.0.0.11 \
        --out /var/log/testbed/benign [--dry-run]

This daemon launches only benign application/admin workloads. It never launches
an attack action -- attack timing is owned by the separate orchestrator.
"""
import argparse, csv, os, random, socket, subprocess, sys, threading, time, uuid, hashlib
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DEVICE_ID = socket.gethostname()

FIELDS = ["device_id", "session_id", "workload_id", "kind", "linkage",
          "overlaps_stage", "neutralises", "start_iso", "end_iso",
          "start_mono", "end_mono", "rc", "seed", "cmd"]


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML required: pip install pyyaml")
    with open(path) as f:
        return yaml.safe_load(f)


def now():
    return datetime.now(timezone.utc).isoformat(), time.monotonic()


def seed_for(campaign_seed, device_id, workload_id):
    h = hashlib.sha256(f"{device_id}:{workload_id}".encode()).hexdigest()
    return (int(campaign_seed) ^ int(h[:8], 16)) & 0x7FFFFFFF


def build_subs(nodes, extra):
    roles = nodes.get("roles", {}) if nodes else {}
    n = nodes.get("nodes", {}) if nodes else {}

    def ip_of(role):
        dev = roles.get(role, "")
        return n.get(dev, {}).get("ip", "") if dev else ""

    subs = {
        "mirror_ip": ip_of("mirror") or ip_of("collector") or ip_of("gateway"),
        "backup_host": ip_of("collector") or ip_of("gateway"),
        "mqtt_broker": "", "svc_host": "", "ipcam_ip": "",
        "health_host": "127.0.0.1", "health_port": "8080", "linkage": "dynamic",
    }
    subs.update(extra or {})
    return subs


class Annotator:
    """Thread-safe append-writer for benign_activity.csv."""
    def __init__(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self._lock = threading.Lock()
        new = not os.path.exists(path)
        self._fh = open(path, "a", newline="")
        self._w = csv.DictWriter(self._fh, fieldnames=FIELDS)
        if new:
            self._w.writeheader(); self._fh.flush()

    def write(self, row):
        with self._lock:
            self._w.writerow({k: row.get(k, "") for k in FIELDS})
            self._fh.flush()


def resolve(cmd, subs, linkage):
    s = dict(subs); s["linkage"] = linkage
    try:
        return cmd.format(**s)
    except KeyError as e:
        # leave unknown placeholders literal rather than crash the campaign
        return cmd.replace("{" + str(e).strip("'") + "}", "")


def run_once(wl, subs, annot, dry):
    linkages = wl.get("linkage", ["dynamic"])
    linkage = random.choice(linkages)
    cmd = resolve(wl["cmd"], subs, linkage)
    session_id = uuid.uuid4().hex[:12]
    s_iso, s_mono = now()
    rc = 0
    if dry:
        print(f"    [dry-run] {DEVICE_ID} {wl['id']} ({linkage}) -> {cmd}")
    else:
        try:
            rc = subprocess.call(cmd, shell=True, cwd=HERE,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            rc = -1
            print(f"    [warn] {wl['id']} failed: {e}", file=sys.stderr)
    e_iso, e_mono = now()
    if wl.get("annotate", True):
        annot.write({
            "device_id": DEVICE_ID, "session_id": session_id, "workload_id": wl["id"],
            "kind": wl.get("kind", ""), "linkage": linkage,
            "overlaps_stage": wl.get("overlaps_stage", ""),
            "neutralises": "|".join(wl.get("neutralises", [])),
            "start_iso": s_iso, "end_iso": e_iso,
            "start_mono": f"{s_mono:.3f}", "end_mono": f"{e_mono:.3f}",
            "rc": rc, "seed": wl.get("_seed", ""), "cmd": cmd,
        })


def poisson_loop(wl, subs, annot, dry, jitter):
    """Recurring workload: sleep ~Exp(rate_s), run once, repeat."""
    rate = float(wl.get("rate_s", 300)) or 300.0
    while True:
        wait = random.expovariate(1.0 / rate)
        wait *= random.uniform(1 - jitter, 1 + jitter)
        if dry:
            print(f"    [dry-run] {wl['id']} would wait {wait:.0f}s")
            time.sleep(0.05)                      # fast-forward in dry-run
        else:
            time.sleep(max(1.0, wait))
        run_once(wl, subs, annot, dry)
        if dry:
            return                                # one pass is enough for a dry-run


def supervise_longlived(wl, subs, annot, dry):
    """rate_s == 0: start once, restart on exit (service-traffic / discovery daemons)."""
    linkage = random.choice(wl.get("linkage", ["dynamic"]))
    cmd = resolve(wl["cmd"], subs, linkage)
    if dry:
        print(f"    [dry-run] {DEVICE_ID} long-lived {wl['id']} -> {cmd}")
        return
    while True:
        session_id = uuid.uuid4().hex[:12]
        s_iso, s_mono = now()
        rc = subprocess.call(cmd, shell=True, cwd=HERE,
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        e_iso, e_mono = now()
        if wl.get("annotate", True):
            annot.write({
                "device_id": DEVICE_ID, "session_id": session_id, "workload_id": wl["id"],
                "kind": wl.get("kind", ""), "linkage": linkage,
                "overlaps_stage": wl.get("overlaps_stage", ""),
                "neutralises": "|".join(wl.get("neutralises", [])),
                "start_iso": s_iso, "end_iso": e_iso,
                "start_mono": f"{s_mono:.3f}", "end_mono": f"{e_mono:.3f}",
                "rc": rc, "seed": wl.get("_seed", ""), "cmd": cmd,
            })
        time.sleep(5.0)                           # brief backoff before restart


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workloads", default=os.path.join(HERE, "workloads.yaml"))
    ap.add_argument("--nodes", default=os.path.join(HERE, "..", "nodes.yaml"))
    ap.add_argument("--self", dest="self_id", default=DEVICE_ID,
                    help="device_id of THIS node as it appears in workloads.yaml hosts")
    ap.add_argument("--extra", nargs="*", default=[], help="k=v placeholder overrides")
    ap.add_argument("--out", default="/var/log/testbed/benign")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    man = load_yaml(a.workloads)
    nodes = load_yaml(a.nodes) if os.path.exists(a.nodes) else {}
    defaults = man.get("defaults", {})
    jitter = float(defaults.get("jitter", 0.35))
    extra = dict(kv.split("=", 1) for kv in a.extra if "=" in kv)
    subs = build_subs(nodes, extra)

    annot_path = os.path.join(a.out, "benign_activity.csv")
    annot = Annotator(annot_path)

    wls = man["workloads"] if isinstance(man, dict) and "workloads" in man else \
        (man if isinstance(man, list) else [])
    # benignd runs ON-DEVICE workloads only; admin sessions (runner: admin_session)
    # are driven by admin_driver.py (from the control machine / a benign operator).
    mine = [w for w in wls
            if a.self_id in w.get("hosts", []) and w.get("runner", "benignd") == "benignd"]

    campaign_seed = defaults.get("campaign_seed", 0)
    print(f"[benignd] device={a.self_id} workloads={len(mine)} dry={a.dry_run} -> {annot_path}")

    threads = []
    for wl in mine:
        wl["_seed"] = seed_for(campaign_seed, a.self_id, wl["id"])
        random.seed(wl["_seed"])                  # per-workload deterministic stream
        if int(wl.get("rate_s", 0)) == 0:
            t = threading.Thread(target=supervise_longlived, args=(wl, subs, annot, a.dry_run), daemon=True)
        else:
            t = threading.Thread(target=poisson_loop, args=(wl, subs, annot, a.dry_run, jitter), daemon=True)
        t.start(); threads.append(t)
        print(f"  + {wl['id']} kind={wl.get('kind')} rate_s={wl.get('rate_s')} "
              f"overlaps={wl.get('overlaps_stage')} seed={wl['_seed']}")

    if a.dry_run:
        for t in threads:
            t.join(timeout=5)
        print("[benignd] dry-run complete")
        return
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    main()
