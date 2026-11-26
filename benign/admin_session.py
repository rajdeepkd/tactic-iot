#!/usr/bin/env python3
"""
admin_session.py -- legitimate administrator SSH / Telnet session generator.

This is the benign counterpart to the flagship slow-brute-force scenario. A real
operator logs in, runs a short maintenance command sequence, and logs out -- and
OCCASIONALLY fat-fingers the password or username first (a benign FAILED-auth
event). Because these benign failures are interleaved, in the same campaign, with
the 1-try/25 s brute force, a single `Failed password` line in auth.log is no
longer diagnostic: only the CADENCE over a window (+ the network flow + sshd
telemetry) separates the two. That is exactly the stage-dependent, multi-source
claim Objective 3 must test.

IT IS NOT A BRUTE-FORCE TOOL. The operator HOLDS valid credentials/keys; there
is no wordlist; typo retries are capped (<= max_retries, default 3) at human
cadence (seconds apart, then success or give up); sessions are rate-limited by
benignd's Poisson schedule. All targets are the operator's own lab boards.

Runs from the WINDOWS CONTROL MACHINE (paramiko) or any operator node. To keep
benign auth from being tied to one source IP, run instances from >=2 origins
(the control PC and a board-to-board hop). Source IP/port are dropped by the
anti-leakage policy (scripts/common.py) regardless.

Deps: paramiko (SSH). Telnet uses a tiny stdlib socket client (no telnetlib
dependency, which is removed in Python 3.13). Degrades gracefully if paramiko
is absent (logs a warning and exits 0 so the campaign continues).

Usage:
  python3 admin_session.py --targets rpi3b-1,rpi5-silo --proto ssh \
       --creds creds.yaml --p-typo 0.18 --max-retries 3
"""
import argparse, os, random, socket, sys, time, uuid
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))

# A realistic short maintenance command sequence (read-only + a benign sudo edit).
# Deliberately overlaps the *host* side of recon/execution: it spawns and exits
# many short-lived helpers (df, ps, journalctl, systemctl, grep|awk pipelines).
ADMIN_CMDS = [
    "uptime",
    "df -h /",
    "free -m",
    "ps aux --sort=-%cpu | head -n 12",
    "journalctl -p warning -n 20 --no-pager",
    "systemctl --no-pager --type=service --state=running | head -n 15",
    "ss -tunp | head -n 20",
    "dmesg | tail -n 15",
    "sudo tail -n 5 /var/log/auth.log",
    "grep -c 'session opened' /var/log/auth.log || true",
    "vmstat 1 3",
]


def now():
    return datetime.now(timezone.utc).isoformat(), time.monotonic()


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        return {}
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        return yaml.safe_load(f) or {}


def mistype(s):
    """Human fat-finger: adjacent-key swap, drop, double, or case slip."""
    if not s:
        return s + "x"
    i = random.randrange(len(s))
    mode = random.choice(["drop", "double", "swap", "shift"])
    if mode == "drop":
        return s[:i] + s[i + 1:]
    if mode == "double":
        return s[:i] + s[i] + s[i:]
    if mode == "swap" and i + 1 < len(s):
        return s[:i] + s[i + 1] + s[i] + s[i + 2:]
    return s[:i] + s[i].swapcase() + s[i + 1:]


def annotate(annot_path, row):
    import csv
    fields = ["origin", "target", "proto", "session_id", "n_failed_auth",
              "outcome", "start_iso", "end_iso", "start_mono", "end_mono", "seed"]
    os.makedirs(os.path.dirname(annot_path) or ".", exist_ok=True)
    new = not os.path.exists(annot_path)
    with open(annot_path, "a", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=fields)
        if new:
            w.writeheader()
        w.writerow({k: row.get(k, "") for k in fields})


def ssh_session(target, host, cfg, p_typo, max_retries):
    """One benign SSH session. Returns (n_failed, outcome)."""
    try:
        import paramiko
    except ImportError:
        print("[admin_session] paramiko not installed; pip install paramiko", file=sys.stderr)
        return 0, "skipped_no_paramiko"

    user = cfg.get("ssh_user", "pi")
    good_pw = cfg.get("password")
    key_path = cfg.get("key_path")             # prefer key-based auth (like real ops)
    port = int(cfg.get("port", 22))

    n_failed = 0
    # Fat-finger model: with prob p_typo, mistype the password (or, rarely, the
    # username) 1..max_retries-1 times BEFORE the correct attempt.
    if good_pw and random.random() < p_typo:
        tries = random.randint(1, max_retries - 1)
        for _ in range(tries):
            cli = paramiko.SSHClient()
            cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            bad_user = mistype(user) if random.random() < 0.25 else user
            bad_pw = mistype(good_pw)
            try:
                cli.connect(host, port=port, username=bad_user, password=bad_pw,
                            look_for_keys=False, allow_agent=False, timeout=8)
                cli.close()                    # unexpectedly correct -> stop
                break
            except Exception:
                n_failed += 1                  # -> a benign 'Failed password' in auth.log
            finally:
                try: cli.close()
                except Exception: pass
            time.sleep(random.uniform(1.5, 4.0))   # human re-type delay

    # The real (successful) login: key first, else the correct password.
    cli = paramiko.SSHClient()
    cli.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        if key_path and os.path.exists(key_path):
            cli.connect(host, port=port, username=user, key_filename=key_path,
                        look_for_keys=False, allow_agent=False, timeout=10)
        elif good_pw:
            cli.connect(host, port=port, username=user, password=good_pw,
                        look_for_keys=False, allow_agent=False, timeout=10)
        else:
            return n_failed, "no_credentials"
    except Exception as e:
        print(f"[admin_session] login to {target} failed: {e}", file=sys.stderr)
        return n_failed, "login_failed"

    # Run a short, jittered maintenance sequence (spawns/exits helpers on target).
    seq = random.sample(ADMIN_CMDS, k=random.randint(4, 8))
    for cmd in seq:
        try:
            _in, out, err = cli.exec_command(cmd, timeout=20)
            out.channel.recv_exit_status()
        except Exception:
            pass
        time.sleep(random.uniform(0.8, 5.0))   # think-time between commands
    cli.close()
    return n_failed, "ok"


def telnet_session(target, host, cfg, p_typo, max_retries):
    """Minimal Telnet login against busybox telnetd (legacy IoT overlap).
    Uses raw sockets -- no telnetlib (removed in Py3.13). Best-effort; failures
    to log in still generate benign auth events on the target."""
    user = cfg.get("telnet_user", cfg.get("ssh_user", "pi"))
    good_pw = cfg.get("telnet_password", cfg.get("password", ""))
    port = int(cfg.get("telnet_port", 23))
    n_failed = 0

    def one_login(u, p):
        try:
            s = socket.create_connection((host, port), timeout=8)
            s.settimeout(6)
            time.sleep(0.5)
            try: s.recv(4096)
            except Exception: pass
            s.sendall((u + "\r\n").encode()); time.sleep(0.6)
            try: s.recv(4096)
            except Exception: pass
            s.sendall((p + "\r\n").encode()); time.sleep(0.8)
            try: banner = s.recv(4096).decode(errors="ignore")
            except Exception: banner = ""
            ok = "incorrect" not in banner.lower() and "login" not in banner.lower()
            if ok:
                for cmd in random.sample(["uptime", "df", "ps", "cat /proc/loadavg"], k=2):
                    s.sendall((cmd + "\r\n").encode()); time.sleep(random.uniform(0.6, 2.5))
                    try: s.recv(4096)
                    except Exception: pass
                s.sendall(b"exit\r\n")
            s.close()
            return ok
        except Exception:
            return False

    if good_pw and random.random() < p_typo:
        for _ in range(random.randint(1, max_retries - 1)):
            if not one_login(user, mistype(good_pw)):
                n_failed += 1
            time.sleep(random.uniform(1.5, 4.0))
    ok = one_login(user, good_pw)
    return n_failed, ("ok" if ok else "login_failed")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", required=True, help="comma-sep device_ids (keys in creds.yaml)")
    ap.add_argument("--proto", choices=["ssh", "telnet"], default="ssh")
    ap.add_argument("--creds", default=os.path.join(HERE, "creds.yaml"),
                    help="YAML: device_id -> {host, ssh_user, password, key_path, port,...}")
    ap.add_argument("--p-typo", type=float, default=0.18, help="prob. of a fat-finger burst")
    ap.add_argument("--max-retries", type=int, default=3, help="max failed tries before success")
    ap.add_argument("--annot", default="/var/log/testbed/benign/benign_activity.csv")
    ap.add_argument("--seed", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    if a.seed is not None:
        random.seed(a.seed)

    creds = load_yaml(a.creds)
    origin = socket.gethostname()
    target = random.choice([t.strip() for t in a.targets.split(",") if t.strip()])
    cfg = creds.get(target, {})
    host = cfg.get("host", target)             # fall back to hostname/IP == device_id

    sid = uuid.uuid4().hex[:12]
    s_iso, s_mono = now()
    if a.dry_run:
        print(f"    [dry-run] {origin} -> {target} {a.proto} (p_typo={a.p_typo})")
        n_failed, outcome = 0, "dry_run"
    elif a.proto == "ssh":
        n_failed, outcome = ssh_session(target, host, cfg, a.p_typo, a.max_retries)
    else:
        n_failed, outcome = telnet_session(target, host, cfg, a.p_typo, a.max_retries)
    e_iso, e_mono = now()

    annotate(a.annot, {
        "origin": origin, "target": target, "proto": a.proto, "session_id": sid,
        "n_failed_auth": n_failed, "outcome": outcome,
        "start_iso": s_iso, "end_iso": e_iso,
        "start_mono": f"{s_mono:.3f}", "end_mono": f"{e_mono:.3f}", "seed": a.seed or "",
    })
    print(f"[admin_session] {origin}->{target} {a.proto} failed={n_failed} outcome={outcome}")


if __name__ == "__main__":
    main()
