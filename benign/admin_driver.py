#!/usr/bin/env python3
"""
admin_driver.py -- Poisson scheduler for benign ADMIN sessions.

Runs the `runner: admin_session` workloads from workloads.yaml on a schedule,
invoking admin_session.py once per fired session. Intended to run on the WINDOWS
CONTROL MACHINE (the operator's normal vantage point; paramiko is cross-platform)
and, optionally, on one board as a SECOND origin so benign auth is not tied to a
single source. Attack timing stays with the separate orchestrator; this only
produces legitimate logins (with the occasional fat-finger failure).

Usage (control machine):
  python admin_driver.py --workloads workloads.yaml --creds creds.yaml
  # optional single-shot for testing:
  python admin_driver.py --once admin_ssh_ops
"""
import argparse, os, random, subprocess, sys, time
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable or "python3"


def load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML required: pip install pyyaml")
    with open(path) as f:
        return yaml.safe_load(f)


def fire(wl, creds, annot, dry, seed=None):
    # append per-invocation flags to the workload's base cmd
    cmd = f'{PY} {os.path.join(HERE, "admin_session.py")} ' + wl["cmd"].split("admin_session.py", 1)[-1].strip()
    cmd += f' --creds "{creds}" --annot "{annot}"'
    if seed is not None:
        cmd += f" --seed {seed}"
    if dry:
        cmd += " --dry-run"
    ts = datetime.now(timezone.utc).isoformat()
    print(f"[admin_driver] {ts} fire {wl['id']}: {cmd}")
    try:
        subprocess.call(cmd, shell=True)
    except Exception as e:
        print(f"[admin_driver] {wl['id']} error: {e}", file=sys.stderr)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--workloads", default=os.path.join(HERE, "workloads.yaml"))
    ap.add_argument("--creds", default=os.path.join(HERE, "creds.yaml"))
    ap.add_argument("--annot", default="/var/log/testbed/benign/benign_activity.csv")
    ap.add_argument("--once", help="fire one workload id and exit (testing)")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    man = load_yaml(a.workloads)
    defaults = man.get("defaults", {})
    jitter = float(defaults.get("jitter", 0.35))
    seed = defaults.get("campaign_seed")
    wls = man.get("workloads", man if isinstance(man, list) else [])
    admin = [w for w in wls if w.get("runner") == "admin_session"]

    if a.once:
        wl = next((w for w in admin if w["id"] == a.once), None)
        if not wl:
            sys.exit(f"no admin workload '{a.once}'")
        fire(wl, a.creds, a.annot, a.dry_run, seed)
        return

    if seed is not None:
        random.seed(seed)

    if a.dry_run:
        # fire each admin workload once immediately (no Poisson wait) and exit
        for wl in admin:
            fire(wl, a.creds, a.annot, True, seed)
        print("[admin_driver] dry-run complete")
        return

    # independent Poisson stream per admin workload
    next_at = {}
    now = time.monotonic
    for wl in admin:
        rate = float(wl.get("rate_s", 600)) or 600.0
        next_at[wl["id"]] = now() + random.expovariate(1.0 / rate) * random.uniform(1 - jitter, 1 + jitter)
    print(f"[admin_driver] scheduling {len(admin)} admin workloads; dry={a.dry_run}")

    while True:
        t = now()
        for wl in admin:
            if t >= next_at[wl["id"]]:
                fire(wl, a.creds, a.annot, False, seed)
                rate = float(wl.get("rate_s", 600)) or 600.0
                next_at[wl["id"]] = t + random.expovariate(1.0 / rate) * random.uniform(1 - jitter, 1 + jitter)
        time.sleep(2.0)


if __name__ == "__main__":
    main()
