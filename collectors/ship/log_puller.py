#!/usr/bin/env python3
"""
log_puller.py -- PRIMARY shipping (pull model), runs on the WINDOWS CONTROL
machine (the orchestrator box). The charter states the control machine already
holds key-based SSH to every board, so PULLING is the natural direction: no
sshd/rsyncd on Windows, no reverse keys on the boards.

Each board is the durable buffer -- collectors write append-only NDJSON/CSV
under /var/log/testbed and rotate; this puller mirrors that tree into
captures/<device_id>/ on a timer. Shipping cadence is INDEPENDENT of attack
windows (Phase-0 principle #1): a lag never loses data, and a final reconciling
pull runs at end of campaign.

Uses rsync-over-ssh when rsync is available (WSL / Git-Bash / cwrsync on
Windows -- incremental, resumable, --append-verify), else falls back to
`scp -r` (whole-tree copy, still correct, just less efficient).

Usage (loop every 5 min, reading the same nodes.yaml the orchestrator uses):
  python log_puller.py --nodes ../nodes.yaml --out ./captures --interval 300
  python log_puller.py --nodes ../nodes.yaml --out ./captures --once   # final pull
"""
import argparse, os, shutil, subprocess, sys, time


def load_nodes(path):
    import yaml
    with open(path) as f:
        return yaml.safe_load(f)


def have(cmd):
    return shutil.which(cmd) is not None


def pull_one(device_id, node, out_root, remote_dir, key):
    ip, user = node["ip"], node["ssh_user"]
    dest = os.path.join(out_root, device_id)
    os.makedirs(dest, exist_ok=True)
    ssh_opts = "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new"
    if key:
        ssh_opts += f" -i {key}"
    if have("rsync"):
        cmd = ["rsync", "-az", "--append-verify", "--partial",
               "-e", ssh_opts,
               f"{user}@{ip}:{remote_dir}/", dest + "/"]
    else:
        # scp fallback (Windows OpenSSH ships scp); recursive whole-tree copy
        key_arg = ["-i", key] if key else []
        cmd = ["scp", "-r", "-o", "BatchMode=yes",
               "-o", "StrictHostKeyChecking=accept-new", *key_arg,
               f"{user}@{ip}:{remote_dir}/.", dest]
    print(f"[pull] {device_id} <- {user}@{ip}:{remote_dir}", flush=True)
    r = subprocess.run(cmd)
    if r.returncode != 0:
        print(f"[pull] WARN {device_id} exit {r.returncode}", flush=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--nodes", required=True)
    ap.add_argument("--out", default="./captures")
    ap.add_argument("--remote-dir", default="/var/log/testbed")
    ap.add_argument("--key", default="", help="SSH private key path")
    ap.add_argument("--interval", type=int, default=300)
    ap.add_argument("--once", action="store_true")
    ap.add_argument("--skip-roles", nargs="*", default=["attacker"],
                    help="node roles NOT to pull from")
    a = ap.parse_args()
    nodes = load_nodes(a.nodes)
    roles = nodes.get("roles", {})
    skip_ids = {roles.get(r) for r in a.skip_roles if roles.get(r)}
    os.makedirs(a.out, exist_ok=True)
    while True:
        for dev, node in nodes["nodes"].items():
            if dev in skip_ids:
                continue
            try:
                pull_one(dev, node, a.out, a.remote_dir, a.key)
            except Exception as e:
                print(f"[pull] ERROR {dev}: {e}", flush=True)
        if a.once:
            break
        time.sleep(a.interval)


if __name__ == "__main__":
    main()
