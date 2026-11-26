#!/usr/bin/env python3
"""
backup_xfer.py -- legitimate backup / file-transfer workload (benign).

Provides the large-transfer traffic that malware delivery (download of a stage-2
binary) and exfiltration (upload of stolen data) must be distinguished from.
Without benign bulk transfers, "any long/large flow == malicious" separates the
delivery/exfil scenarios on a single network feature. With them, benign backups,
log shipping and update fetches share the long-flow / byte-volume / up-down-ratio
space, so those flows are ambiguous in the network modality alone.

Modes:
  rsync   rsync -az over SSH of --src to <dst>:/backups/<dev>/   (compressed)
  scp     scp -C -r of --src to <dst>:/backups/<dev>/logs/       (compressed)
  tar     tar czf a local archive of --src then scp it           (disk + net)
  fetch   wget/curl a file from the AIR-GAPPED local mirror       (delivery-shaped)

Compression is varied (some runs -z, some plain) so telemetry (CPU/disk) is not
a constant tell. All destinations are lab-internal (the hub); no internet egress.
Requires key-based SSH already configured (the orchestrator sets this up).

Usage:
  python3 backup_xfer.py --mode rsync --dst 10.0.0.1 --src /var/lib/testbed/data
  python3 backup_xfer.py --mode scp   --dst 10.0.0.1 --src /var/log/testbed
  python3 backup_xfer.py --mode fetch --url http://10.0.0.1/mirror/pkgs/sample.deb
"""
import argparse, os, random, socket, subprocess, sys, tempfile, time

DEV = socket.gethostname()
SSH_USER = os.environ.get("TESTBED_SSH_USER", "pi")


def sh(cmd, timeout=600):
    try:
        return subprocess.call(cmd, stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL, timeout=timeout)
    except Exception as e:
        print(f"[xfer] {' '.join(cmd)} -> {e}", file=sys.stderr)
        return -1


def run_rsync(dst, src, user):
    z = ["-z"] if random.random() < 0.5 else []
    dest = f"{user}@{dst}:/backups/{DEV}/"
    cmd = ["rsync", "-a"] + z + ["--partial", "-e",
           "ssh -o BatchMode=yes -o StrictHostKeyChecking=accept-new", src + "/", dest]
    print(f"[xfer] rsync {'(-z)' if z else ''} {src} -> {dest}")
    return sh(cmd)


def run_scp(dst, src, user):
    c = ["-C"] if random.random() < 0.5 else []
    dest = f"{user}@{dst}:/backups/{DEV}/logs/"
    cmd = ["scp", "-r", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new"] + c + [src, dest]
    print(f"[xfer] scp {src} -> {dest}")
    return sh(cmd)


def run_tar(dst, src, user):
    with tempfile.NamedTemporaryFile(suffix=".tgz", delete=False) as tf:
        arc = tf.name
    sh(["tar", "czf", arc, "-C", os.path.dirname(src) or "/", os.path.basename(src)])
    rc = run_scp_file(dst, arc, user)
    try: os.unlink(arc)
    except OSError: pass
    return rc


def run_scp_file(dst, path, user):
    dest = f"{user}@{dst}:/backups/{DEV}/archives/"
    return sh(["scp", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new", path, dest])


def run_fetch(url):
    """Fetch from the LOCAL air-gapped mirror -- shaped like a benign delivery."""
    out = os.path.join(tempfile.gettempdir(), f"benign_dl_{random.randint(0, 10**6)}")
    tool = "wget" if subprocess.call(["bash", "-lc", "command -v wget >/dev/null 2>&1"]) == 0 else "curl"
    if tool == "wget":
        rc = sh(["wget", "-q", "-O", out, url])
    else:
        rc = sh(["curl", "-fsS", "-o", out, url])
    try: os.unlink(out)
    except OSError: pass
    print(f"[xfer] fetch {url} via {tool} rc={rc}")
    return rc


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", required=True, choices=["rsync", "scp", "tar", "fetch"])
    ap.add_argument("--dst"); ap.add_argument("--src"); ap.add_argument("--url")
    ap.add_argument("--user", default=SSH_USER)
    a = ap.parse_args()
    t0 = time.monotonic()
    if a.mode == "rsync":
        rc = run_rsync(a.dst, a.src, a.user)
    elif a.mode == "scp":
        rc = run_scp(a.dst, a.src, a.user)
    elif a.mode == "tar":
        rc = run_tar(a.dst, a.src, a.user)
    else:
        rc = run_fetch(a.url)
    print(f"[xfer] mode={a.mode} rc={rc} dur={time.monotonic()-t0:.1f}s")
    sys.exit(0 if rc == 0 else 0)              # never fail the campaign on a transfer hiccup


if __name__ == "__main__":
    main()
