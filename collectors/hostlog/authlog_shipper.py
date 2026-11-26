#!/usr/bin/env python3
"""
authlog_shipper.py -- structured capture of the AUTHENTICATION-CONTEXT stream:
sshd / sudo / su / systemd-logind events. This is the flagship host signal for
scenario 1 (slow SSH brute force interleaved with genuine, occasionally typo'd
logins) -- the case the charter says the network modality cannot resolve because
SSH auth payloads are encrypted, but auth.log/journald see every outcome.

PRIMARY SOURCE: journald via `journalctl -o json` (UTC __REALTIME_TIMESTAMP,
chrony-synced, structured, survives reboots when Storage=persistent). We follow
with a persisted cursor so a restart never loses or double-ships events.
FALLBACK: tail /var/log/auth.log (traditional rsyslog file present on Raspberry
Pi OS and the Jetson's Ubuntu base) when journald is unavailable.

We EMIT structured NDJSON and compute NO features here (the pipeline owns
windowing/features -- charter principle: collectors stay dumb). Each record:
  {device_id, ts_iso, ts_mono, source, unit, event, user, invalid_user,
   rhost, rport, method, tty, pid, raw}

`event` is one of: auth_fail, auth_accept, invalid_user, disconnect_preauth,
sudo_fail, sudo_ok, su_fail, su_ok, session_open, session_close, other.
Downstream, the "brute vs typo" figure uses inter-failure cadence, per-rhost
failure counts and attempted-username entropy -- all derivable from these fields.

Usage:
  python3 authlog_shipper.py --out /var/log/testbed/hostlog \
      --cursor /var/log/testbed/hostlog/.authcursor --source journald
"""
import argparse, json, os, re, socket, subprocess, time
from datetime import datetime, timezone

DEVICE_ID = socket.gethostname()

# sshd / sudo / su / PAM message patterns
PATTERNS = [
    ("auth_accept",       re.compile(r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<rhost>\S+) port (?P<rport>\d+)")),
    ("invalid_user",      re.compile(r"Invalid user (?P<user>\S+) from (?P<rhost>\S+)(?: port (?P<rport>\d+))?")),
    ("auth_fail",         re.compile(r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<rhost>\S+) port (?P<rport>\d+)")),
    ("auth_fail",         re.compile(r"pam_unix\(sshd:auth\): authentication failure;.*?(?:ruser=\S*\s*)?rhost=(?P<rhost>\S+)(?:\s+user=(?P<user>\S+))?")),
    ("disconnect_preauth",re.compile(r"Connection (?:closed|reset) by (?:authenticating|invalid) user (?P<user>\S+) (?P<rhost>\S+) port (?P<rport>\d+) \[preauth\]")),
    ("disconnect_preauth",re.compile(r"Disconnected from authenticating user (?P<user>\S+) (?P<rhost>\S+) port (?P<rport>\d+) \[preauth\]")),
    ("sudo_fail",         re.compile(r"pam_unix\(sudo:auth\): authentication failure;.*?user=(?P<user>\S+)")),
    ("sudo_ok",           re.compile(r"sudo:\s+(?P<user>\S+) : TTY=(?P<tty>\S+) ;")),
    ("su_fail",           re.compile(r"pam_unix\(su(?:-l)?:auth\): authentication failure;.*?user=(?P<user>\S+)")),
    ("session_open",      re.compile(r"pam_unix\(\S+:session\): session opened for user (?P<user>\S+)")),
    ("session_close",     re.compile(r"pam_unix\(\S+:session\): session closed for user (?P<user>\S+)")),
]


def classify(msg):
    for event, rx in PATTERNS:
        m = rx.search(msg)
        if m:
            d = m.groupdict()
            d = {k: v for k, v in d.items() if v is not None}
            d["event"] = event
            d["invalid_user"] = ("invalid user" in msg) or (event == "invalid_user")
            return d
    return {"event": "other"}


def mono_offset():
    return time.time(), time.monotonic()


def emit(fh, rec):
    fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
    fh.flush()


def run_journald(out_fh, cursor_path):
    real0, mono0 = mono_offset()
    cmd = ["journalctl", "-f", "-o", "json", "-n", "0",
           "--output-fields=MESSAGE,SYSLOG_IDENTIFIER,_SYSTEMD_UNIT,_PID,__REALTIME_TIMESTAMP",
           "SYSLOG_IDENTIFIER=sshd", "SYSLOG_IDENTIFIER=sudo",
           "SYSLOG_IDENTIFIER=su", "SYSLOG_IDENTIFIER=systemd-logind"]
    if os.path.exists(cursor_path):
        cur = open(cursor_path).read().strip()
        if cur:
            cmd = cmd[:1] + ["--after-cursor", cur] + cmd[1:]
    print(f"[authlog] following journald: {' '.join(cmd)}", flush=True)
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except Exception:
            continue
        msg = j.get("MESSAGE", "")
        usec = int(j.get("__REALTIME_TIMESTAMP", "0"))
        ts_iso = (datetime.fromtimestamp(usec / 1e6, timezone.utc).isoformat()
                  if usec else datetime.now(timezone.utc).isoformat())
        parsed = classify(msg)
        rec = {"device_id": DEVICE_ID, "ts_iso": ts_iso,
               "ts_mono": round(mono0 + (usec / 1e6 - real0), 6) if usec else None,
               "source": "journald",
               "unit": j.get("_SYSTEMD_UNIT", j.get("SYSLOG_IDENTIFIER", "")),
               "pid": j.get("_PID"), "raw": msg, **parsed}
        emit(out_fh, rec)
        if "__CURSOR" in j:
            open(cursor_path, "w").write(j["__CURSOR"])


def run_authlog(out_fh, path="/var/log/auth.log"):
    real0, mono0 = mono_offset()
    print(f"[authlog] tailing {path}", flush=True)
    with open(path) as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            parsed = classify(line)
            rec = {"device_id": DEVICE_ID,
                   "ts_iso": datetime.now(timezone.utc).isoformat(),
                   "ts_mono": round(time.monotonic(), 6),
                   "source": "auth.log", "unit": "", "raw": line.rstrip(),
                   **parsed}
            emit(out_fh, rec)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/log/testbed/hostlog")
    ap.add_argument("--cursor", default="/var/log/testbed/hostlog/.authcursor")
    ap.add_argument("--source", choices=["journald", "authlog"], default="journald")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    path = os.path.join(a.out, f"auth_{DEVICE_ID}_{day}.ndjson")
    fh = open(path, "a", buffering=1)
    print(f"[authlog] device={DEVICE_ID} -> {path}", flush=True)
    while True:
        try:
            if a.source == "journald":
                run_journald(fh, a.cursor)
            else:
                run_authlog(fh)
        except FileNotFoundError as e:
            print(f"[authlog] {e}; retry in 5s", flush=True)
            time.sleep(5)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
