#!/usr/bin/env python3
"""
auditlog_parser.py -- turn auditd's /var/log/audit/audit.log into structured
NDJSON events for the pipeline, using `ausearch -i` so record grouping,
number->name and uid->name translation are done by the audit tooling (correct
per-ABI, so it also handles the aarch32 RPi 3B+ vs aarch64 boards for free).

It emits the HOST-DOMINANT stage evidence the charter needs:
  * proc_exec   : execve/execveat   (delivery + execution stage)
  * priv_change : setuid/setgid/... (privilege-escalation stage)
  * priv_cap    : capset            (capability grant)
  * suid_bit    : chmod +s          (persistence via SUID dropper)
  * user_auth / user_login / cred_acq : PAM authentication (from -k or type)

Runs incrementally: a checkpoint file stores the last processed event time so a
periodic run (or the systemd timer) ships only new events. Each record:
  {device_id, ts_iso, ts_mono, type, key, syscall, exe, comm, argv, ppid, pid,
   auid, uid, euid, success, res, addr, terminal, raw_serial}

Usage (one-shot, ship since checkpoint):
  python3 auditlog_parser.py --out /var/log/testbed/hostlog \
      --checkpoint /var/log/testbed/hostlog/.auditckpt
"""
import argparse, json, os, socket, subprocess, time
from datetime import datetime, timezone

DEVICE_ID = socket.gethostname()

# audit key -> our event type (keys come from testbed.rules)
KEY_TYPE = {
    "proc_exec": "proc_exec", "priv_change": "priv_change",
    "priv_cap": "priv_cap", "suid_bit": "suid_bit",
    "identity": "identity_write", "persistence": "persistence_write",
    "persistence_home": "persistence_write", "sshd_conf": "sshd_conf_write",
    "pam_conf": "pam_conf_write", "authlog_tamper": "authlog_tamper",
    "logins": "login_record",
}

FIELDS = ("type", "syscall", "exe", "comm", "key", "ppid", "pid", "auid",
          "uid", "euid", "suid", "fsuid", "success", "res", "addr",
          "terminal", "acct", "hostname")


def parse_block(block, real0, mono0):
    """One ausearch -i event block (lines of key=val) -> our record dict."""
    rec = {"device_id": DEVICE_ID}
    argv = []
    ev_epoch = None
    for line in block.splitlines():
        # ausearch -i prints 'time->...' header lines; skip, we take epoch from
        # msg=audit(EPOCH:serial) which -i keeps as node/msg fields sometimes.
        for tok in line.split():
            if "=" not in tok:
                continue
            k, v = tok.split("=", 1)
            v = v.strip('"')
            if k in FIELDS:
                rec[k] = v
            elif k in ("a0", "a1", "a2", "a3") or (k.startswith("a") and k[1:].isdigit()):
                argv.append(v)
            elif k == "msg" and v.startswith("audit("):
                try:
                    ev_epoch = float(v[len("audit("):].split(":")[0])
                except Exception:
                    pass
    if argv:
        rec["argv"] = argv
    rec["type_raw"] = rec.get("type", "")
    rec["event"] = KEY_TYPE.get(rec.get("key", ""), None) or _type_event(rec.get("type", ""))
    if ev_epoch:
        rec["ts_iso"] = datetime.fromtimestamp(ev_epoch, timezone.utc).isoformat()
        rec["ts_mono"] = round(mono0 + (ev_epoch - real0), 6)
    else:
        rec["ts_iso"] = datetime.now(timezone.utc).isoformat()
        rec["ts_mono"] = None
    return rec


def _type_event(t):
    return {"USER_AUTH": "user_auth", "USER_LOGIN": "user_login",
            "USER_ACCT": "user_acct", "CRED_ACQ": "cred_acq",
            "USER_START": "session_start", "USER_END": "session_end",
            "ADD_USER": "add_user", "USER_CHAUTHTOK": "passwd_change",
            }.get(t, t.lower() if t else "other")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/log/testbed/hostlog")
    ap.add_argument("--checkpoint", default="/var/log/testbed/hostlog/.auditckpt")
    ap.add_argument("--audit-log", default="/var/log/audit/audit.log")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    real0, mono0 = time.time(), time.monotonic()

    start = None
    if os.path.exists(a.checkpoint):
        start = open(a.checkpoint).read().strip() or None
    # ausearch time formats: "MM/DD/YYYY HH:MM:SS" or keywords recent/today/boot
    cmd = ["ausearch", "-i", "--input", a.audit_log]
    if start:
        cmd += ["-ts", start]
    else:
        cmd += ["-ts", "boot"]
    try:
        raw = subprocess.check_output(cmd, text=True, stderr=subprocess.DEVNULL)
    except subprocess.CalledProcessError:
        print("[audit] ausearch found no new events", flush=True)
        return

    day = datetime.now(timezone.utc).strftime("%Y%m%d")
    path = os.path.join(a.out, f"audit_{DEVICE_ID}_{day}.ndjson")
    n = 0
    with open(path, "a", buffering=1) as fh:
        for block in raw.split("----"):
            block = block.strip()
            if not block:
                continue
            rec = parse_block(block, real0, mono0)
            fh.write(json.dumps(rec, separators=(",", ":")) + "\n")
            n += 1
    # advance checkpoint to now (ausearch -ts is inclusive; small overlap is
    # deduped downstream by (ts, raw_serial))
    open(a.checkpoint, "w").write(datetime.now().strftime("%m/%d/%Y %H:%M:%S"))
    print(f"[audit] wrote {n} events -> {path}", flush=True)


if __name__ == "__main__":
    main()
