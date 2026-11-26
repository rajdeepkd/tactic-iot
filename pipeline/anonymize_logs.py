#!/usr/bin/env python3
"""
anonymize_logs.py -- identity pseudonymization layer for the host/system logs.

Motivation: models (especially FL / SplitFL / the BAN study) must not overfit to the
*attacker's identity* -- its hostname, process ids, usernames, IP/MAC addresses -- so
that detection reflects BEHAVIOUR, not "who". The fused feature dataset is already
identity-free (features are behavioural counters), but any pipeline that consumes the
RAW auditd/journald logs, or that extracts richer per-event features, must pass the
logs through this layer first.

Approach: consistent, salted, non-reversible pseudonyms. Each identity token is
replaced by a stable tag derived from HMAC-SHA256(salt, token) -- the same token always
maps to the same pseudonym (so behavioural structure/co-occurrence is preserved) but the
real value cannot be recovered without the salt, and the salt is generated fresh and NOT
stored with the data. Field-typed prefixes keep pseudonyms interpretable (USER_3f9a, …).

Scrubbed fields (auditd + journald/syslog):
  - usernames / accounts : acct=, AUID/UID/EUID names, "user <x>", "Invalid user <x>",
                           "for <x> from", sudo USER=/USER by
  - process ids          : pid=, ppid=, tid=, session=, "[1234]" syslog brackets
  - hostnames            : node=, kernel hostname token after the syslog timestamp
  - network identifiers  : IPv4, IPv6, MAC, "from <ip> port <n>", saddr= hex (zeroed)
  - paths that embed users: /home/<user>/..., /Users/<user>/...

Usage:
  python anonymize_logs.py --in <raw_log_or_dir> --out <dir> [--salt-file salt.bin]
  (directory mode walks *audit*.log* and *journal*.json / journald_*.json)
"""
import argparse, os, re, glob, hmac, hashlib, secrets, sys

def make_salt(path=None):
    if path and os.path.exists(path):
        return open(path, "rb").read()
    s = secrets.token_bytes(32)
    if path:
        open(path, "wb").write(s)
    return s

def tag(salt, kind, value):
    if value is None or value == "":
        return value
    h = hmac.new(salt, (kind + ":" + str(value)).encode("utf-8", "replace"), hashlib.sha256).hexdigest()[:8]
    return f"{kind}_{h}"

# ---- regex patterns (compiled once) ----
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
IPV6 = re.compile(r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b")
HOMEPATH = re.compile(r"(/(?:home|Users)/)([^/\s\"']+)")
# key=value identity fields in auditd
KV = re.compile(r"\b(acct|auid|uid|euid|suid|fsuid|gid|egid|pid|ppid|tid|ses|session|node|hostname|addr|saddr|exe|comm|key)=(\"[^\"]*\"|[^\s]+)")
# journald/syslog text patterns
INVUSER = re.compile(r"(Invalid user |invalid user |user |User |for |USER=|logname=|acct=)([A-Za-z0-9._\-]+)")
PIDBRACKET = re.compile(r"\[(\d{1,7})\]")
PORT = re.compile(r"\bport (\d{1,5})\b")

# fields whose *value* is an identity to pseudonymize (auditd key=value)
ID_KEYS = {"acct": "USER", "auid": "UID", "uid": "UID", "euid": "UID", "suid": "UID",
           "fsuid": "UID", "ses": "SES", "session": "SES", "pid": "PID", "ppid": "PID",
           "tid": "PID", "node": "HOST", "hostname": "HOST", "addr": "ADDR",
           "exe": "EXE", "comm": "COMM"}
# behavioural key=value we KEEP as-is (they carry the attack signal, not identity)
KEEP_KEYS = {"type", "syscall", "success", "res", "a0", "a1", "a2", "a3", "items",
             "arch", "key"}  # key= is often a rule tag (e.g. 'exec'); keep it

def anon_auditd_line(salt, line):
    def repl(m):
        k, v = m.group(1), m.group(2)
        if k in ID_KEYS:
            vq = v.strip('"')
            if k == "saddr":                     # hex sockaddr -> zeroed
                return f'{k}=ANON'
            return f'{k}={tag(salt, ID_KEYS[k], vq)}'
        return m.group(0)
    line = KV.sub(repl, line)
    line = MAC.sub(lambda m: tag(salt, "MAC", m.group(0)), line)
    line = IPV4.sub(lambda m: tag(salt, "IP", m.group(0)), line)
    line = HOMEPATH.sub(lambda m: m.group(1) + tag(salt, "USER", m.group(2)), line)
    return line

def anon_text(salt, s):
    """journald message / syslog free text."""
    s = MAC.sub(lambda m: tag(salt, "MAC", m.group(0)), s)
    s = IPV6.sub(lambda m: tag(salt, "IP6", m.group(0)), s)
    s = IPV4.sub(lambda m: tag(salt, "IP", m.group(0)), s)
    s = HOMEPATH.sub(lambda m: m.group(1) + tag(salt, "USER", m.group(2)), s)
    s = PIDBRACKET.sub(lambda m: "[" + tag(salt, "PID", m.group(1)) + "]", s)
    s = INVUSER.sub(lambda m: m.group(1) + tag(salt, "USER", m.group(2)), s)
    s = PORT.sub(lambda m: "port " + tag(salt, "PORT", m.group(1)), s)
    return s

def anon_journald_json(salt, line):
    """journalctl -o json JSONL: pseudonymize identity fields, keep behaviour."""
    import json
    try:
        o = json.loads(line)
    except Exception:
        return line
    for f in ("_HOSTNAME", "_MACHINE_ID", "_BOOT_ID"):
        if f in o:
            o[f] = tag(salt, "HOST", o[f])
    for f in ("_PID", "_PPID", "_UID", "_GID", "_AUDIT_SESSION", "SYSLOG_PID"):
        if f in o:
            o[f] = tag(salt, "PID" if "PID" in f else ("UID" if "UID" in f or "GID" in f else "SES"), o[f])
    for f in ("MESSAGE", "SYSLOG_IDENTIFIER", "_COMM", "_EXE", "_CMDLINE"):
        if f in o and isinstance(o[f], str):
            o[f] = anon_text(salt, o[f])
    return json.dumps(o)

def process_file(salt, src, dst):
    base = os.path.basename(src)
    is_json = base.endswith(".json") or "journal" in base
    n = 0
    # read fully first so in-place (src==dst) overwrite cannot truncate the source
    with open(src, "r", encoding="utf-8", errors="replace") as fi:
        lines = fi.read().splitlines()
    with open(dst, "w", encoding="utf-8", newline="\n") as fo:
        for line in lines:
            out = anon_journald_json(salt, line) if is_json else anon_auditd_line(salt, line)
            fo.write(out + "\n"); n += 1
    return n

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--in", dest="inp", required=True, help="raw log file or directory")
    ap.add_argument("--out", required=True, help="output directory")
    ap.add_argument("--salt-file", default=None, help="reuse/persist salt (default: ephemeral, discarded)")
    a = ap.parse_args()
    os.makedirs(a.out, exist_ok=True)
    salt = make_salt(a.salt_file)
    if os.path.isdir(a.inp):
        files = sorted(glob.glob(os.path.join(a.inp, "**", "*audit*.log*"), recursive=True) +
                       glob.glob(os.path.join(a.inp, "**", "*journal*.json"), recursive=True))
    else:
        files = [a.inp]
    tot = 0
    for src in files:
        dst = os.path.join(a.out, os.path.basename(src))
        k = process_file(salt, src, dst); tot += k
        print(f"  {os.path.basename(src):40} {k:>8} lines -> {dst}")
    print(f"anonymized {len(files)} file(s), {tot} lines. salt {'persisted to '+a.salt_file if a.salt_file else 'was ephemeral (discarded; non-reversible)'}.")

if __name__ == "__main__":
    main()
