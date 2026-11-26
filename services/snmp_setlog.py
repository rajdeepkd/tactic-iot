#!/usr/bin/env python3
"""
snmp_setlog.py -- net-snmp `pass` handler for ONE writable string scalar, giving
control_snmp_set a reliable HOST-silo footprint.

WHY: an SNMP SET of a built-in scalar (sysLocation.0) is persisted by net-snmp via
an atomic temp+rename, which an auditd path/dir watch does not reliably catch, so
the unauthorized SET left no dependable host trace. A `pass` subtree instead makes
snmpd EXEC this script on every request: a SET exec is an execve (caught by the
auditd tb_exec rule) and this script also emits a journald line via `logger`. Benign
monitoring and the attack both go through here, so host-presence alone does not
separate them -- rate / co-occurring stage activity / the ground-truth label do.
That asymmetry is the unauthorized_control multimodal-necessity evidence, identical
in spirit to tactic-cmd-handler (MQTT) and modbus_server LoggingBlock (Modbus).

snmpd.conf:  pass .1.3.6.1.4.1.8072.9999.1 /opt/testbed/services/snmp_setlog.py
The writable scalar is .1.3.6.1.4.1.8072.9999.1.0 (STRING). Value persists in
/run (reset on reboot -> scratch, reversible). No attacker-controlled text is ever
executed; only a fixed `logger` line runs. The written value is NOT logged
(anti-identity P7).
"""
import os
import subprocess
import sys

BASE = ".1.3.6.1.4.1.8072.9999.1"
SCALAR = BASE + ".0"
STATE = "/var/lib/snmp/tactic_snmp_cfg"   # Debian-snmp-writable (snmpd's own dir)
DEFAULT = "tactic-lab rack"


def load():
    try:
        with open(STATE) as f:
            return f.read().strip() or DEFAULT
    except Exception:
        return DEFAULT


def store(v):
    try:
        with open(STATE, "w") as f:
            f.write(v)
    except Exception:
        pass


def emit(oid, typ, val):
    sys.stdout.write(f"{oid}\n{typ}\n{val}\n")
    sys.stdout.flush()


def main():
    a = sys.argv[1:]
    if not a:
        return
    op = a[0]
    if op == "-g":                      # GET
        if len(a) > 1 and a[1] == SCALAR:
            emit(SCALAR, "string", load())
    elif op == "-n":                    # GETNEXT (walk)
        if len(a) > 1 and a[1] == BASE:
            emit(SCALAR, "string", load())
        # at or past the scalar -> end of subtree: print nothing
    elif op == "-s":                    # SET  (a = -s OID TYPE VALUE)
        if len(a) > 1 and a[1] == SCALAR:
            store(a[3] if len(a) > 3 else "")
            try:
                subprocess.run(["logger", "-t", "tactic-snmp",
                                f"snmp set on {os.uname().nodename}"],
                               timeout=5, check=False)
            except Exception:
                pass
            # success == no output. (A non-empty line here would be an error.)


if __name__ == "__main__":
    main()
