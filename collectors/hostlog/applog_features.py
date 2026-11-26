#!/usr/bin/env python3
"""
applog_features.py -- TACTIC-IoT v2.1 APPLICATION-LOG feature source.

Parses the broker (mosquitto) and SNMP trap-sink (snmptrapd) / agent (snmpd) lines
that the v2.1 logging config emits into the system journal, and turns them into
BEHAVIOURAL per-event counters for the IoT application-protocol attack classes.
These are the "fourth source" (application logs) that the OS-level host silo does not
carry, and they are the honest fix for the MQTT/SNMP brute-force host-blindness.

LEAKAGE DISCIPLINE (do not break):
  * We featurize the DAEMON's reaction to real attacker traffic (a connection churn,
    a bad-community trap), never the orchestrator `tactic-*` breadcrumb markers, and
    never a raw attacker-controlled string as a feature value.
  * Emitted features are counts / behavioural tallies a real detector could compute
    from the daemon's own log. Distinct-username is a tally, not the username text.

The emitted schema mirrors read_journald() in align_windows.py: one record per matched
journal line, {device_id, ts_ns, <counter>=1.0, ...}; align_windows bins these into the
same one-second windows as every other source. Integration = add this parse to
read_journald (or call this and left-join on (device_id, window)).

PROVISIONAL REGEXES: the mosquitto 2.x / net-snmp line formats below are the documented
defaults, but exact wording varies by version. RUN --selftest ON THE SMOKE-TEST journald
FIRST and adjust any pattern that does not fire before the full re-collection.

Usage:
  python applog_features.py --selftest path/to/journald.json      # validate regexes
  python applog_features.py --in journald.json --out applog_events.csv
"""
import argparse, json, re, sys

# ---- PROVISIONAL patterns (validate with --selftest) -----------------------
# mosquitto (SYSLOG_IDENTIFIER == "mosquitto"), log_type all + connection_messages:
RE_MQTT_CONN    = re.compile(r"New (connection|client connected) from")
RE_MQTT_DISCONN = re.compile(r"(disconnect|closed its connection|Socket error on client)", re.I)
RE_MQTT_NOAUTH  = re.compile(r"not authori[sz]ed", re.I)
RE_MQTT_USER    = re.compile(r"u'([^']*)'")           # attempted username (-> distinct tally only)

# snmptrapd local sink (our format1/2 tag) carrying an authenticationFailure trap,
# and/or snmpd's own direct syslog line at raised verbosity:
RE_SNMP_TRAP    = re.compile(r"TACTIC-TRAP")
RE_SNMP_AUTHFAIL = re.compile(r"(authenticationFailure|Authentication failure \(incorrect community)", re.I)


def classify(ident, msg):
    """Return a dict of applog counters for one journal line, or None if not app-log."""
    if ident == "mosquitto":
        rec = {}
        if RE_MQTT_CONN.search(msg):
            rec["applog_mqtt_conn"] = 1.0
            mu = RE_MQTT_USER.search(msg)
            if mu:
                rec["applog_mqtt_cred"] = 1.0            # a CONNECT that carried a username
                rec["_mqtt_user"] = mu.group(1)          # side field: distinct tally only
        if RE_MQTT_DISCONN.search(msg):
            rec["applog_mqtt_disconn"] = 1.0
        if RE_MQTT_NOAUTH.search(msg):
            rec["applog_mqtt_denied"] = 1.0
        return rec or None
    if ident in ("snmptrapd", "snmpd"):
        if RE_SNMP_AUTHFAIL.search(msg) or (ident == "snmptrapd" and RE_SNMP_TRAP.search(msg)):
            return {"applog_snmp_authfail": 1.0}
        return None
    return None


def iter_events(path):
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            rt = j.get("__REALTIME_TIMESTAMP")
            if rt is None:
                continue
            ident = str(j.get("SYSLOG_IDENTIFIER", ""))
            rec = classify(ident, str(j.get("MESSAGE", "")))
            if rec is None:
                continue
            rec["device_id"] = j.get("_HOSTNAME", "unknown")
            rec["ts_ns"] = int(rt) * 1000
            yield rec


def selftest(path):
    tally, samples = {}, {}
    n = 0
    for rec in iter_events(path):
        n += 1
        for k, v in rec.items():
            if k in ("device_id", "ts_ns", "_mqtt_user"):
                continue
            tally[k] = tally.get(k, 0) + 1
    print(f"[selftest] {path}")
    print(f"[selftest] matched application-log events: {n}")
    if not tally:
        print("[selftest] NO app-log events matched -- check that logging is enabled and")
        print("           adjust the PROVISIONAL regexes to the real line wording.")
        return 1
    for k in sorted(tally):
        print(f"[selftest]   {k:24} {tally[k]}")
    # show a few raw matched messages per identifier for eyeballing the format
    shown = 0
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                j = json.loads(line)
            except Exception:
                continue
            ident = str(j.get("SYSLOG_IDENTIFIER", ""))
            if ident in ("mosquitto", "snmptrapd", "snmpd") and classify(ident, str(j.get("MESSAGE", ""))):
                print(f"[sample] {ident}: {str(j.get('MESSAGE',''))[:120]}")
                shown += 1
                if shown >= 8:
                    break
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--selftest")
    ap.add_argument("--in", dest="inp")
    ap.add_argument("--out")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(selftest(a.selftest))
    if not a.inp or not a.out:
        ap.error("need --in and --out (or --selftest)")
    import csv
    cols = ["device_id", "ts_ns", "applog_mqtt_conn", "applog_mqtt_disconn",
            "applog_mqtt_cred", "applog_mqtt_denied", "applog_snmp_authfail"]
    with open(a.out, "w", newline="") as fo:
        w = csv.DictWriter(fo, fieldnames=cols, extrasaction="ignore")
        w.writeheader()
        for rec in iter_events(a.inp):
            w.writerow(rec)
    print(f"-> {a.out}")


if __name__ == "__main__":
    main()
