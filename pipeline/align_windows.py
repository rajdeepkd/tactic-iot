#!/usr/bin/env python3
r"""
align_windows.py -- cross-source event/window alignment + stage labelling for
the Objective-3 physical testbed.

Turns raw per-device collector output (Zeek network, journald/auditd host logs,
telemetry_reader telemetry) into fused, stage-labelled multimodal windows:

    [ device_id | window_idx | window_start_iso | group_id
      | net__* ... | host__* ... | tel__* ...
      | modality_mask | attack_type | stage | label_overlap ]

Design (see Objective3_Phase1_Testbed_Charter.md s3/s6/s7 and pipeline notes):

  * COMMON AXIS = synced CLOCK_REALTIME. chrony holds inter-board skew < 1 ms
    (measured by validate_alignment.py); the binding constraint on telemetry is
    the sample period, not skew -- so prefer W >= a few telemetry sample periods.
  * GLOBAL-EPOCH ANCHOR. window_idx = floor(ts_realtime_ns / W_ns). Because all
    devices bin on the SAME synced axis against the SAME anchor, windows with
    equal idx are the SAME wall-clock interval on every device -> alignment is
    an index equality, not a fuzzy join. Two captures share the grid -> directly
    comparable (and comparable to the CIC-YNU per-execution baseline once pooled
    by group_id; see --pooled).
  * EVENT-LEVEL GROUND TRUTH by interval-join against labels.csv (written by the
    orchestrator, which owns the clock). No post-hoc hand annotation.
  * ANTI-LEAKAGE (pilot P7c): every window carries group_id (execution/session).
    Downstream MUST split by group_id and temporally, never window-level random
    (window-level split cost up to 0.35 macro-F1 in P7). This script only emits
    the key; it never itself splits.
  * modality_mask marks genuinely-absent modalities (camera has no auth.log) so
    E4' missing-modality is meaningful.

Feature layout matches results/E2b (net__*/host__*/tel__* + __cnt) so E1'/E2'/E4'
repoint with minimal change.

Usage:
  python3 align_windows.py --captures ./captures/run_2026-09-27 \
      --labels ./captures/run_2026-09-27/labels.csv \
      --out ./captures/run_2026-09-27/aligned --window-s 1,5 --pooled

Inputs looked for under --captures (any subset; missing modality is masked):
  telemetry : telemetry_*.csv                  (from telemetry_reader.py)
  network   : *conn.log *ssh.log *dns.log *http.log *weird.log (+ .gz)  (Zeek TSV;
              on-hub Zeek or the interim pcap_to_connlog.py conn.log stand-in)
  host      : *.journal.json / journald_*.json (journalctl -o json, JSONL)
              audit_*.log / audit.log          (raw auditd)
Dependencies: pandas, numpy, pyyaml (stdlib for the rest).
"""
import argparse, glob, gzip, io, json, os, sys
from datetime import datetime, timezone
import numpy as np
import pandas as pd

NS = 1_000_000_000
SRC_PREFIX = {"net": "net__", "host": "host__", "tel": "tel__", "applog": "applog__"}


# --------------------------------------------------------------------------- #
# timestamp helpers
# --------------------------------------------------------------------------- #
def iso_to_ns(s):
    """ISO-8601 (with or without tz) -> realtime ns UTC. NaT-safe."""
    dt = pd.to_datetime(s, utc=True, errors="coerce")
    return dt.astype("int64")  # ns since epoch; NaT -> min int, filtered by ts_ns>0


def num(series):
    return pd.to_numeric(series, errors="coerce")


# --------------------------------------------------------------------------- #
# per-modality readers -> canonical frame [device_id, ts_ns, <numeric feats>]
# --------------------------------------------------------------------------- #
def read_telemetry(paths):
    """telemetry_reader.py CSVs. Prefers ts_realtime_ns; falls back to ts_iso."""
    frames = []
    tel_feats = ["cpu_pct", "mem_pct", "mem_used_mb", "load1", "load5", "load15",
                 "temp_c", "nprocs", "net_tx_bps", "net_rx_bps",
                 "disk_r_bps", "disk_w_bps", "bus_v", "current_ma", "power_mw",
                 # C3: collector-apparatus load (mean-aggregated gauge) -> recorded
                 # nuisance, so pcap/auditd/journald self-load can be controlled for.
                 "col_cpu_pct", "col_cap_cpu_pct", "col_rss_mb", "col_n"]
    for p in paths:
        try:
            # index_col=False: the telemetry reader appends one trailing column the
            # header does not name (33 header fields, 34 data fields). Without this,
            # pandas infers the first column as the index and shifts every named column
            # by one, so ts_realtime_ns reads ts_mono_ns (~9e14, not ns-scale) and all
            # feature values misalign -> telemetry silently drops out of the fusion.
            df = pd.read_csv(p, low_memory=False, index_col=False)
        except Exception as e:
            print(f"  [tel] skip {os.path.basename(p)}: {e}", file=sys.stderr)
            continue
        # robust ts: a header/data column MISMATCH (older reader appended to a file
        # with a stale header) shifts ts_realtime_ns to a non-ns value -> sanity-check
        # it is ns-scale (since ~2001), else fall back to ts_iso, else skip the file.
        ts_ns = None
        if "ts_realtime_ns" in df.columns:
            tv = num(df["ts_realtime_ns"])
            if tv.notna().any() and float(tv.median()) > 1e15:
                ts_ns = tv.round().astype("Int64")
        if ts_ns is None and "ts_iso" in df.columns:
            ts_ns = pd.Series(iso_to_ns(df["ts_iso"]))
        if ts_ns is None:
            print(f"  [tel] skip {os.path.basename(p)}: no usable ns timestamp "
                  f"(header/data column mismatch?)", file=sys.stderr)
            continue
        out = pd.DataFrame({"device_id": df.get("device_id", "unknown"),
                            "ts_ns": ts_ns})
        for c in tel_feats:
            if c in df.columns:
                out["tel_" + c] = num(df[c])
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def _open_maybe_gz(p):
    if p.endswith(".gz"):
        return io.TextIOWrapper(gzip.open(p, "rb"), encoding="utf-8", errors="replace")
    return open(p, "r", encoding="utf-8", errors="replace")


# Zeek conn_state values that mark scan/half-open/rejected flows (the recon tell)
ZEEK_SCAN_STATES = {"S0", "REJ", "RSTOS0", "SH", "SHR", "RSTRH"}
# net_* COUNT columns (0/1 or counts) -> summed per window; absent log -> 0.
# Kept apart from the mean-aggregated flow gauges so per-window means average
# only real flows, not zero-filled non-conn rows.
#  * net_s0 / net_rej split the scan tell so SYN-scan (S0) vs connect-scan (REJ)
#    separate (net_scan_s0 kept as the union for continuity).
#  * net_arp_* come from the pcap ARP layer (Zeek IP flows are blind to ARP) so
#    MITM/ARP-spoof is detectable (poisoning = a burst of ARP replies).
NET_COUNT_COLS = ["net_conns", "net_scan_s0", "net_s0", "net_rej",
                  "net_ssh_sess", "net_ssh_auth_ok", "net_ssh_auth_fail",
                  "net_dns_q", "net_dns_nx", "net_http_req", "net_http_4xx",
                  "net_http_5xx", "net_weird",
                  "net_arp_total", "net_arp_reply", "net_arp_request",
                  # v2 IoT application protocols (behavioural counters only).
                  "net_mqtt_connect", "net_mqtt_connack_fail", "net_mqtt_pub",
                  "net_mqtt_sub", "net_modbus_req", "net_modbus_write",
                  "net_modbus_exc", "net_snmp_get", "net_snmp_bulk",
                  "net_snmp_set", "net_coap_msg", "net_coap_con", "net_coap_get",
                  # C1 fix: per-window packet + byte counts from the wire (pkts.csv),
                  # so a long single-connection transfer is visible in EVERY second
                  # it spans, not only the second Zeek stamps its one conn record.
                  "net_pkts", "net_bytes"]

# Modbus function names (Zeek maps codes -> names) that denote a WRITE: these are
# the control_modbus_write tell. A write is valid Modbus and looks benign in flow
# features, so this counter is the network view of the unauthorized-control class.
MODBUS_WRITE_FUNCS = ("WRITE_SINGLE_COIL", "WRITE_SINGLE_REGISTER",
                      "WRITE_MULTIPLE_COILS", "WRITE_MULTIPLE_REGISTERS",
                      "MASK_WRITE_REGISTER", "READ_WRITE_MULTIPLE_REGISTERS")


def _zeek_frame(path):
    """Parse a Zeek TSV log by its #fields header -> DataFrame (str cells,
    '-'/'(empty)' -> NaN). Skips all # meta lines. Also parses the interim
    pcap_to_connlog.py output (a conn.log column subset)."""
    cols, rows = None, []
    with _open_maybe_gz(path) as fh:
        for line in fh:
            if line.startswith("#fields"):
                cols = line.rstrip("\n").split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if cols is None:
                continue
            rows.append(line.rstrip("\n").split("\t"))
    if cols is None or not rows:
        return None
    width = len(cols)
    rows = [r[:width] + [np.nan] * (width - len(r)) if len(r) != width else r for r in rows]
    return pd.DataFrame(rows, columns=cols).replace({"-": np.nan, "(empty)": np.nan})


def _zeek_logs(captures, name):
    return sorted(glob.glob(os.path.join(captures, "**", f"*{name}.log*"), recursive=True))


def _zeek_base(path, device_from_path):
    """(df, out) with device_id + ts_ns prefilled, or (None, None) if unusable.
    'ts' = libpcap capture time = the capturing board's synced CLOCK_REALTIME."""
    df = _zeek_frame(path)
    if df is None or "ts" not in df.columns:
        return None, None
    dev = device_from_path(path) if device_from_path else "unknown"
    out = pd.DataFrame({"device_id": dev,
                        "ts_ns": (num(df["ts"]) * NS).round().astype("Int64")},
                       index=df.index)
    return df, out


def read_zeek_conn(paths, device_from_path=None):
    """conn.log -> per-flow numeric gauges + flow/scan counters. id.* IPs are
    identity -> deliberately dropped (anti-leakage, P7)."""
    keep = ["duration", "orig_bytes", "resp_bytes", "missed_bytes",
            "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]
    frames = []
    for p in paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        for c in keep:
            if c in df.columns:
                out["net_" + c] = num(df[c])
        out["net_conns"] = 1.0
        if "conn_state" in df.columns:
            cs = df["conn_state"]
            out["net_scan_s0"] = cs.isin(ZEEK_SCAN_STATES).astype(float)
            out["net_s0"] = (cs == "S0").astype(float)     # SYN sent, no reply (SYN scan)
            out["net_rej"] = (cs == "REJ").astype(float)    # rejected (connect scan to closed port)
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_arp(paths, device_from_path=None):
    """ARP-layer counters from arp.<device>.csv (ts,arp_total,arp_reply,arp_request,
    extracted by harvest.sh via tcpdump). Zeek's IP-flow logs are blind to ARP, so
    this is the ONLY view of MITM/ARP-spoof (poisoning = a burst of ARP replies)."""
    frames = []
    for p in paths:
        try:
            df = pd.read_csv(p)
        except Exception:
            continue
        if df.empty or "ts" not in df.columns:
            continue
        dev = device_from_path(p) if device_from_path else "unknown"
        out = pd.DataFrame({"device_id": dev,
                            "ts_ns": (num(df["ts"]) * NS).round().astype("Int64")})
        for c in ("arp_total", "arp_reply", "arp_request"):
            if c in df.columns:
                out["net_" + c] = num(df[c])
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_zeek_ssh(paths, device_from_path=None):
    """ssh.log -> session + auth counters (brute-force tell). Drops version/
    client/server/key-fingerprint strings (identity)."""
    frames = []
    for p in paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        succ = df["auth_success"] if "auth_success" in df.columns else pd.Series(np.nan, index=df.index)
        out["net_ssh_sess"] = 1.0
        out["net_ssh_auth_ok"] = (succ == "T").astype(float)
        out["net_ssh_auth_fail"] = (succ == "F").astype(float)
        if "auth_attempts" in df.columns:
            out["net_ssh_attempts"] = num(df["auth_attempts"])  # gauge (mean)
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_zeek_dns(paths, device_from_path=None):
    """dns.log -> query + NXDOMAIN counters. Drops qname/answer strings."""
    frames = []
    for p in paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        rc = df["rcode_name"] if "rcode_name" in df.columns else pd.Series(np.nan, index=df.index)
        out["net_dns_q"] = 1.0
        out["net_dns_nx"] = (rc == "NXDOMAIN").astype(float)
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_zeek_http(paths, device_from_path=None):
    """http.log -> request + 4xx/5xx counters. Drops URI/host/user-agent strings."""
    frames = []
    for p in paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        sc = num(df["status_code"]) if "status_code" in df.columns else pd.Series(np.nan, index=df.index)
        out["net_http_req"] = 1.0
        out["net_http_4xx"] = ((sc >= 400) & (sc < 500)).astype(float)
        out["net_http_5xx"] = (sc >= 500).astype(float)
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_zeek_weird(paths, device_from_path=None):
    """weird.log -> anomaly-event counter (MITM/ARP/proto-violation tell)."""
    frames = []
    for p in paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        out["net_weird"] = 1.0
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_zeek_mqtt(conn_paths, pub_paths, sub_paths, device_from_path=None):
    """MQTT message-level counters from Zeek's mqtt_connect / mqtt_publish /
    mqtt_subscribe logs (@load policy/protocols/mqtt). Drops client_id / topic /
    payload (identity). net_mqtt_connack_fail = refused CONNECT (the bruteforce /
    connflood tell)."""
    frames = []
    for p in conn_paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        out["net_mqtt_connect"] = 1.0
        if "connect_status" in df.columns:
            cs = df["connect_status"].astype(str)
            out["net_mqtt_connack_fail"] = (~cs.str.contains("Accept", case=False, na=False)).astype(float)
        frames.append(out)
    for p in pub_paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        out["net_mqtt_pub"] = 1.0
        frames.append(out)
    for p in sub_paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        out["net_mqtt_sub"] = 1.0
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_zeek_modbus(paths, device_from_path=None):
    """modbus.log -> request / write / exception counters. Register values and
    addresses are identity-ish and dropped; only the behaviour is kept. The write
    counter is the network view of control_modbus_write (valid-looking on the wire)."""
    frames = []
    for p in paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        out["net_modbus_req"] = 1.0
        if "func" in df.columns:
            fn = df["func"].astype(str).str.upper()
            out["net_modbus_write"] = fn.isin(MODBUS_WRITE_FUNCS).astype(float)
        if "exception" in df.columns:
            out["net_modbus_exc"] = df["exception"].notna().astype(float)
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_zeek_snmp(paths, device_from_path=None):
    """snmp.log -> per-session get / getbulk / set COUNTS (the fields are already
    counts, summed per window). community string is identity -> dropped. The set
    counter is the network view of control_snmp_set."""
    frames = []
    for p in paths:
        df, out = _zeek_base(p, device_from_path)
        if df is None:
            continue
        get = num(df["get_requests"]) if "get_requests" in df.columns else 0.0
        resp = num(df["get_responses"]) if "get_responses" in df.columns else 0.0
        out["net_snmp_get"] = get
        out["net_snmp_bulk"] = num(df["get_bulk_requests"]) if "get_bulk_requests" in df.columns else 0.0
        out["net_snmp_set"] = num(df["set_requests"]) if "set_requests" in df.columns else 0.0
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_coap(paths, device_from_path=None):
    """CoAP counters from coap.<device>.csv (ts,coap_msg,coap_con,coap_get,
    extracted by harvest.sh via tshark). Zeek has no CoAP analyzer, so this csv is
    the only CoAP view (parallels read_arp for the ARP layer)."""
    frames = []
    for p in paths:
        try:
            df = pd.read_csv(p)
        except Exception:
            continue
        if df.empty or "ts" not in df.columns:
            continue
        dev = device_from_path(p) if device_from_path else "unknown"
        out = pd.DataFrame({"device_id": dev,
                            "ts_ns": (num(df["ts"]) * NS).round().astype("Int64")})
        for c in ("coap_msg", "coap_con", "coap_get"):
            if c in df.columns:
                out["net_" + c] = num(df[c])
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_pkts(paths, device_from_path=None):
    """Per-window packet + byte counts from pkts.<device>.csv (ts,pkts,bytes,
    extracted by harvest.sh per packet via tshark/tcpdump). This is the C1 answer:
    unlike Zeek's one-record-per-connection, every packet carries its own timestamp,
    so a long transfer or a flood populates net__pkts/net__bytes in each second it
    occupies. Returns None when the csv is absent (v1 captures stay unchanged)."""
    frames = []
    for p in paths:
        try:
            df = pd.read_csv(p)
        except Exception:
            continue
        if df.empty or "ts" not in df.columns:
            continue
        dev = device_from_path(p) if device_from_path else "unknown"
        out = pd.DataFrame({"device_id": dev,
                            "ts_ns": (num(df["ts"]) * NS).round().astype("Int64")})
        for c in ("pkts", "bytes"):
            if c in df.columns:
                out["net_" + c] = num(df[c])
        # Pre-aggregate to 1 s device buckets before the net frame is assembled.
        # A flood can push pkts.<dev>.csv past several million per-packet rows;
        # concatenating those raw inflates the net frame to tens of millions of rows
        # and OOMs windowize()'s copy. net_pkts/net_bytes are SUM features and the
        # window grid is integer-second and epoch-anchored (anchor_ns=0), so summing
        # per floored second HERE is identical to summing per window LATER -- the same
        # totals land in the same window_idx -- at ~1 row/second instead of 1/packet.
        # 1 s nests inside every window size used (W1/W5/W8/W10), so this is exact for
        # all of them. float64 is kept (net_bytes can exceed float32 integer precision).
        out = out.dropna(subset=["ts_ns"])
        if out.empty:
            continue
        SEC_NS = 1_000_000_000
        out["ts_ns"] = (out["ts_ns"].astype("int64") // SEC_NS) * SEC_NS
        val_cols = [c for c in out.columns if c.startswith("net_")]
        out = out.groupby(["device_id", "ts_ns"], as_index=False)[val_cols].sum()
        frames.append(out)
    return pd.concat(frames, ignore_index=True) if frames else None


def read_zeek_all(captures, device_from_path=None):
    """Union all Zeek network logs (conn+ssh+dns+http+weird) into one canonical
    net frame. COUNT columns fill to 0 where a log didn't contribute the row;
    flow gauges stay NaN so per-window means average only real flows. Backward-
    compatible: with only a conn.log present (incl. the interim converter) this
    reduces to the previously-validated behaviour plus net_scan_s0."""
    parts = [
        read_zeek_conn(_zeek_logs(captures, "conn"), device_from_path),
        read_zeek_ssh(_zeek_logs(captures, "ssh"), device_from_path),
        read_zeek_dns(_zeek_logs(captures, "dns"), device_from_path),
        read_zeek_http(_zeek_logs(captures, "http"), device_from_path),
        read_zeek_weird(_zeek_logs(captures, "weird"), device_from_path),
        read_arp(sorted(glob.glob(os.path.join(captures, "**", "arp.*.csv"), recursive=True)), device_from_path),
        # v2 IoT application protocols. Each returns None when its log is absent,
        # so v1 captures reduce to the previously-validated behaviour.
        read_zeek_mqtt(_zeek_logs(captures, "mqtt_connect"),
                       _zeek_logs(captures, "mqtt_publish"),
                       _zeek_logs(captures, "mqtt_subscribe"), device_from_path),
        read_zeek_modbus(_zeek_logs(captures, "modbus"), device_from_path),
        read_zeek_snmp(_zeek_logs(captures, "snmp"), device_from_path),
        read_coap(sorted(glob.glob(os.path.join(captures, "**", "coap.*.csv"), recursive=True)), device_from_path),
        read_pkts(sorted(glob.glob(os.path.join(captures, "**", "pkts.*.csv"), recursive=True)), device_from_path),
    ]
    parts = [p for p in parts if p is not None]
    if not parts:
        return None
    net = pd.concat(parts, ignore_index=True)
    for c in NET_COUNT_COLS:
        if c in net.columns:
            net[c] = net[c].fillna(0.0)
    return net


def read_journald(paths, device_from_path=None):
    """journald JSONL (journalctl -o json). Emits behavioural host counters --
    NOT raw text (anti-identity policy). __REALTIME_TIMESTAMP is us since epoch;
    __MONOTONIC_TIMESTAMP + _BOOT_ID give the dual clock for free."""
    frames = []
    for p in paths:
        recs = []
        dev = device_from_path(p) if device_from_path else None
        with _open_maybe_gz(p) as fh:
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
                msg = str(j.get("MESSAGE", ""))
                ident = str(j.get("SYSLOG_IDENTIFIER", ""))
                is_ssh = ident in ("sshd", "sshd-session")  # OpenSSH >=9.8 split sshd -> sshd-session
                recs.append({
                    "device_id": dev or j.get("_HOSTNAME", "unknown"),
                    "ts_ns": int(rt) * 1000,  # us -> ns
                    "host_log_lines": 1.0,
                    "host_auth_fail": 1.0 if (is_ssh and "Failed password" in msg) else 0.0,
                    "host_auth_ok":   1.0 if (is_ssh and "Accepted " in msg) else 0.0,
                    "host_invalid_user": 1.0 if "Invalid user" in msg else 0.0,
                    "host_new_session": 1.0 if ("session opened" in msg or ident == "systemd-logind") else 0.0,
                })
        if recs:
            frames.append(pd.DataFrame(recs))
    return pd.concat(frames, ignore_index=True) if frames else None


def read_auditd(paths, device_from_path=None):
    """Raw auditd log. 'msg=audit(EPOCH.mmm:serial)' -> realtime ns. Emits
    execve / syscall / connect counters (the execution-stage host signal)."""
    import re
    pat = re.compile(r"audit\((\d+\.\d+):\d+\)")
    frames = []
    for p in paths:
        recs = []
        dev = device_from_path(p) if device_from_path else "unknown"
        with _open_maybe_gz(p) as fh:
            for line in fh:
                m = pat.search(line)
                if not m:
                    continue
                ts_ns = int(round(float(m.group(1)) * NS))
                recs.append({
                    "device_id": dev, "ts_ns": ts_ns,
                    "host_audit_lines": 1.0,
                    "host_execve": 1.0 if "type=EXECVE" in line else 0.0,
                    "host_syscall": 1.0 if "type=SYSCALL" in line else 0.0,
                    "host_connect": 1.0 if "syscall=connect" in line or "SYSCALL=connect" in line else 0.0,
                })
        if recs:
            frames.append(pd.DataFrame(recs))
    return pd.concat(frames, ignore_index=True) if frames else None


# --------------------------------------------------------------------------- #
# APPLICATION-LOG modality (4th source): broker / CoAP / Modbus daemon logs,
# harvested as applog_<proto>_<dev>.log (each line 'epoch: message'). Behavioural
# counters only (connection/auth-fail/request/write rates) -- never raw payloads or
# the orchestrator tactic-* markers. Emits columns applog_* that windowize() renames
# to applog__* and sums per window.
# --------------------------------------------------------------------------- #
import re as _re
_APP_TS = _re.compile(r"^(\d+):\s*(.*)$")
def read_applog(paths, device_from_path=None):
    frames = []
    for p in paths:
        dev = device_from_path(p) if device_from_path else None
        recs = []
        proto = "mqtt" if "applog_mqtt" in p else "coap" if "applog_coap" in p else "modbus" if "applog_modbus" in p else "app"
        try:
            fh = open(p, encoding="utf-8", errors="replace")
        except OSError:
            continue
        with fh:
            for line in fh:
                m = _APP_TS.match(line)
                if not m:
                    continue
                ts_ns = int(m.group(1)) * 1_000_000_000
                msg = m.group(2); low = msg.lower()
                r = {"device_id": dev or "unknown", "ts_ns": ts_ns, "applog_lines": 1.0}
                if proto == "mqtt":
                    if "not authori" in low:
                        r["applog_mqtt_authfail"] = 1.0
                    if "new connection from" in low or "new client connected" in low:
                        r["applog_mqtt_conn"] = 1.0
                        if "new client connected" in low and "'" in msg.split(" as ", 1)[-1]:
                            r["applog_mqtt_cred"] = 1.0
                    elif "disconnect" in low or "closed its connection" in low or "socket error" in low:
                        r["applog_mqtt_disconn"] = 1.0
                elif proto == "coap":
                    if "discovery" in low:
                        r["applog_coap_discovery"] = 1.0
                    elif "put" in low:
                        r["applog_coap_put"] = 1.0
                    else:
                        r["applog_coap_get"] = 1.0
                elif proto == "modbus":
                    if "write" in low:
                        r["applog_modbus_write"] = 1.0
                recs.append(r)
        if recs:
            frames.append(pd.DataFrame(recs))
    return pd.concat(frames, ignore_index=True) if frames else None


# --------------------------------------------------------------------------- #
# windowing
# --------------------------------------------------------------------------- #
# features that are counts (summed per window); everything else is mean-aggregated
SUM_FEATS = {"net_conns", "net_scan_s0", "net_s0", "net_rej", "net_ssh_sess",
             "net_ssh_auth_ok", "net_ssh_auth_fail", "net_dns_q", "net_dns_nx",
             "net_http_req", "net_http_4xx", "net_http_5xx", "net_weird",
             "net_arp_total", "net_arp_reply", "net_arp_request",
             # v2 IoT application-protocol counters
             "net_mqtt_connect", "net_mqtt_connack_fail", "net_mqtt_pub",
             "net_mqtt_sub", "net_modbus_req", "net_modbus_write", "net_modbus_exc",
             "net_snmp_get", "net_snmp_bulk", "net_snmp_set",
             "net_coap_msg", "net_coap_con", "net_coap_get",
             "net_pkts", "net_bytes",
             "host_log_lines", "host_auth_fail", "host_auth_ok",
             "host_invalid_user", "host_new_session", "host_audit_lines",
             "host_execve", "host_syscall", "host_connect",
             # v3 application-log modality (all behavioural counters)
             "applog_lines", "applog_mqtt_conn", "applog_mqtt_cred",
             "applog_mqtt_disconn", "applog_mqtt_authfail",
             "applog_coap_get", "applog_coap_put", "applog_coap_discovery",
             "applog_modbus_write"}


def windowize(df, source, w_ns, anchor_ns=0):
    """Bin a canonical frame into W-windows; aggregate numeric feats per
    (device_id, window_idx). Sums for counters, means for gauges, plus a row
    count. Returns wide frame prefixed by the modality."""
    if df is None or df.empty:
        return None
    df = df.dropna(subset=["ts_ns"]).copy()
    df = df[df["ts_ns"] > 0]
    if df.empty:
        return None
    df["window_idx"] = ((df["ts_ns"].astype("int64") - anchor_ns) // w_ns).astype("int64")
    feat_cols = [c for c in df.columns if c not in ("device_id", "ts_ns", "window_idx")]
    g = df.groupby(["device_id", "window_idx"], sort=True)
    agg = {}
    for c in feat_cols:
        agg[c] = "sum" if c in SUM_FEATS else "mean"
    out = g.agg(agg)
    out[SRC_PREFIX[source] + "cnt"] = g.size()
    pref = SRC_PREFIX[source]
    out = out.rename(columns={c: pref + c.split("_", 1)[1] for c in feat_cols})
    return out.reset_index()


# --------------------------------------------------------------------------- #
# ground-truth labelling (interval-join against labels.csv)
# --------------------------------------------------------------------------- #
def load_labels(path):
    empty = pd.DataFrame(columns=["scenario_id", "run_idx", "attack_type",
                                  "target", "stage", "start_ns", "end_ns"])
    if not path or not os.path.exists(path) or os.path.getsize(path) == 0:
        print(f"  [labels] {path} missing/empty -> everything labelled 'normal'", file=sys.stderr)
        return empty
    try:
        lab = pd.read_csv(path)
    except pd.errors.EmptyDataError:
        print(f"  [labels] {path} has no columns -> everything labelled 'normal'", file=sys.stderr)
        return empty
    if lab.empty or "start_iso" not in lab.columns:
        return empty
    lab["start_ns"] = pd.Series(iso_to_ns(lab["start_iso"])).astype("int64")
    lab["end_ns"] = pd.Series(iso_to_ns(lab["end_iso"])).astype("int64")
    if "stage" not in lab.columns:
        # RECOMMENDED orchestrator extension (charter/kill-chain): a per-run
        # kill-chain stage {recon,bruteforce,delivery,execution,persistence,
        # privesc,c2,exfil,ddos}. Absent -> fall back to attack_type as stage.
        lab["stage"] = lab["attack_type"]
    if "run_idx" not in lab.columns:
        lab["run_idx"] = 0
    return lab[["scenario_id", "run_idx", "attack_type", "target", "stage",
                "start_ns", "end_ns"]]


def label_window(dev, w_start_ns, w_end_ns, lab):
    """Return (attack_type, stage, group_id, overlap_frac) for one window.
    On multiple overlaps keep the one with the greatest overlap."""
    if lab.empty:
        return "normal", "normal", None, 0.0
    cand = lab[(lab["target"] == dev) &
               (lab["start_ns"] < w_end_ns) & (lab["end_ns"] > w_start_ns)]
    if cand.empty:
        return "normal", "normal", None, 0.0
    ov = (np.minimum(cand["end_ns"], w_end_ns) -
          np.maximum(cand["start_ns"], w_start_ns)).clip(lower=0)
    i = ov.values.argmax()
    r = cand.iloc[i]
    frac = float(ov.values[i]) / float(w_end_ns - w_start_ns)
    gid = f"{r['scenario_id']}#{int(r['run_idx'])}"
    return r["attack_type"], r["stage"], gid, round(frac, 4)


# --------------------------------------------------------------------------- #
# driver
# --------------------------------------------------------------------------- #
def device_from_filename(p):
    """Infer device_id from the filename tokens (e.g. conn.log.rpi3b1); if none
    match, fall back to the PARENT DIRECTORY (e.g. captures/rpi3b1/conn.log) so a
    device-in-directory layout (log_puller mirror, plain Zeek 'conn.log' output)
    still attributes per-board instead of collapsing to one shared 'unknown' group
    whose counters would be cross-summed across boards."""
    base = os.path.basename(p)
    parent = os.path.basename(os.path.dirname(p))
    for src in (base, parent):
        for tok in src.replace(".", "_").split("_"):
            if tok.startswith(("rpi", "jetson", "ipcam", "coral", "attacker")):
                return tok
    if parent and parent.lower() not in ("captures", "testbed", "logs", "var", "tmp", ""):
        return parent          # parent dir names the device verbatim
    return "unknown"


def build(captures, labels_path, w_s, anchor_ns, benign_bucket_s):
    w_ns = int(round(w_s * NS))
    dff = device_from_filename
    tel = read_telemetry(sorted(glob.glob(os.path.join(captures, "**", "telemetry_*.csv"), recursive=True)))
    net = read_zeek_all(captures, dff)
    host_frames = [
        read_journald(sorted(glob.glob(os.path.join(captures, "**", "*journal*.json"), recursive=True)), dff),
        read_auditd(sorted(glob.glob(os.path.join(captures, "**", "*audit*.log*"), recursive=True)), dff),
    ]
    host_frames = [h for h in host_frames if h is not None]
    host = pd.concat(host_frames, ignore_index=True) if host_frames else None
    applog = read_applog(sorted(glob.glob(os.path.join(captures, "**", "applog_*.log"), recursive=True)), dff)

    parts = []
    for src, frame in (("net", net), ("host", host), ("tel", tel), ("applog", applog)):
        w = windowize(frame, src, w_ns, anchor_ns)
        if w is not None:
            parts.append(w)
    if not parts:
        raise SystemExit("no modality data found under " + captures)

    fused = parts[0]
    for p in parts[1:]:
        fused = fused.merge(p, on=["device_id", "window_idx"], how="outer")
    fused = fused.sort_values(["device_id", "window_idx"]).reset_index(drop=True)

    # modality mask from per-source counts (4 bits now: net host tel applog)
    for src in ("net", "host", "tel", "applog"):
        cnt = SRC_PREFIX[src] + "cnt"
        fused[cnt] = fused.get(cnt, np.nan)
    fused["modality_mask"] = (
        fused["net__cnt"].notna().astype(int).astype(str) +
        fused["host__cnt"].notna().astype(int).astype(str) +
        fused["tel__cnt"].notna().astype(int).astype(str) +
        fused["applog__cnt"].notna().astype(int).astype(str))  # e.g. "1111", "1011"

    # window wall-clock bounds
    fused["window_start_ns"] = fused["window_idx"] * w_ns + anchor_ns
    fused["window_start_iso"] = pd.to_datetime(fused["window_start_ns"], unit="ns", utc=True)\
        .dt.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # ground-truth labels
    lab = load_labels(labels_path)
    at, st, gid, ov = [], [], [], []
    bb_ns = int(benign_bucket_s * NS)
    for _, row in fused.iterrows():
        a, s, g, f = label_window(row["device_id"], int(row["window_start_ns"]),
                                  int(row["window_start_ns"]) + w_ns, lab)
        if g is None:  # benign windows still get a coarse session bucket for grouped splits
            g = f"benign#{row['device_id']}#{int(row['window_start_ns'] // bb_ns)}"
        at.append(a); st.append(s); gid.append(g); ov.append(f)
    fused["attack_type"] = at
    fused["stage"] = st
    fused["group_id"] = gid
    fused["label_overlap"] = ov

    # tidy column order
    lead = ["device_id", "window_idx", "window_start_iso", "group_id",
            "attack_type", "stage", "label_overlap", "modality_mask"]
    feats = [c for c in fused.columns if c not in lead + ["window_start_ns"]]
    fused = fused[lead + sorted(feats)]
    return fused


def pool_by_group(fused):
    """Collapse windows to one row per group_id (execution/session) -> the
    CIC-YNU per-execution view, for the execution-stage baseline comparison.
    Counts summed, gauges meaned."""
    feat = [c for c in fused.columns if c.startswith(("net__", "host__", "tel__"))]
    agg = {c: ("sum" if (c.endswith("cnt") or c.split("__", 1)[1] in
               {s.split("_", 1)[1] for s in SUM_FEATS}) else "mean") for c in feat}
    g = fused.groupby("group_id")
    out = g.agg(agg)
    out["n_windows"] = g.size()
    out["attack_type"] = g["attack_type"].agg(lambda s: s.value_counts().index[0])
    out["stage"] = g["stage"].agg(lambda s: s.value_counts().index[0])
    out["device_id"] = g["device_id"].first()
    return out.reset_index()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captures", required=True, help="dir with raw collector output")
    ap.add_argument("--labels", default=None, help="labels.csv (orchestrator ground truth)")
    ap.add_argument("--out", required=True, help="output dir")
    ap.add_argument("--window-s", default="1,5", help="comma list of window sizes (s), e.g. 1,5")
    ap.add_argument("--epoch-anchor-ns", type=int, default=0,
                    help="window grid anchor (0 = Unix epoch -> captures share a grid)")
    ap.add_argument("--benign-bucket-s", type=float, default=600.0,
                    help="benign group_id bucket size for grouped splits")
    ap.add_argument("--pooled", action="store_true", help="also emit per-group pooled view")
    a = ap.parse_args()

    os.makedirs(a.out, exist_ok=True)
    if a.labels is None:
        guess = os.path.join(a.captures, "labels.csv")
        a.labels = guess if os.path.exists(guess) else None

    for w_s in [float(x) for x in a.window_s.split(",") if x.strip()]:
        print(f"[align] window = {w_s}s")
        fused = build(a.captures, a.labels, w_s, a.epoch_anchor_ns, a.benign_bucket_s)
        tag = f"W{('%g' % w_s).replace('.', 'p')}"
        fp = os.path.join(a.out, f"fused_windows_{tag}.csv")
        fused.to_csv(fp, index=False)
        cov = fused["modality_mask"].value_counts().to_dict()
        cls = fused["attack_type"].value_counts().to_dict()
        stg = fused["stage"].value_counts().to_dict()
        manifest = {"window_s": w_s, "n_windows": int(len(fused)),
                    "n_devices": int(fused["device_id"].nunique()),
                    "n_groups": int(fused["group_id"].nunique()),
                    "modality_mask_counts": cov,
                    "attack_type_counts": cls, "stage_counts": stg,
                    "epoch_anchor_ns": a.epoch_anchor_ns,
                    "generated_utc": datetime.now(timezone.utc).isoformat()}
        json.dump(manifest, open(os.path.join(a.out, f"manifest_{tag}.json"), "w"), indent=2)
        print(f"   -> {fp}  ({len(fused)} windows; masks={cov}; classes={cls})")
        if a.pooled:
            pooled = pool_by_group(fused)
            pf = os.path.join(a.out, f"pooled_by_group_{tag}.csv")
            pooled.to_csv(pf, index=False)
            print(f"   -> {pf}  ({len(pooled)} groups) [CIC-YNU per-execution view]")
    print("[align] done.")


if __name__ == "__main__":
    main()
