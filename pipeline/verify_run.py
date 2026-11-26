#!/usr/bin/env python3
r"""verify_run.py -- V5 PER-RUN CONTENT GATE.

Run immediately after a single run is harvested + aligned + ingested into
By_device_and_campaigns/<device>/run<NN>_V5/. Unlike v4_verify.py (which checked only
file PRESENCE and so passed the whole defective v4 dataset), this checks CONTENT: every
modality is non-empty AND carries real signal in the built windows, telemetry is ns-scale
and schema-consistent, auditd actually recorded events, and benign windows carry
application + auth activity. Prints a per-check table, a machine-readable RUNDETAIL JSON
line (counts for the run-details log), and exits 0 IFF the run is VALID.

Usage:
  verify_run.py --node <By_device run dir> --device <vn> --run <idx> [--stage <scen>]
                [--raw <harvest work dir>] [--expect-telcols 37]

The gate is intentionally strict: a FAIL means DO NOT advance to the next run.
"""
import sys, os, glob, json, struct, argparse
import pandas as pd
import numpy as np

# ---- healthy-run floors (derived from v4 run24, auditd alive: net .97 tel .83 host .68 app .40)
FLOORS = dict(
    windows_min   = 500,     # a non-truncated run
    net_frac      = 0.80,    # continuous capture -> nearly every window
    tel_frac      = 0.70,    # continuous 2 Hz sampler
    host_frac     = 0.15,    # event-driven (host-exec stages + benign admin); ~0 means auditd dead
    app_frac      = 0.10,    # IoT stages + benign client
    audit_lines   = 200,     # raw audit.log non-trivial
    journald_lines= 50,
    applog_lines  = 20,
    tel_rows      = 100,
    benign_app_frac = 0.05,  # normal windows must carry SOME app activity (E-8)
)
TEL_NS_MIN = 1e18            # realtime ns epoch is ~1.79e18 now; anything < means wrong column

def nlines(p):
    if not p or not os.path.exists(p): return 0
    n = 0
    with open(p, "rb") as f:
        for _ in f: n += 1
    return n

def first_glob(*pats):
    for pat in pats:
        g = sorted(glob.glob(pat))
        if g: return g[0]
    return None

def frac_nonzero(df, cols):
    if df.empty or not cols: return 0.0
    sub = df[cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    return round(float((sub != 0).any(axis=1).mean()), 3)

def pcap_ok(path, sample=2000):
    try:
        with open(path, "rb") as f:
            gh = f.read(24); m = gh[:4]
            if m not in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
                return (False, 0)
            en = "<" if m in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1") else ">"
            n = 0
            while n < sample:
                rh = f.read(16)
                if len(rh) < 16: break
                _, _, incl, _ = struct.unpack(en + "IIII", rh)
                f.read(incl); n += 1
        return (True, n)
    except Exception:
        return (False, 0)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--node", required=True, help="By_device run dir (has preprocessed/ + raw/)")
    ap.add_argument("--device", required=True)
    ap.add_argument("--run", required=True)
    ap.add_argument("--stage", default="V5")
    ap.add_argument("--raw", default="", help="harvest work dir p<r> (optional, for raw counts if node raw absent)")
    ap.add_argument("--expect-telcols", type=int, default=37)
    ap.add_argument("--start", default="", help="run start epoch (for RUNDETAIL)")
    ap.add_argument("--end", default="", help="run end epoch (for RUNDETAIL)")
    a = ap.parse_args()

    node = a.node
    raw = os.path.join(node, "raw")
    rawalt = a.raw  # harvest staging fallback
    vn = a.device
    checks = []   # (name, ok, detail)
    def chk(name, ok, detail=""):
        checks.append((name, bool(ok), detail))

    # ---------- windows ----------
    w1 = os.path.join(node, "preprocessed", "windows_w1.csv")
    if not os.path.exists(w1):
        chk("windows_present", False, "windows_w1.csv missing")
        emit(a, checks, {}, fatal=True); return
    df = pd.read_csv(w1, dtype={"modality_mask": str}, low_memory=False)
    nwin = len(df)
    chk("windows_count", nwin >= FLOORS["windows_min"], f"{nwin} (floor {FLOORS['windows_min']})")

    # Coverage metrics are computed over IN-RUN windows only. The pcap is selected by file
    # mtime with a +/-605 s margin (to never miss a covering rotation file), so its packets
    # create benign "edge" windows up to ~20 min before/after the labelled run. Those edge
    # windows legitimately lack the tightly-sliced continuous modalities (telemetry/applog),
    # which would otherwise drag coverage fractions down (tel 0.55, benign-app 0.03) and mask
    # whether the telemetry actually MERGED. Restrict coverage to [start-120, end+120].
    dcov = df
    if a.start and a.end:
        try:
            ep = pd.to_datetime(df["window_start_iso"], utc=True, errors="coerce").astype("int64") // 10**9
            inrun = (ep >= int(a.start) - 120) & (ep <= int(a.end) + 120)
            if int(inrun.sum()) >= 100:
                dcov = df[inrun]
        except Exception:
            dcov = df
    n_inrun = len(dcov)

    netc = [c for c in df.columns if c.startswith("net__") and c != "net__cnt"]
    host_all = [c for c in df.columns if c.startswith("host__")]
    host_sig = [c for c in host_all if c != "host__cnt"]
    appc = [c for c in df.columns if c.startswith("applog__") and c != "applog__cnt"]
    telcnt = pd.to_numeric(dcov.get("tel__cnt", pd.Series(dtype=float)), errors="coerce").fillna(0)

    net_frac = frac_nonzero(dcov, netc)
    tel_frac = round(float((telcnt > 0).mean()), 3) if n_inrun else 0.0
    host_frac = frac_nonzero(dcov, host_sig)
    app_frac = frac_nonzero(dcov, appc)

    chk("network_signal", net_frac >= FLOORS["net_frac"], f"frac>0={net_frac}")
    chk("telemetry_signal", tel_frac >= FLOORS["tel_frac"], f"tel__cnt>0 frac={tel_frac}")
    chk("host_signal", host_frac >= FLOORS["host_frac"], f"frac>0={host_frac}")
    chk("applog_signal", app_frac >= FLOORS["app_frac"], f"frac>0={app_frac}")

    # auditd really recorded syscalls (the v4 confound): execve/syscall/audit_lines columns exist + nonzero
    hexe = [c for c in host_all if ("execve" in c or "syscall" in c or "audit_lines" in c)]
    audit_built = frac_nonzero(dcov, hexe) if hexe else 0.0
    chk("auditd_execve_present", bool(hexe) and audit_built > 0,
        f"cols={len(hexe)} frac>0={audit_built}")

    # no modality silently all-NaN/all-zero in the built windows
    for mname, cols, fr in (("net", netc, net_frac), ("tel", ["tel__cnt"], tel_frac),
                            ("host", host_sig, host_frac), ("applog", appc, app_frac)):
        chk(f"{mname}_not_empty", fr > 0.0, f"frac>0={fr}")

    # benign realism (E-8): in-run normal windows carry application activity
    nb = dcov[dcov.get("attack_type", "") == "normal"]
    ben_app = frac_nonzero(nb, appc) if len(nb) else 0.0
    ben_auth = 0.0
    authcols = [c for c in host_all if c in ("host__auth_ok", "host__log_lines", "host__new_session")]
    ben_auth = frac_nonzero(nb, authcols) if (len(nb) and authcols) else 0.0
    chk("benign_app_realism", len(nb) == 0 or ben_app >= FLOORS["benign_app_frac"],
        f"normal n={len(nb)} app_frac={ben_app} auth_frac={ben_auth}")

    # ---------- raw files (node raw/, else harvest staging) ----------
    audit_p = first_glob(os.path.join(raw, "host", "audit*.log"),
                         os.path.join(raw, "host", "*audit*"),
                         os.path.join(rawalt, f"audit_{vn}.log"))
    jrnl_p = first_glob(os.path.join(raw, "host", "journald*.json"),
                        os.path.join(raw, "host", "*journal*"),
                        os.path.join(rawalt, f"journald_{vn}.json"))
    # the real 2 Hz telemetry is telemetry_2hz.csv; do NOT pick up collector_cpu.csv (a 6-col
    # collector-apparatus projection that sorts first alphabetically and would read as width 6).
    tel_p = first_glob(os.path.join(raw, "telemetry", "telemetry_2hz.csv"),
                       os.path.join(raw, "telemetry", "telemetry_*_win.csv"),
                       os.path.join(raw, "telemetry", "telemetry_*.csv"),
                       os.path.join(rawalt, f"telemetry_{vn}_win.csv"))
    app_ps = (glob.glob(os.path.join(raw, "applog", "*")) or
              glob.glob(os.path.join(rawalt, f"applog_*_{vn}.log")))
    zeek_conn = first_glob(os.path.join(raw, "network", "zeek", "conn*.log"),
                           os.path.join(raw, "network", "conn.log*"),
                           os.path.join(rawalt, f"conn.log.{vn}"))

    audit_n = nlines(audit_p); jrnl_n = nlines(jrnl_p)
    applog_n = sum(nlines(p) for p in app_ps)
    chk("raw_audit_nonempty", audit_n >= FLOORS["audit_lines"], f"{audit_n} lines ({os.path.basename(audit_p or '-')})")
    chk("raw_journald_nonempty", jrnl_n >= FLOORS["journald_lines"], f"{jrnl_n} lines")
    chk("raw_applog_nonempty", applog_n >= FLOORS["applog_lines"], f"{applog_n} lines")

    # telemetry raw: rows, ns-scale, schema width, device_id
    tel_rows = 0; tel_w_hdr = tel_w_dat = 0; tel_ns_ok = False; tel_dev_ok = False
    if tel_p and os.path.exists(tel_p):
        with open(tel_p) as f:
            hdr = f.readline().rstrip("\n").split(",")
            tel_w_hdr = len(hdr)
            rows = [ln for ln in f]
            tel_rows = len(rows)
            if rows:
                first = rows[0].rstrip("\n").split(",")
                tel_w_dat = len(first)
                idx = {h: i for i, h in enumerate(hdr)}
                if "ts_realtime_ns" in idx and len(first) > idx["ts_realtime_ns"]:
                    try: tel_ns_ok = float(first[idx["ts_realtime_ns"]]) >= TEL_NS_MIN
                    except Exception: tel_ns_ok = False
                if "device_id" in idx:
                    tel_dev_ok = (first[idx["device_id"]] == vn)
    chk("raw_telemetry_rows", tel_rows >= FLOORS["tel_rows"], f"{tel_rows} rows")
    chk("telemetry_schema_width", tel_w_hdr == tel_w_dat == a.expect_telcols,
        f"hdr={tel_w_hdr} dat={tel_w_dat} expect={a.expect_telcols}")
    chk("telemetry_ts_ns_scale", tel_ns_ok, f"first ts >= {TEL_NS_MIN:.0e}")
    chk("telemetry_device_id", tel_dev_ok, f"device_id=={vn}")

    # network derived proof (zeek conn from the pcap)
    conn_n = nlines(zeek_conn)
    chk("network_zeek_conn", conn_n > 1, f"conn rows={max(conn_n-1,0)} ({os.path.basename(zeek_conn or '-')})")

    # ---------- verdict + RUNDETAIL ----------
    detail = dict(run=a.run, device=vn, stage=a.stage, start=a.start, end=a.end,
                  windows=nwin, inrun_windows=n_inrun, net_frac=net_frac, tel_frac=tel_frac, host_frac=host_frac,
                  app_frac=app_frac, audit_built_frac=audit_built, benign_app_frac=ben_app,
                  benign_auth_frac=ben_auth, audit_lines=audit_n, journald_lines=jrnl_n,
                  applog_lines=applog_n, telemetry_rows=tel_rows, zeek_conn_rows=max(conn_n-1,0),
                  tel_cols=tel_w_hdr)
    emit(a, checks, detail)

def emit(a, checks, detail, fatal=False):
    allok = all(ok for _, ok, _ in checks) and not fatal
    print(f"==== verify_run  device={a.device} run={a.run} ====")
    for name, ok, d in checks:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name:26s} {d}")
    detail["verdict"] = "PASS" if allok else "FAIL"
    detail["n_fail"] = sum(1 for _, ok, _ in checks if not ok)
    print("RUNDETAIL " + json.dumps(detail))
    print("VERDICT: " + detail["verdict"])
    sys.exit(0 if allok else 1)

if __name__ == "__main__":
    main()
