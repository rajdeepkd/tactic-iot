#!/usr/bin/env python3
r"""
validate_alignment.py -- PROVE cross-source alignment quality for a capture.

Two independent estimators, plus the chrony skew already logged at capture time:

  (A) BEACON RESIDUALS (direct, per event, per modality).
      sync_beacon.py leaves one coincident mark in host+network+telemetry and
      prints a receipt with the true emit time (synced CLOCK_REALTIME). For each
      beacon we find its observation in each modality and report
          residual = observed_collector_ts - beacon_emit_ts.
      This measures the ACTUAL alignment error the dataset will carry -- clock
      skew AND collector/sampling latency -- not just the clock offset.

  (B) CROSS-CORRELATION OFFSET RECOVERY (indirect, retained from Phase-0 / E2b).
      For a rate-signalled scenario (the slow SSH brute force: 1 attempt / 25 s),
      build a fine-binned event-rate series per modality, cross-correlate each
      pair, and read the lag at peak correlation. Good alignment => peak lag ~ 0
      (within one bin); the recovered PERIOD must also match the known 25 s
      cadence (a scale sanity check). This needs no beacons and cross-checks (A).

Gate: report PASS if max|residual| and |xcorr lag| are both below
      --gate-frac x the smallest analysis window (default 0.1 x 1 s = 100 ms).
      A capture that fails the gate is rejected (a validity gate, like the
      concurrency gate in charter principle #2).

Usage:
  python3 validate_alignment.py \
      --beacons ./captures/run1/beacons.jsonl \
      --captures ./captures/run1 \
      --labels ./captures/run1/labels.csv \
      --net-markers ./captures/run1/beacon_udp.csv   # optional (tshark export)
      --chrony-snaps ./captures/run1/timesync        # optional (setup_timesync.sh)
      --bruteforce-scenario brute_ssh_slow --expected-period-s 25 \
      --bin-ms 100 --min-window-s 1 --out ./captures/run1/aligned/alignment_report.json

Extract the network marker CSV with, e.g.:
  tshark -r cap.pcap -Y 'udp.port==52525' -T fields -e frame.time_epoch -e data \
      | awk '{printf "%.9f,%s\n",$1,$2}' > beacon_udp.csv   # ts_epoch,hexpayload
"""
import argparse, glob, json, os, sys
from datetime import datetime, timezone
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import align_windows as aw  # reuse the exact same readers -> same timestamps

NS = 1_000_000_000


# --------------------------------------------------------------------------- #
# (A) beacon residuals
# --------------------------------------------------------------------------- #
def load_beacons(path):
    """receipts.jsonl: one sync_beacon.py receipt per line."""
    recs = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    recs.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return recs


def host_observations(captures):
    """{beacon_id: (device_id, observed_ts_ns)} from journald SYNCBEACON lines."""
    obs = {}
    files = sorted(glob.glob(os.path.join(captures, "**", "*journal*.json"), recursive=True))
    for p in files:
        with aw._open_maybe_gz(p) as fh:
            for line in fh:
                line = line.strip()
                if not line or "SYNCBEACON" not in line:
                    continue
                try:
                    j = json.loads(line)
                except json.JSONDecodeError:
                    continue
                msg = j.get("MESSAGE", "")
                rt = j.get("__REALTIME_TIMESTAMP")
                if rt is None:
                    continue
                try:
                    payload = json.loads(msg[msg.index("{"):])
                except (ValueError, json.JSONDecodeError):
                    continue
                obs[payload.get("beacon")] = (j.get("_HOSTNAME", "?"), int(rt) * 1000)
    return obs


def net_observations(csv_path):
    """{beacon_id: observed_ts_ns} from a tshark-exported marker CSV
    (frame.time_epoch, hex-payload). Payload carries the beacon JSON after the
    14-byte magic -> we just match on the beacon id substring."""
    obs = {}
    if not csv_path or not os.path.exists(csv_path):
        return obs
    for line in open(csv_path, encoding="utf-8", errors="replace"):
        ts_str, _, hexp = line.strip().partition(",")
        try:
            ts_ns = int(round(float(ts_str) * NS))
        except ValueError:
            continue
        try:
            raw = bytes.fromhex(hexp.replace(":", "")).decode("utf-8", "replace")
            payload = json.loads(raw[raw.index("{"):])
            obs[payload.get("beacon")] = ts_ns
        except (ValueError, json.JSONDecodeError):
            continue
    return obs


def residuals(beacons, host_obs, net_obs):
    rows = []
    for b in beacons:
        bid, dev, emit = b.get("beacon"), b.get("device_id"), b.get("emit_real_ns")
        if emit is None:
            continue
        if bid in host_obs:
            rows.append((dev, "host", (host_obs[bid][1] - emit) / 1e6))   # ms
        if bid in net_obs:
            rows.append((dev, "net", (net_obs[bid] - emit) / 1e6))
    return pd.DataFrame(rows, columns=["device_id", "modality", "residual_ms"])


def telemetry_sampling(captures):
    """Telemetry alignment is bounded by the SAMPLE PERIOD, not clock skew.
    Report achieved period + jitter per device from ts_realtime_ns diffs."""
    tel = aw.read_telemetry(sorted(glob.glob(os.path.join(captures, "**", "telemetry_*.csv"), recursive=True)))
    out = {}
    if tel is None:
        return out
    tel = tel.dropna(subset=["ts_ns"])
    for dev, g in tel.groupby("device_id"):
        d = np.diff(np.sort(g["ts_ns"].astype("int64").values)) / 1e6  # ms
        if len(d):
            out[dev] = {"median_period_ms": float(np.median(d)),
                        "p95_period_ms": float(np.percentile(d, 95)),
                        "n_samples": int(len(g))}
    return out


# --------------------------------------------------------------------------- #
# (B) cross-correlation offset recovery
# --------------------------------------------------------------------------- #
def rate_series(frame, count_col_hint, t0_ns, t1_ns, bin_ns):
    """Event-count series over [t0,t1) at bin_ns resolution for a frame."""
    if frame is None or frame.empty:
        return None
    ts = frame["ts_ns"].dropna().astype("int64").values
    ts = ts[(ts >= t0_ns) & (ts < t1_ns)]
    if ts.size < 5:
        return None
    nb = int((t1_ns - t0_ns) // bin_ns) + 1
    idx = ((ts - t0_ns) // bin_ns).astype(int)
    s = np.bincount(idx, minlength=nb).astype(float)
    return s


def xcorr_lag(a, b, bin_ns, max_lag_bins):
    """Lag (ns) at peak cross-correlation of b relative to a; + peak corr."""
    a = a - a.mean(); b = b - b.mean()
    if a.std() == 0 or b.std() == 0:
        return None, 0.0
    lags = range(-max_lag_bins, max_lag_bins + 1)
    best_lag, best_c = 0, -2.0
    for L in lags:
        if L >= 0:
            x, y = a[L:], b[:len(b) - L] if L else b
        else:
            x, y = a[:L], b[-L:]
        n = min(len(x), len(y))
        if n < 5:
            continue
        c = np.corrcoef(x[:n], y[:n])[0, 1]
        if np.isfinite(c) and c > best_c:
            best_c, best_lag = c, L
    return best_lag * bin_ns, best_c


def dominant_period_s(series, bin_ns):
    """Recover the dominant period via the real FFT (scale sanity check)."""
    s = series - series.mean()
    if s.std() == 0 or len(s) < 8:
        return None
    sp = np.abs(np.fft.rfft(s))
    freqs = np.fft.rfftfreq(len(s), d=bin_ns / NS)  # Hz
    sp[0] = 0
    k = int(np.argmax(sp))
    return (1.0 / freqs[k]) if freqs[k] > 0 else None


def crosscorr_check(captures, labels_path, scenario, bin_ms, max_lag_s):
    lab = aw.load_labels(labels_path)
    row = lab[lab["scenario_id"].astype(str).str.startswith(scenario)] if not lab.empty else lab
    if row.empty:
        return {"note": f"scenario '{scenario}' not in labels; skipped"}
    r = row.iloc[0]
    dev, t0, t1 = r["target"], int(r["start_ns"]), int(r["end_ns"])
    bin_ns = int(bin_ms * 1e6)
    max_lag_bins = int((max_lag_s * NS) // bin_ns)

    net = aw.read_zeek_conn(sorted(glob.glob(os.path.join(captures, "**", "*conn.log*"), recursive=True)),
                            aw.device_from_filename)
    hostf = [aw.read_journald(sorted(glob.glob(os.path.join(captures, "**", "*journal*.json"), recursive=True)),
                              aw.device_from_filename),
             aw.read_auditd(sorted(glob.glob(os.path.join(captures, "**", "*audit*.log*"), recursive=True)),
                            aw.device_from_filename)]
    hostf = [h for h in hostf if h is not None]
    host = pd.concat(hostf, ignore_index=True) if hostf else None
    tel = aw.read_telemetry(sorted(glob.glob(os.path.join(captures, "**", "telemetry_*.csv"), recursive=True)))

    def dev_only(f):
        return f[f["device_id"] == dev] if (f is not None and "device_id" in f) else f

    series = {"net": rate_series(dev_only(net), None, t0, t1, bin_ns),
              "host": rate_series(dev_only(host), None, t0, t1, bin_ns),
              "tel": rate_series(dev_only(tel), None, t0, t1, bin_ns)}
    series = {k: v for k, v in series.items() if v is not None}

    lags, periods = {}, {}
    for k, v in series.items():
        p = dominant_period_s(v, bin_ns)
        if p:
            periods[k] = round(p, 2)
    ref = "host" if "host" in series else next(iter(series), None)
    if ref:
        for k in series:
            if k == ref:
                continue
            lag_ns, c = xcorr_lag(series[ref], series[k], bin_ns, max_lag_bins)
            if lag_ns is not None:
                lags[f"{ref}->{k}"] = {"lag_ms": round(lag_ns / 1e6, 2), "peak_corr": round(c, 3)}
    return {"scenario": scenario, "target": dev, "ref_modality": ref,
            "bin_ms": bin_ms, "recovered_period_s": periods, "pairwise_lag": lags}


# --------------------------------------------------------------------------- #
def chrony_skew(snap_dir):
    """Pull the worst 'RMS offset' from setup_timesync.sh JSON snapshots."""
    out = {}
    if not snap_dir or not os.path.isdir(snap_dir):
        return out
    for p in glob.glob(os.path.join(snap_dir, "*.json")):
        try:
            j = json.load(open(p))
        except (OSError, json.JSONDecodeError):
            continue
        tr = j.get("tracking", "")
        for field in ("RMS offset", "Last offset", "Root dispersion"):
            if field in tr:
                seg = tr.split(field)[1].split("|")[0]
                digits = "".join(ch for ch in seg if ch in "0123456789.eE+-")
                try:
                    out.setdefault(j.get("host", os.path.basename(p)), {})[field] = float(digits) * 1000
                except ValueError:
                    pass
    return out  # values in ms


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--captures", required=True)
    ap.add_argument("--beacons", default=None, help="beacons.jsonl receipts")
    ap.add_argument("--labels", default=None)
    ap.add_argument("--net-markers", default=None, help="tshark UDP marker CSV")
    ap.add_argument("--chrony-snaps", default=None, help="setup_timesync.sh snapshot dir")
    ap.add_argument("--bruteforce-scenario", default="brute_ssh_slow")
    ap.add_argument("--expected-period-s", type=float, default=25.0)
    ap.add_argument("--bin-ms", type=float, default=100.0)
    ap.add_argument("--max-lag-s", type=float, default=5.0)
    ap.add_argument("--min-window-s", type=float, default=1.0)
    ap.add_argument("--gate-frac", type=float, default=0.1)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    if a.labels is None:
        g = os.path.join(a.captures, "labels.csv")
        a.labels = g if os.path.exists(g) else None

    report = {"generated_utc": datetime.now(timezone.utc).isoformat(),
              "captures": a.captures, "gate_ms": a.gate_frac * a.min_window_s * 1000}

    # (A) beacon residuals
    res_summary = {}
    max_resid = 0.0
    if a.beacons and os.path.exists(a.beacons):
        beacons = load_beacons(a.beacons)
        df = residuals(beacons, host_observations(a.captures), net_observations(a.net_markers))
        report["n_beacons"] = len(beacons)
        if not df.empty:
            for (dev, mod), g in df.groupby(["device_id", "modality"]):
                r = g["residual_ms"].abs()
                res_summary[f"{dev}/{mod}"] = {
                    "median_ms": round(float(g["residual_ms"].median()), 3),
                    "p95_abs_ms": round(float(r.quantile(0.95)), 3),
                    "max_abs_ms": round(float(r.max()), 3), "n": int(len(g))}
                max_resid = max(max_resid, float(r.max()))
    report["beacon_residuals"] = res_summary
    report["telemetry_sampling"] = telemetry_sampling(a.captures)

    # (B) cross-correlation offset recovery
    xc = crosscorr_check(a.captures, a.labels, a.bruteforce_scenario, a.bin_ms, a.max_lag_s)
    report["crosscorr"] = xc
    max_lag = 0.0
    for v in xc.get("pairwise_lag", {}).values():
        max_lag = max(max_lag, abs(v["lag_ms"]))
    period_ok = True
    for k, p in xc.get("recovered_period_s", {}).items():
        if abs(p - a.expected_period_s) > 0.15 * a.expected_period_s:
            period_ok = False
    report["period_scale_ok"] = period_ok

    # chrony skew context
    report["chrony_skew_ms"] = chrony_skew(a.chrony_snaps)

    # gate
    gate_ms = report["gate_ms"]
    report["max_beacon_residual_ms"] = round(max_resid, 3)
    report["max_xcorr_lag_ms"] = round(max_lag, 3)
    report["PASS"] = bool(max_resid < gate_ms and max_lag < gate_ms and period_ok)

    os.makedirs(os.path.dirname(a.out) or ".", exist_ok=True)
    json.dump(report, open(a.out, "w"), indent=2)
    print(json.dumps(report, indent=2))
    print(f"\n[validate] gate={gate_ms:.1f} ms  "
          f"max_residual={max_resid:.3f} ms  max_lag={max_lag:.3f} ms  "
          f"PASS={report['PASS']}")
    sys.exit(0 if report["PASS"] else 2)


if __name__ == "__main__":
    main()
