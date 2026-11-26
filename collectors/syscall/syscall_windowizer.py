#!/usr/bin/env python3
"""
syscall_windowizer.py -- turn a raw syscall EVENT stream (from eBPF/perf/strace)
into the CIC-YNU-IoTMal strace representation: 20-syscall windows of per-name
counts, grouped by execution, plus execution-level mean/std/max aggregates.

OUTPUT MATCHES THE PILOT PIPELINE (P4_pilot.py / P7_binary_controlled.py):
  * per-window rows  : exec_key, device_id, arch, win_idx, Call_<canon>...  (n counts)
  * exec aggregates  : <canon>__mean, <canon>__std, <canon>__max, n_win
The per-window `win_idx` is retained so the pipeline can DROP the first K windows
(the dynamic-loader / start-up phase) exactly as P7 does with K=100/300 -- this
neutralises the P7(a) linking shortcut. `exec_key` is the grouping unit for the
train/test split, which neutralises the P7(c) window-level leakage.

WINDOWS: default is tumbling (non-overlapping) blocks of W=20 syscalls per
execution, ordered by ts_mono -- matching how CIC-YNU indexes windows by
per-Hash position. `--stride` < W gives sliding windows (an ablation).

CANONICALISATION: syscall_canon.canon() folds aarch32 (mmap2, fcntl64, chown32,
_newselect, *_time64...) and aarch64 (openat, newfstatat, pselect6, *at forms...)
onto one vocabulary. Numbers from eBPF/perf are resolved with the board's
`ausyscall --dump` table (--arch-table, saved per board by record_device_meta.sh).

Usage:
  # eBPF NDJSON, resolve numbers with the board's saved table:
  python3 syscall_windowizer.py --format ebpf \
      --arch-table meta/ausyscall_rpi5.txt \
      --in captures/rpi5/syscall/*.ndjson \
      --out-windows out/rpi5_windows.parquet --out-exec out/rpi5_exec.parquet

  # strace text (names already present; no arch table needed):
  python3 syscall_windowizer.py --format strace --arch armv7l \
      --in captures/rpi3b/exec_*.strace --out-exec out/rpi3b_exec.parquet
"""
import argparse, glob, json, os, re, sys
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import syscall_canon as C

W_DEFAULT = 20


# ---------------------------------------------------------------- parsers
def iter_ebpf(paths):
    """NDJSON from syscall_ebpf_collector.py (has exe_start_ns => exact exec key)."""
    for p in paths:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                key = f"{r['tgid']}:{r.get('exe_start_ns', 0)}"
                yield key, float(r["ts_mono"]), int(r["syscall_id"]), None


def iter_perf(paths):
    """NDJSON from perf_to_ndjson.sh (no start_time => key = tgid:comm)."""
    for p in paths:
        with open(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = json.loads(line)
                key = f"{r['tgid']}:{r.get('comm', '')}"
                ts = float(r.get("ts_mono", r.get("ts_real", 0.0)))
                yield key, ts, int(r["syscall_id"]), None


# strace line: "12345 14:02:11.123456 openat(AT_FDCWD, ...) = 3 <0.000012>"
_STRACE = re.compile(r"^\s*(?P<pid>\d+)?\s*[\d:.]*\s*(?P<name>[a-zA-Z_][\w]*)\(")


def iter_strace(paths):
    """strace -f text; whole file (one execution tree) shares one exec key."""
    for p in paths:
        exec_key = os.path.basename(p)
        seq = 0
        with open(p, errors="replace") as f:
            for line in f:
                if any(t in line for t in ("--- SIG", "+++ ", "<unfinished",
                                           "resumed>", "= ?")):
                    # keep resumed lines? we count on entry name only
                    pass
                m = _STRACE.match(line)
                if not m or not m.group("name"):
                    continue
                seq += 1
                yield exec_key, float(seq), None, m.group("name")


# ---------------------------------------------------------------- core
def build(events, arch_table, window, stride, cic_compat):
    """events -> (per-window rows list, per-exec aggregates dict).

    Streams per execution, orders by ts, forms windows, counts canon names.
    Aggregates kept online (sum, sumsq, max, count) like P7.aggregate().
    """
    per_exec_events = defaultdict(list)  # exec_key -> [(ts, canon_name)]
    for key, ts, sid, name in events:
        if name is None:
            raw = arch_table.get(sid, f"nr_{sid}") if arch_table else f"nr_{sid}"
        else:
            raw = name
        cn = C.canon(raw)
        if cic_compat and cn in C.TRUNC:
            continue
        per_exec_events[key].append((ts, cn))

    win_rows = []
    agg = {}  # exec_key -> {name: [sum, sumsq, max, cnt_over_windows]}, plus _nwin
    for key, evs in per_exec_events.items():
        evs.sort(key=lambda x: x[0])
        names = [n for _, n in evs]
        a = defaultdict(lambda: [0.0, 0.0, 0.0])
        nwin = 0
        i = 0
        step = stride if stride else window
        while i < len(names):
            chunk = names[i:i + window]
            if len(chunk) < window and i != 0:
                # tail shorter than a full window: keep it (like CIC-YNU keeps
                # the final partial window) but only if it is the sole/last one
                pass
            counts = defaultdict(int)
            for nm in chunk:
                counts[nm] += 1
            row = {"exec_key": key, "win_idx": nwin}
            for nm, c in counts.items():
                row[f"Call_{nm}"] = c
                s = a[nm]
                s[0] += c
                s[1] += c * c
                s[2] = max(s[2], c)
            win_rows.append(row)
            nwin += 1
            i += step
        exec_agg = {"n_win": nwin}
        for nm, (s, ss, mx) in a.items():
            mean = s / nwin if nwin else 0.0
            var = max(0.0, ss / nwin - mean * mean) if nwin else 0.0
            exec_agg[f"{nm}__mean"] = mean
            exec_agg[f"{nm}__std"] = var ** 0.5
            exec_agg[f"{nm}__max"] = mx
        agg[key] = exec_agg
    return win_rows, agg


def write_table(rows, path, index_cols):
    if not path:
        return
    try:
        import pandas as pd
        df = pd.DataFrame(rows).fillna(0)
        for c in index_cols:
            if c not in df.columns:
                df[c] = ""
        if path.endswith(".parquet"):
            df.to_parquet(path, index=False)
        else:
            df.to_csv(path, index=False)
        print(f"[windowizer] wrote {path}  ({len(df)} rows, {df.shape[1]} cols)")
    except ImportError:
        import csv
        keys = sorted({k for r in rows for k in r})
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            for r in rows:
                w.writerow({k: r.get(k, 0) for k in keys})
        print(f"[windowizer] wrote {path} (csv fallback, {len(rows)} rows)")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", nargs="+", required=True,
                    help="input files/globs")
    ap.add_argument("--format", choices=["ebpf", "perf", "strace"], required=True)
    ap.add_argument("--arch-table", help="ausyscall --dump file (ebpf/perf)")
    ap.add_argument("--arch", default="", help="tag written into exec rows")
    ap.add_argument("--device-id", default="")
    ap.add_argument("--window", type=int, default=W_DEFAULT)
    ap.add_argument("--stride", type=int, default=0,
                    help="0 => tumbling (=window). <window => sliding (ablation)")
    ap.add_argument("--cic-compat", action="store_true",
                    help="also drop CIC-YNU truncated tokens for like-for-like")
    ap.add_argument("--out-windows", help="per-window table (parquet/csv)")
    ap.add_argument("--out-exec", help="per-execution aggregate table")
    a = ap.parse_args()

    paths = []
    for g in a.inp:
        paths.extend(sorted(glob.glob(g)))
    if not paths:
        sys.exit("no input files matched")

    arch_table = {}
    if a.format in ("ebpf", "perf"):
        if not a.arch_table:
            sys.exit("--arch-table (ausyscall --dump) required for ebpf/perf")
        arch_table = C.load_arch_table(open(a.arch_table).read())

    reader = {"ebpf": iter_ebpf, "perf": iter_perf, "strace": iter_strace}[a.format]
    win_rows, agg = build(reader(paths), arch_table, a.window, a.stride,
                           a.cic_compat)

    for r in win_rows:
        r["device_id"] = a.device_id
        r["arch"] = a.arch
    exec_rows = [dict(exec_key=k, device_id=a.device_id, arch=a.arch, **v)
                 for k, v in agg.items()]

    write_table(win_rows, a.out_windows, ["exec_key", "device_id", "arch", "win_idx"])
    write_table(exec_rows, a.out_exec, ["exec_key", "device_id", "arch"])
    print(f"[windowizer] executions={len(agg)}  windows={len(win_rows)}")


if __name__ == "__main__":
    main()
