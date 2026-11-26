#!/usr/bin/env python3
r"""
derive_windows.py -- derive W5/W8/W10 fused windows from the shipped W1 windows, for every
By_device run (and By_labels pooled, optional). A WN window groups N consecutive 1-second
windows that share the same global-epoch bin (bin = window_idx // N). Count-type features are
summed; telemetry gauges/rates are averaged; the modality mask is OR-ed; the label is the
bin's dominant non-normal attack (benign only if no attack second falls in the bin). This
matches the native multi-second aggregation closely while reusing the released W1 data.

Usage: derive_windows.py [--root dataset_v4] [--sizes 5,8,10]
"""
import argparse, glob, os, numpy as np, pandas as pd

KEYS = ["device_id", "window_idx", "window_start_iso", "group_id",
        "attack_type", "stage", "label_overlap", "modality_mask"]
# telemetry gauge/rate columns are averaged; every other feature column is summed.
TEL_MEAN = {f"tel__{c}" for c in ("cpu_pct", "mem_pct", "mem_used_mb", "load1", "load5",
            "load15", "nprocs", "temp_c", "disk_r_bps", "disk_w_bps", "net_rx_bps", "net_tx_bps")}


def or_mask(masks):
    masks = [m for m in masks if isinstance(m, str) and m]
    if not masks:
        return ""
    width = max(len(m) for m in masks)
    out = ["0"] * width
    for m in masks:
        for i, ch in enumerate(m):
            if ch == "1":
                out[i] = "1"
    return "".join(out)


def derive(df, N):
    feats = [c for c in df.columns if c.startswith(("net__", "host__", "tel__", "applog__"))]
    df = df.copy()
    df["_bin"] = (df["window_idx"] // N).astype("int64")
    rows = []
    for (dev, b), g in df.groupby(["device_id", "_bin"], sort=True):
        atk = g[g["attack_type"] != "normal"]
        if len(atk):
            # dominant attack = most seconds in the bin (tiebreak: summed label_overlap)
            top = (atk.groupby("attack_type")
                      .agg(n=("attack_type", "size"), ov=("label_overlap", "sum"))
                      .sort_values(["n", "ov"], ascending=False).index[0])
            arow = atk[atk["attack_type"] == top].iloc[0]
            at, st, gid = top, arow["stage"], arow["group_id"]
        else:
            at, st, gid = "normal", "normal", f"benign#{dev}#{int(b)}"
        rec = {"device_id": dev, "window_idx": int(b),
               "window_start_iso": g["window_start_iso"].iloc[0], "group_id": gid,
               "attack_type": at, "stage": st,
               "label_overlap": float(g["label_overlap"].sum()),
               "modality_mask": or_mask(list(g["modality_mask"]))}
        for c in feats:
            if c in TEL_MEAN:
                rec[c] = g[c].mean()                       # gauge/rate -> mean (NaN if all absent)
            else:
                rec[c] = g[c].sum(min_count=1)             # count/bytes -> sum (NaN if all absent)
        rows.append(rec)
    out = pd.DataFrame(rows)
    return out[[k for k in KEYS] + feats]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default="./dataset")
    ap.add_argument("--sizes", default="5,8,10")
    ap.add_argument("--glob", default="By_device_and_campaigns/*/*/preprocessed/windows_w1.csv")
    a = ap.parse_args()
    sizes = [int(s) for s in a.sizes.split(",")]
    files = sorted(glob.glob(os.path.join(a.root, a.glob)))
    print(f"[derive] {len(files)} W1 files -> W{sizes}")
    tot = {N: 0 for N in sizes}
    for f in files:
        d = pd.read_csv(f, dtype={"modality_mask": str})
        for N in sizes:
            o = derive(d, N)
            op = f.replace("windows_w1.csv", f"windows_w{N}.csv")
            o.to_csv(op, index=False)
            tot[N] += len(o)
    for N in sizes:
        print(f"[derive] W{N}: total windows = {tot[N]}")
    print("[derive] DONE")


if __name__ == "__main__":
    main()
