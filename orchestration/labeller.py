#!/usr/bin/env python3
"""
Interval-join STAGE labeller (GUARD-BAND reference implementation).

RELATION TO THE PIPELINE: pipeline/align_windows.py is the production aligner and
does the base interval-join (plain overlap, no guard bands) while building the
fused windows. This module is the guard-band-aware variant of that join: it adds
the CORE-interval trimming, the boundary_ambiguous flag, and the grouped-by-
execution key (attack -> per-stage-execution group; benign -> per-device time
block). finalize_dataset.py applies the SAME guard rule to align_windows.py output;
this file is the standalone/reference version and is handy for labelling an
arbitrary window index directly from labels.ndjson.

Given (a) the orchestrator's ground-truth labels.ndjson and (b) a per-device
window index on each board's synced CLOCK_REALTIME, assign every window:
    stage                       majority-overlap lifecycle stage (else 'benign')
    stage_multilabel            all stages whose CORE interval the window touches
    boundary_ambiguous          window sits in a guard band / straddles a boundary
    primary_modality_hypothesis carried from the stage taxonomy (analysis only)
    group_id                    grouped-BY-EXECUTION split key (anti-leakage)
    run/scenario/repeat/stage_index provenance

CORE interval  = [t_open + guard_pre , t_close - guard_post]  (trusted attack span)
RAW  interval  = [t_open , t_close]
A window is a positive for a stage iff >= min_overlap_frac of the window lies in
that stage's CORE interval. A window that overlaps the RAW span but not enough of
the CORE is flagged boundary_ambiguous (excludable from strict train/eval — the
P7 window-boundary-leakage control). Everything else is 'benign' (benign
background is always on, so 'benign' means "no attack stage here", not "idle").

Because every board captures net+host+telemetry on ONE synced clock, labelling is
per-device and cross-machine skew never enters (Charter S3).

Usage (standalone):
  python labeller.py --labels captures/<run>/labels.ndjson \
                     --windows windows.parquet --manifest scenarios.yaml \
                     --out labelled_windows.parquet
`windows` must have columns: device_id, window_s, w_index, w_start_synced, w_end_synced.
"""
import argparse, json
import numpy as np
import pandas as pd

BENIGN_BLOCK_S = 300   # pure-benign windows are grouped into 5-min execution-like blocks


def load_labels(path):
    rows = [json.loads(l) for l in open(path) if l.strip()]
    return pd.DataFrame(rows)


def _overlap(a0, a1, b0, b1):
    """Length of overlap between [a0,a1] and scalars/arrays [b0,b1]."""
    return np.clip(np.minimum(a1, b1) - np.maximum(a0, b0), 0.0, None)


def label_windows(windows: pd.DataFrame, labels: pd.DataFrame, taxonomy: dict,
                  min_overlap_frac=0.5, benign_block_s=BENIGN_BLOCK_S) -> pd.DataFrame:
    w = windows.copy().reset_index(drop=True)
    n = len(w)
    ws = w["w_start_synced"].to_numpy(float)
    we = w["w_end_synced"].to_numpy(float)
    wlen = np.maximum(we - ws, 1e-9)

    # outputs
    best_frac = np.zeros(n)
    stage = np.array(["benign"] * n, dtype=object)
    multi = [set() for _ in range(n)]
    touch_raw = np.zeros(n, dtype=bool)      # overlaps any RAW attack span at all
    grp = np.array([""] * n, dtype=object)
    prov = {k: np.array([None] * n, dtype=object) for k in
            ("run_id", "scenario_id", "repeat_idx", "stage_index", "primary_modality_hypothesis")}

    if len(labels):
        for dev_id, dev_labels in labels.groupby("target_device_id"):
            m = (w["device_id"].to_numpy() == dev_id)
            if not m.any():
                continue
            idx = np.where(m)[0]
            for _, lb in dev_labels.iterrows():
                t0, t1 = float(lb["t_open_synced"]), float(lb["t_close_synced"])
                c0, c1 = t0 + float(lb["guard_pre_s"]), t1 - float(lb["guard_post_s"])
                if c1 <= c0:                      # degenerate after trimming
                    c0, c1 = t0, t1
                # raw overlap (any) -> ambiguity candidate
                raw_ov = _overlap(ws[idx], we[idx], t0, t1)
                touch_raw[idx[raw_ov > 0]] = True
                # core overlap fraction
                core_ov = _overlap(ws[idx], we[idx], c0, c1)
                frac = core_ov / wlen[idx]
                st = lb["stage"]
                for j_local, f in zip(idx, frac):
                    if f > 0:
                        multi[j_local].add(st)
                    if f > best_frac[j_local]:
                        best_frac[j_local] = f
                        if f >= min_overlap_frac:
                            stage[j_local] = st
                        # provenance of the dominant stage (even if sub-threshold, keep pointer)
                        prov["run_id"][j_local] = lb["run_id"]
                        prov["scenario_id"][j_local] = lb["scenario_id"]
                        prov["repeat_idx"][j_local] = lb.get("repeat_idx")
                        prov["stage_index"][j_local] = lb["stage_index"]
                        prov["primary_modality_hypothesis"][j_local] = taxonomy.get(st, {}).get("primary_modality")

    # boundary_ambiguous: touched a raw span but was NOT a confident positive
    ambiguous = touch_raw & (best_frac < min_overlap_frac)
    # a window that touched a raw span but stayed 'benign' by threshold: keep stage from best pointer,
    # flag ambiguous so it is excludable from strict eval
    for j in np.where(ambiguous)[0]:
        if stage[j] == "benign" and prov["scenario_id"][j] is not None:
            # keep it benign-labelled but flagged; the pointer/provenance stays for grouping
            pass

    # group_id (grouped-by-execution). Attack/boundary windows -> their stage execution;
    # pure benign -> per-device 5-min block so contiguous benign never spans train/test.
    for j in range(n):
        if prov["scenario_id"][j] is not None and (stage[j] != "benign" or ambiguous[j]):
            grp[j] = f"{prov['run_id'][j]}|{prov['scenario_id'][j]}|r{prov['repeat_idx'][j]}|s{prov['stage_index'][j]}"
        else:
            blk = int(ws[j] // benign_block_s)
            grp[j] = f"BENIGN|{w['device_id'].iloc[j]}|blk{blk}"

    w["stage"] = stage
    w["stage_multilabel"] = [sorted(s) if s else ["benign"] for s in multi]
    w["boundary_ambiguous"] = ambiguous
    w["core_overlap_frac"] = np.round(best_frac, 4)
    w["group_id"] = grp
    for k, arr in prov.items():
        w[k] = arr
    return w


def main():
    import yaml
    ap = argparse.ArgumentParser()
    ap.add_argument("--labels", required=True)
    ap.add_argument("--windows", required=True, help="parquet/csv with device_id,window_s,w_index,w_start_synced,w_end_synced")
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--out", default="labelled_windows.parquet")
    ap.add_argument("--min-overlap-frac", type=float, default=None)
    a = ap.parse_args()

    man = yaml.safe_load(open(a.manifest))
    tax = man["stage_taxonomy"]
    mof = a.min_overlap_frac if a.min_overlap_frac is not None else man["defaults"].get("min_overlap_frac", 0.5)

    windows = pd.read_parquet(a.windows) if a.windows.endswith(".parquet") else pd.read_csv(a.windows)
    labels = load_labels(a.labels)
    out = label_windows(windows, labels, tax, min_overlap_frac=mof)

    if a.out.endswith(".parquet"):
        out.to_parquet(a.out, index=False)
    else:
        out.to_csv(a.out, index=False)
    print(f"[labeller] {len(out)} windows labelled  ->  {a.out}")
    print(out["stage"].value_counts().to_string())
    print(f"boundary_ambiguous: {int(out['boundary_ambiguous'].sum())}  groups: {out['group_id'].nunique()}")


if __name__ == "__main__":
    main()
