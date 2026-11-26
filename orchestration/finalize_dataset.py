#!/usr/bin/env python3
"""
finalize_dataset.py -- dataset-assembly FINALISE step (downstream of the aligner).

pipeline/align_windows.py already produces fused, stage-labelled windows with a
modality_mask and a group_id (per-execution / per-benign-block), but it
deliberately does NOT split ("Downstream MUST split by group_id and temporally")
and does not apply guard bands or a per-device telemetry baseline. This script
fills exactly those gaps, purely ADDITIVELY, so the two do not duplicate work:

  1. GUARD BANDS (P7 boundary-leakage control). Using labels.csv (start_ns/end_ns
     + guard_pre_s/guard_post_s written by the orchestrator), recompute each
     window's overlap with the stage's CORE interval [start+guard_pre, end-guard_post]
     and set boundary_ambiguous + core_overlap_frac. Ambiguous windows keep their
     label but are excludable from strict train/eval.
  2. PER-DEVICE BENIGN BASELINE (P5 fix). Median of each tel__ feature over
     confident-benign windows on that device IN THE SAME CAMPAIGN ->
     benign_baseline_<device>.json, plus baseline-relative telemetry telb__*
     (tel__ minus device baseline) that neutralises the device/arch fingerprint.
  3. SPLIT INDICES keyed by group_id (row-order independent):
       grouped_kfold          GroupKFold(5) by group_id — same execution never
                              spans folds (P7: window-level random splits cost up
                              to 0.35 macro-F1)
       temporal_holdout       groups split by earliest window time (temporally
                              honest; benign+malicious are same-campaign, so the
                              P7 capture-date confound is already neutralised)
       leave_one_scenario_out per scenario, its groups form the test set
  4. dataset_card.json (counts, mask coverage, feature groups, provenance, and
     the CIC-YNU alignment note).

Usage:
  python finalize_dataset.py \
      --fused captures/<run>/aligned/fused_windows_W1.csv \
      --labels captures/<run>/labels.csv \
      --run-manifest captures/<run>/run_manifest.json \
      --window-s 1 --out-dir dataset/<run>
"""
import argparse, json, os
from datetime import datetime, timezone
import numpy as np
import pandas as pd

SENTINEL = -1.0
BENIGN_STAGES = {"normal", "benign", "S0_baseline_benign"}


def _read(path):
    return pd.read_parquet(path) if path.endswith(".parquet") else pd.read_csv(path, low_memory=False)


def _win_start_epoch(df, window_s):
    if "window_start_iso" in df.columns:
        return pd.to_datetime(df["window_start_iso"], utc=True, errors="coerce").astype("int64") / 1e9
    return df["window_idx"].astype(float) * window_s


def add_guard_flags(fused, labels, window_s, min_overlap_frac):
    """Recompute core-interval overlap with guard bands; set boundary_ambiguous."""
    ws = _win_start_epoch(fused, window_s).to_numpy(float)
    we = ws + window_s
    frac = np.zeros(len(fused))
    ambiguous = np.zeros(len(fused), dtype=bool)
    if not labels.empty:
        lab = labels.copy()
        lab["t0"] = lab["start_ns"].astype(float) / 1e9
        lab["t1"] = lab["end_ns"].astype(float) / 1e9
        lab["c0"] = lab["t0"] + lab["guard_pre_s"].astype(float)
        lab["c1"] = lab["t1"] - lab["guard_post_s"].astype(float)
        dev = fused["device_id"].to_numpy()
        stg = fused["stage"].astype(str).to_numpy()
        for _, r in lab.iterrows():
            sel = (dev == r["target"]) & (stg == str(r["stage"]))
            if not sel.any():
                continue
            idx = np.where(sel)[0]
            core = np.clip(np.minimum(we[idx], r["c1"]) - np.maximum(ws[idx], r["c0"]), 0, None) / window_s
            raw = np.clip(np.minimum(we[idx], r["t1"]) - np.maximum(ws[idx], r["t0"]), 0, None)
            frac[idx] = np.maximum(frac[idx], core)
            ambiguous[idx] |= (raw > 0) & (core < min_overlap_frac)
    fused = fused.copy()
    fused["core_overlap_frac"] = np.round(frac, 4)
    fused["boundary_ambiguous"] = ambiguous
    return fused


def add_baseline(fused):
    tel_cols = [c for c in fused.columns if c.startswith("tel__") and not c.endswith("cnt")]
    baselines = {}
    for dev, grp in fused.groupby("device_id"):
        benign = grp[grp["stage"].astype(str).isin(BENIGN_STAGES) & (~grp.get("boundary_ambiguous", False))]
        benign = benign[benign[tel_cols].notna().any(axis=1)] if tel_cols else benign
        if len(benign) >= 5 and tel_cols:
            baselines[dev] = benign[tel_cols].median(numeric_only=True).to_dict()
    for dev, base in baselines.items():
        mrow = fused["device_id"] == dev
        for c in tel_cols:
            fused.loc[mrow, "telb__" + c.split("tel__", 1)[1]] = fused.loc[mrow, c] - base.get(c, 0.0)
    telb = [c for c in fused.columns if c.startswith("telb__")]
    if telb:
        fused[telb] = fused[telb].fillna(SENTINEL)
    return fused, baselines


def make_splits(df, n_splits=5, temporal_test_frac=0.3, seed=42, window_s=1):
    rng = np.random.default_rng(seed)
    g = df.groupby("group_id")
    gids = list(g.groups.keys())
    shuffled = list(rng.permutation(gids))
    group_to_fold = {str(x): i % n_splits for i, x in enumerate(shuffled)}

    ws = _win_start_epoch(df, window_s)
    gmin = ws.groupby(df["group_id"]).min().sort_values()
    cut = int(len(gmin) * (1 - temporal_test_frac))
    temporal = {"train_groups": [str(x) for x in gmin.index[:cut]],
                "test_groups": [str(x) for x in gmin.index[cut:]]}

    loso = {}
    if "scenario_id" in df.columns:
        base = df[df["scenario_id"].notna()] if "scenario_id" in df else df
    # group_id encodes scenario for attack windows (scenario#run); derive LOSO from it
    scen_of = df.assign(_scen=df["group_id"].astype(str).str.split("#").str[0])
    for scen, sg in scen_of[~scen_of["_scen"].str.startswith("benign")].groupby("_scen"):
        loso[scen] = {"test_groups": sorted(sg["group_id"].astype(str).unique().tolist())}

    return {"grouped_kfold": {"n_splits": n_splits, "group_to_fold": group_to_fold},
            "temporal_holdout": temporal,
            "leave_one_scenario_out": loso,
            "note": "map each row to a split via its group_id column; benign groups are per-device time blocks."}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--fused", required=True, help="align_windows.py output fused_windows_W*.csv/parquet")
    ap.add_argument("--labels", required=True, help="orchestrator labels.csv (has guard_pre_s/guard_post_s, start_ns/end_ns)")
    ap.add_argument("--run-manifest", required=True)
    ap.add_argument("--window-s", type=int, default=1)
    ap.add_argument("--min-overlap-frac", type=float, default=0.5)
    ap.add_argument("--out-dir", required=True)
    a = ap.parse_args()

    os.makedirs(a.out_dir, exist_ok=True)
    fused = _read(a.fused)
    labels = _read(a.labels) if os.path.exists(a.labels) else pd.DataFrame()
    rm = json.load(open(a.run_manifest))
    fps = rm.get("device_fingerprints", {})

    fused = add_guard_flags(fused, labels, a.window_s, a.min_overlap_frac)
    fused, baselines = add_baseline(fused)

    # controlled nuisance metadata (recorded, NOT features)
    fused["board"] = fused["device_id"].map(lambda d: fps.get(d, {}).get("board"))
    fused["arch"] = fused["device_id"].map(lambda d: fps.get(d, {}).get("arch"))
    fused["cfg_kernel"] = fused["device_id"].map(lambda d: fps.get(d, {}).get("kernel"))
    fused["cfg_ram_mb"] = fused["device_id"].map(lambda d: fps.get(d, {}).get("ram_mb"))
    fused["cfg_governor"] = fused["device_id"].map(lambda d: fps.get(d, {}).get("governor"))
    fused["cfg_nvpmodel"] = fused["device_id"].map(lambda d: fps.get(d, {}).get("nvpmodel"))

    splits = make_splits(fused, window_s=a.window_s)

    ds = os.path.join(a.out_dir, f"dataset_w{a.window_s}.parquet")
    fused.to_parquet(ds, index=False)
    json.dump(splits, open(os.path.join(a.out_dir, f"split_indices_w{a.window_s}.json"), "w"), indent=2)
    for dev, base in baselines.items():
        json.dump(base, open(os.path.join(a.out_dir, f"benign_baseline_{dev}.json"), "w"), indent=2)

    mask_col = fused["modality_mask"].astype(str) if "modality_mask" in fused else pd.Series([], dtype=str)
    card = {
        "run_id": rm.get("run_id"), "window_s": a.window_s, "n_windows": int(len(fused)),
        "n_groups": int(fused["group_id"].nunique()),
        "stage_counts": fused["stage"].value_counts().to_dict(),
        "boundary_ambiguous": int(fused["boundary_ambiguous"].sum()),
        "modality_mask_counts": mask_col.value_counts().to_dict() if len(mask_col) else {},
        "feature_groups": {p: [c for c in fused.columns if c.startswith(p)]
                           for p in ("net__", "host__", "tel__", "telb__")},
        "nuisance_metadata_not_features": ["board", "arch", "cfg_kernel", "cfg_ram_mb", "cfg_governor", "cfg_nvpmodel"],
        "ethics_ref": rm.get("ethics_ref"), "manifest_sha256": rm.get("manifest_sha256"),
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "cic_ynu_alignment": "S5_execution windows correspond to CIC-YNU-IoTMal's single represented stage "
                             "(post-delivery execution in isolation); group_id mirrors CIC's group-by-hash; "
                             "net__/host__/tel__ mirror pcap/strace(auditd)/sar so E1'/E2' cross-reference cleanly.",
    }
    json.dump(card, open(os.path.join(a.out_dir, f"dataset_card_w{a.window_s}.json"), "w"), indent=2)

    print(f"[finalize] {len(fused)} windows (w={a.window_s}s) -> {ds}")
    print(fused["stage"].value_counts().to_string())
    print(f"boundary_ambiguous={int(fused['boundary_ambiguous'].sum())}  groups={fused['group_id'].nunique()}  "
          f"baselines={list(baselines)}")


if __name__ == "__main__":
    main()
