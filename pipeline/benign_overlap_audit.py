#!/usr/bin/env python3
"""
benign_overlap_audit.py -- the P7 SHORTCUT-AUDIT release gate.

A multimodal IDS result is only trustworthy if the benign class BEHAVIOURALLY
OVERLAPS each attack stage: if a single feature (or the mere presence of a
modality) trivially separates benign from an attack, the classifier learns that
artifact, not detection (P7: window-split leakage / benign-never-scans / capture
confounds cost up to 0.35 macro-F1 of illusory gain). This script inspects a
fused_windows_*.csv (from align_windows.py) and flags trivial separators, so the
researcher decides -- BEFORE training -- whether each is a legitimate signal
(scanning IS recon) or a confound to fix in the benign design.

It does NOT train a model. It reports, per attack stage vs benign:
  1. single-feature separability  (rank AUC; |AUC-0.5| high  => one feature nearly
     splits the classes -> shortcut risk),
  2. "benign-never" perfect separators (benign always 0, attack always > 0),
  3. modality-presence leakage       (does an attack stage ALWAYS have a modality
     benign sometimes lacks? -> separable by mask alone),
  4. group-split integrity           (no group_id straddles >1 stage; else a
     row-level split leaks across train/test),
  5. benign richness on the key discriminative features.

Verdict: PASS (no non-obvious trivial separator) or FLAG (review the listed
features). A FLAG is not automatically a failure -- an intended signal (recon ->
scan flows) will flag; the point is that every flag is examined and justified.

Usage:
  python3 benign_overlap_audit.py fused_windows_W1.csv [--auc 0.98] [--json out.json]
"""
import sys, json, argparse
import numpy as np
import pandas as pd

LEAD = {"device_id", "window_idx", "window_start_iso", "group_id",
        "attack_type", "stage", "label_overlap", "modality_mask"}
BENIGN = "normal"


def rank_auc(pos, neg):
    """AUC = P(pos > neg) via Mann-Whitney U with average ranks (tie-safe).
    pos/neg are 1-D arrays (NaNs already removed)."""
    pos, neg = np.asarray(pos, float), np.asarray(neg, float)
    n1, n0 = len(pos), len(neg)
    if n1 == 0 or n0 == 0:
        return np.nan
    allv = np.concatenate([pos, neg])
    order = allv.argsort(kind="mergesort")
    ranks = np.empty(len(allv), float)
    ranks[order] = np.arange(1, len(allv) + 1)
    # average ranks for ties
    _, inv, cnt = np.unique(allv, return_inverse=True, return_counts=True)
    sums = np.zeros(len(cnt))
    np.add.at(sums, inv, ranks)
    ranks = (sums / cnt)[inv]
    r1 = ranks[:n1].sum()
    return (r1 - n1 * (n1 + 1) / 2.0) / (n1 * n0)


def feat_cols(df):
    return [c for c in df.columns if c.startswith(("net__", "host__", "tel__"))
            and not c.endswith("__cnt")]


def audit(df, auc_flag=0.98, min_n=5):
    rep = {"n_windows": int(len(df)), "flags": [], "checks": {}}
    stages = [s for s in df["stage"].unique() if s != BENIGN]
    rep["stages_present"] = stages
    rep["stage_counts"] = df["stage"].value_counts().to_dict()
    rep["modality_mask_counts"] = df["modality_mask"].value_counts().to_dict()

    if not stages:
        rep["verdict"] = "N/A"
        rep["note"] = ("no attack stages in this dataset (benign-only). Capture a "
                       "campaign with labels.csv before the shortcut audit is meaningful.")
        return rep

    ben = df[df["stage"] == BENIGN]
    rep["auc_flag"] = auc_flag
    if len(ben) < min_n:
        rep["verdict"] = "ERROR"
        rep["note"] = (f"benign class ('{BENIGN}') has {len(ben)} rows (<{min_n}) -- cannot "
                       f"audit. Are benign windows labelled '{BENIGN}'? (stages seen: {stages})")
        return rep
    feats = feat_cols(df)

    # (4) group-split integrity: the real leakage risk is a group_id that MIXES
    # benign (normal) with attack windows -> benign would ride into an attack fold.
    # A group spanning several ATTACK stages is BY DESIGN (a campaign-run is one
    # split unit), so that is reported, not flagged.
    def _mixes(s):
        u = set(s); return (BENIGN in u) and bool(u - {BENIGN})
    mixed = df.groupby("group_id")["stage"].apply(_mixes)
    straddlers = mixed[mixed]
    rep["checks"]["group_benign_attack_clean"] = bool(straddlers.empty)
    rep["checks"]["multi_stage_attack_groups"] = int((df.groupby("group_id")["stage"].nunique() > 1).sum())
    if not straddlers.empty:
        rep["flags"].append({"type": "group_mixes_benign_and_attack",
                             "detail": f"{len(straddlers)} group_id(s) contain BOTH benign and attack "
                                       "windows -> benign leaks into an attack fold. Fix grouping/guard bands.",
                             "groups": straddlers.index.tolist()[:10]})

    # per-stage separability + presence leakage
    rep["per_stage"] = {}
    for stg in stages:
        atk = df[df["stage"] == stg]
        entry = {"n": int(len(atk)), "separators": [], "benign_never": [],
                 "presence_leak": []}
        # (3)+(4) modality-presence leakage, BIDIRECTIONAL and AUC-based: a modality
        # whose mere PRESENCE separates the classes (either direction) is a shortcut,
        # even if not a perfect 100/0 split. presence_auc is the AUC of the binary
        # "modality present?" indicator between attack and benign windows.
        for src in ("net", "host", "tel"):
            col = src + "__cnt"
            atk_has = float(atk[col].notna().mean()) if col in atk else 0.0
            ben_has = float(ben[col].notna().mean()) if col in ben else 0.0
            p_auc = atk_has * (1 - ben_has) + 0.5 * (atk_has * ben_has + (1 - atk_has) * (1 - ben_has))
            if max(p_auc, 1 - p_auc) >= auc_flag:
                entry["presence_leak"].append(
                    {"modality": src, "presence_auc": round(p_auc, 3),
                     "attack_present": round(atk_has, 3), "benign_present": round(ben_has, 3),
                     "direction": "attack>benign" if p_auc >= 0.5 else "benign>attack"})
                rep["flags"].append({"type": "modality_presence_separator", "stage": stg,
                                     "modality": src, "presence_auc": round(p_auc, 3)})
        # (1)+(2) single-feature separability
        scored = []
        for c in feats:
            a = atk[c].to_numpy(float); b = ben[c].to_numpy(float)
            a = a[~np.isnan(a)]; b = b[~np.isnan(b)]
            if len(a) < min_n or len(b) < min_n:
                continue
            auc = rank_auc(a, b)
            if np.isnan(auc):
                continue
            sep = max(auc, 1 - auc)
            scored.append((sep, auc, c, b, a))
        scored.sort(reverse=True, key=lambda t: t[0])
        for sep, auc, c, b, a in scored[:6]:
            rec = {"feature": c, "auc": round(float(auc), 4),
                   "benign_nonzero_rate": round(float((b != 0).mean()), 3),
                   "attack_nonzero_rate": round(float((a != 0).mean()), 3)}
            entry["separators"].append(rec)
            if sep >= auc_flag:
                # "benign-never" perfect separator: benign all 0, attack all >0
                if (b == 0).all() and (a > 0).all():
                    entry["benign_never"].append(c)
                rep["flags"].append({"type": "single_feature_separator", "stage": stg,
                                     "feature": c, "auc": round(float(auc), 4),
                                     "benign_nonzero_rate": rec["benign_nonzero_rate"],
                                     "attack_nonzero_rate": rec["attack_nonzero_rate"]})
        rep["per_stage"][stg] = entry

    rep["verdict"] = "FLAG" if rep["flags"] else "PASS"
    return rep


def render(rep):
    print(f"\n=== benign-overlap shortcut audit ===")
    print(f"windows={rep['n_windows']}  stages={rep.get('stages_present')}")
    print(f"stage_counts={rep.get('stage_counts')}")
    print(f"modality_mask_counts={rep.get('modality_mask_counts')}")
    if rep["verdict"] in ("N/A", "ERROR"):
        print(f"\nVERDICT: {rep['verdict']} -- {rep.get('note')}")
        return
    thr = rep.get("auc_flag", 0.98)
    print(f"group_benign_attack_clean={rep['checks'].get('group_benign_attack_clean')}  "
          f"(multi-stage attack groups (by design, ok): {rep['checks'].get('multi_stage_attack_groups')})  "
          f"(flag threshold |AUC-0.5|>={thr})")
    for stg, e in rep.get("per_stage", {}).items():
        print(f"\n-- stage {stg} (n={e['n']}) --")
        if e["presence_leak"]:
            print(f"   MODALITY-PRESENCE LEAK: {e['presence_leak']}")
        print(f"   top single-feature separators (|AUC-0.5| desc):")
        for r in e["separators"]:
            mark = "  <== SHORTCUT?" if (max(r['auc'], 1 - r['auc']) >= thr) else ""
            print(f"     {r['feature']:<24} AUC={r['auc']:.3f}  "
                  f"benign_nz={r['benign_nonzero_rate']:.2f} attack_nz={r['attack_nonzero_rate']:.2f}{mark}")
        if e["benign_never"]:
            print(f"   BENIGN-NEVER (benign always 0, attack always >0): {e['benign_never']}")
    print(f"\nVERDICT: {rep['verdict']}  ({len(rep['flags'])} flag(s))")
    if rep["verdict"] == "FLAG":
        print("   Review each flag: is it an INTENDED signal (e.g. recon->scan) or a")
        print("   CONFOUND to fix in the benign design (e.g. benign never opens SSH)?")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("fused_csv")
    ap.add_argument("--auc", type=float, default=0.98, help="flag |AUC-0.5| >= this")
    ap.add_argument("--json", default=None)
    a = ap.parse_args()
    df = pd.read_csv(a.fused_csv, dtype={"modality_mask": str})  # keep leading zeros ("010")
    rep = audit(df, auc_flag=a.auc)
    render(rep)
    if a.json:
        json.dump(rep, open(a.json, "w"), indent=2, default=str)
        print(f"\n[json] -> {a.json}")
    sys.exit(0 if rep["verdict"] in ("PASS", "N/A") else 3)


if __name__ == "__main__":
    main()
