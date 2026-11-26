#!/usr/bin/env python3
r"""
exp_v5_analysis.py -- the COMPLETE analysis of the final TACTIC-IoT v5 dataset.

Reads the 4-modality fused windows (net / host / telemetry / applog) produced by
align_windows / derive_windows across every V5 run (window sizes W1/W5/W8/W10), then for
the whole corpus computes, with a strict grouped-by-run split (no window from a test run is
ever seen in training):

  A. Dataset summary          -> v5_summary.csv, v5_presence.csv, v5_mask.csv           (W1)
  B. Per-sublabel + per-stage detection (one-vs-rest RF, the fixed modality-isolating
     detector): AP for each single modality, fused, dominant modality, FUSION GAIN, and
     every leave-one-modality-out ablation                         -> v5_detection.csv   (all W)
  C. Multiclass fused RF: accuracy, macro-F1, per-class P/R/F1, confusion, bootstrap CI
                                                 -> v5_multiclass.csv, v5_confusion.csv  (all W / W1)
  D. RF modality-ablation on the multiclass macro-F1 (single / leave-one-out / all)
                                                                   -> v5_ablation.csv    (W1)
  E. Window-size effect W1 vs W5 vs W8 vs W10 on fused macro-F1    -> v5_window.csv
  F. Group-bootstrap 95% CIs on the headline fused metrics         -> folded into the CSVs
  G. Mutual information of each feature with the multiclass label, aggregated per modality
                                                 -> v5_mutual_info.csv, v5_mutual_info_top.csv (all W)
  H. Class-overlap via K-means clustering (ARI / NMI / homogeneity / completeness /
     silhouette + per-class dominant-cluster purity + class x cluster matrix)
                                     -> v5_overlap.csv, v5_overlap_matrix_W{w}.csv       (all W)
  I. Multi-model grid -- RandomForest, GradientBoosting(HistGB), MLP, LSTM, GRU -- on BOTH
     the binary (attack-vs-normal) and the multiclass task, fused + best single modality +
     fusion gain, at every window size
                                 -> v5_modelgrid_multiclass.csv, v5_modelgrid_binary.csv (all W)

One-vs-rest / multiclass RF use average_precision (binary) and macro-F1 (multiclass). RF is
the fixed detector in B-E so the comparison there isolates the MODALITY, not the model; the
model grid (I) then shows the dataset is learnable by diverse model families and whether the
fusion benefit is model-dependent. Deterministic (random_state=42). LSTM/GRU classify each
window from its T-1 causal predecessors in the same capture segment (temporal context), so
they are scored on exactly the same test windows as the per-window tabular models.

SMOKE: `--smoke` subsamples windows and shrinks every model (few trees / 2 epochs) and writes
to a separate outdir, to validate the code end-to-end fast without touching the real results.
"""
import argparse, glob, os, sys, numpy as np, pandas as pd
from sklearn.ensemble import (RandomForestClassifier, HistGradientBoostingClassifier)
from sklearn.preprocessing import StandardScaler
from sklearn.feature_selection import mutual_info_classif
from sklearn.cluster import KMeans
from sklearn.metrics import (average_precision_score, f1_score, accuracy_score,
                             precision_recall_fscore_support, confusion_matrix, roc_auc_score,
                             adjusted_rand_score, normalized_mutual_info_score,
                             homogeneity_completeness_v_measure, silhouette_score)
import torch, torch.nn as nn

RS = 42
np.random.seed(RS); torch.manual_seed(RS)
HERE = os.path.dirname(os.path.abspath(__file__))
MODS = [("net", "net__"), ("host", "host__"), ("tel", "tel__"), ("applog", "applog__")]


# ----------------------------- data loading / split -----------------------------
def load(windows_glob):
    fs = []
    for p in glob.glob(windows_glob):
        try:
            d = pd.read_csv(p, dtype={"modality_mask": str})
            if len(d):
                fs.append(d)
        except Exception as e:
            print("  skip", p, e, file=sys.stderr)
    if not fs:
        raise SystemExit("no fused windows matched " + windows_glob)
    return pd.concat(fs, ignore_index=True)


def feat_groups(df):
    return {k: [c for c in df.columns if c.startswith(pref)] for k, pref in MODS}


def grouped_split(df, scen):
    """Grouped AND representative held-out test set. A whole capture group (one attack run
    'V5#r', or one benign session 'benign#dev#s') is entirely train or test (no window leaks).
    Test = every 3rd group (id % 3 == 2); because early runs are full campaigns with all
    classes, this puts every class on BOTH sides of the split."""
    gid = df["group_id"].astype(str)
    run = pd.to_numeric(gid.str.extract(rf"^{scen}#(\d+)$")[0], errors="coerce")
    benid = pd.to_numeric(gid.str.extract(r"^benign#.*#(\d+)$")[0], errors="coerce")
    df = df.assign(run=run, grp=gid)
    te_atk = run.notna() & (run.fillna(-1).astype(int) % 3 == 2)
    te_ben = benid.notna() & (benid.fillna(-1).astype(int) % 3 == 2)
    te = (te_atk | te_ben).to_numpy()
    tr = ~te
    return df, pd.Series(tr, index=df.index), pd.Series(te, index=df.index), \
        sorted(run[te_atk].dropna().astype(int).unique())


def subsample(df, maxw):
    """Stratified-by-class row subsample for smoke/fast runs; keeps group_id intact.
    Uses positional indices per class (no groupby.apply -> no pandas grouping-column warning)."""
    if not maxw or len(df) <= maxw:
        return df
    frac = maxw / len(df)
    rng = np.random.default_rng(RS)
    keep = []
    for _, pos in df.groupby("attack_type").indices.items():
        k = min(len(pos), max(1, int(round(len(pos) * frac))))
        keep.append(rng.choice(pos, size=k, replace=False))
    return df.iloc[np.sort(np.concatenate(keep))].reset_index(drop=True)


def macro(yt, yp, labels):
    return round(float(f1_score(yt, yp, average="macro",
                 labels=[l for l in labels if l != "normal"], zero_division=0)), 4)


# ----------------------------- torch models (MLP / RNN) -----------------------------
def class_weight(yidx, k):
    cnt = np.bincount(yidx, minlength=k).astype(float)
    return torch.tensor(cnt.sum() / (k * np.maximum(cnt, 1)), dtype=torch.float32)


class MLP(nn.Module):
    def __init__(self, d, k):
        super().__init__()
        self.n = nn.Sequential(nn.Linear(d, 256), nn.ReLU(), nn.Dropout(0.2),
                               nn.Linear(256, 128), nn.ReLU(), nn.Dropout(0.2), nn.Linear(128, k))

    def forward(self, x):
        return self.n(x)


class RNN(nn.Module):
    def __init__(self, d, k, kind="lstm", h=96):
        super().__init__()
        self.r = (nn.LSTM if kind == "lstm" else nn.GRU)(d, h, batch_first=True)
        self.f = nn.Sequential(nn.Dropout(0.2), nn.Linear(h, k))

    def forward(self, x):
        o = self.r(x)[0]
        return self.f(o[:, -1, :])


def fit_mlp_proba(Xtr, ytr_idx, Xte, k, ep=20):
    sc = StandardScaler().fit(Xtr)
    Xtr = torch.tensor(sc.transform(Xtr), dtype=torch.float32)
    Xte = torch.tensor(sc.transform(Xte), dtype=torch.float32)
    y = torch.tensor(ytr_idx, dtype=torch.long)
    net = MLP(Xtr.shape[1], k)
    opt = torch.optim.Adam(net.parameters(), 1e-3, weight_decay=1e-5)
    lf = nn.CrossEntropyLoss(weight=class_weight(ytr_idx, k))
    n = len(Xtr)
    for _ in range(ep):
        net.train(); pm = torch.randperm(n)
        for i in range(0, n, 1024):
            b = pm[i:i + 1024]; opt.zero_grad(); lf(net(Xtr[b]), y[b]).backward(); opt.step()
    net.eval()
    with torch.no_grad():
        out = [torch.softmax(net(Xte[i:i + 4096]), 1).numpy() for i in range(0, len(Xte), 4096)]
    return np.concatenate(out) if out else np.zeros((0, k))


def build_seq(df, Xs, T=8):
    """(N, T, d) causal context sequences: window i preceded by its T-1 predecessors within
    the same capture group, ordered by window_idx, edge-padded at segment start."""
    run = df["group_id"].astype(str).values
    order = np.argsort(df["window_idx"].values, kind="stable")
    seq = np.zeros((len(df), T, Xs.shape[1]), dtype=np.float32)
    for g in pd.unique(run):
        gi = order[run[order] == g]
        for pos, i in enumerate(gi):
            idx = gi[max(0, pos - T + 1):pos + 1]
            seq[i, T - len(idx):, :] = Xs[idx]
    return seq


def fit_rnn_proba(seq_tr, ytr_idx, seq_te, k, kind, ep=12):
    y = torch.tensor(ytr_idx, dtype=torch.long)
    net = RNN(seq_tr.shape[2], k, kind)
    opt = torch.optim.Adam(net.parameters(), 1e-3, weight_decay=1e-5)
    lf = nn.CrossEntropyLoss(weight=class_weight(ytr_idx, k))
    Xtr = torch.tensor(seq_tr, dtype=torch.float32); n = len(Xtr)
    for _ in range(ep):
        net.train(); pm = torch.randperm(n)
        for i in range(0, n, 512):
            b = pm[i:i + 512]; opt.zero_grad(); lf(net(Xtr[b]), y[b]).backward(); opt.step()
    net.eval(); Xte = torch.tensor(seq_te, dtype=torch.float32)
    with torch.no_grad():
        out = [torch.softmax(net(Xte[i:i + 1024]), 1).numpy() for i in range(0, len(Xte), 1024)]
    return np.concatenate(out) if out else np.zeros((0, k))


# ----------------------------- main -----------------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--work", default="./dataset_v5",
                    help="dataset_v5 root; reads By_device_and_campaigns/*/*/preprocessed/windows_wN.csv")
    ap.add_argument("--scen", default="V5")
    ap.add_argument("--outdir", default=os.path.join(HERE, "v5_results"))
    ap.add_argument("--windows", default="1,5,8,10")
    ap.add_argument("--trees", type=int, default=200)
    ap.add_argument("--boot", type=int, default=300, help="group-bootstrap resamples for CIs")
    ap.add_argument("--ep-mlp", type=int, default=20)
    ap.add_argument("--ep-rnn", type=int, default=12)
    ap.add_argument("--ctx", type=int, default=8, help="RNN temporal-context length (windows)")
    ap.add_argument("--mi-cap", type=int, default=20000, help="row cap for MI / overlap (cost control)")
    ap.add_argument("--models", default="rf,gb,mlp,lstm,gru")
    ap.add_argument("--max-windows", type=int, default=0, help="subsample cap (0=all); set by --smoke")
    ap.add_argument("--smoke", action="store_true",
                    help="fast code-correctness run: subsample + tiny models + smoke outdir")
    a = ap.parse_args()

    wanted = [int(w) for w in a.windows.split(",")]
    models = [m.strip() for m in a.models.split(",") if m.strip()]
    if a.smoke:
        a.outdir = a.outdir.rstrip("/\\") + "_smoke"
        a.trees = min(a.trees, 40); a.boot = min(a.boot, 30)
        a.ep_mlp = 2; a.ep_rnn = 2
        a.max_windows = a.max_windows or 4000; a.mi_cap = min(a.mi_cap, 2000)
        print("[SMOKE] trees=%d boot=%d ep_mlp=%d ep_rnn=%d max_windows=%d mi_cap=%d"
              % (a.trees, a.boot, a.ep_mlp, a.ep_rnn, a.max_windows, a.mi_cap))
    os.makedirs(a.outdir, exist_ok=True)

    # which window sizes actually exist on disk
    WINDOWS = []
    for W in wanted:
        if glob.glob(os.path.join(a.work, "By_device_and_campaigns", "*", "*",
                                  "preprocessed", f"windows_w{W}.csv")):
            WINDOWS.append(W)
        else:
            print(f"[skip] no W{W} windows under {a.work} -- skipping this window size")
    if not WINDOWS:
        raise SystemExit("no window files found; run derive_windows / finalize first")
    print(f"[run] window sizes present: {WINDOWS} | models: {models}")

    results = {"det": [], "multiclass": [], "mgrid_mc": [], "mgrid_bin": [], "mi": [], "overlap": []}

    for W in WINDOWS:
        g = os.path.join(a.work, "By_device_and_campaigns", "*", "*", "preprocessed", f"windows_w{W}.csv")
        df = load(g)
        if a.max_windows:
            df = subsample(df, a.max_windows)
        FG = feat_groups(df)
        NET, HOST, TEL, APP = FG["net"], FG["host"], FG["tel"], FG["applog"]
        ALL = NET + HOST + TEL + APP
        df, tr, te, test_runs = grouped_split(df, a.scen)
        trv, tev = tr.values, te.values
        if trv.sum() == 0 or tev.sum() == 0:
            print(f"[skip] W{W}: empty train/test after split"); continue
        print(f"\n===== W{W}: windows={len(df)} net={len(NET)} host={len(HOST)} "
              f"tel={len(TEL)} applog={len(APP)} | train={int(trv.sum())} test={int(tev.sum())}")

        Xall = df[ALL].fillna(0)
        y = df["attack_type"].astype(str).values
        labels = sorted(set(y))
        l2i = {l: i for i, l in enumerate(labels)}
        yidx = np.array([l2i[v] for v in y])
        yte = y[tev]

        def rf_fit_predict(feats, yb):
            if not feats or yb[trv].sum() == 0 or yb[tev].sum() == 0:
                return None, float("nan")
            m = RandomForestClassifier(n_estimators=a.trees, n_jobs=-1, random_state=RS,
                                       class_weight="balanced").fit(df.loc[tr, feats].fillna(0), yb[trv])
            p = m.predict_proba(df.loc[te, feats].fillna(0))[:, list(m.classes_).index(1)]
            return p, round(average_precision_score(yb[tev], p), 4)

        # ---------- A. summary / presence / mask (W1 only) ----------
        if W == 1:
            summ, pres = [], []
            for lvl, col in (("stage", "stage"), ("sublabel", "attack_type")):
                for t, n in df[col].value_counts().items():
                    summ.append({"level": lvl, "class": t, "windows": int(n)})
            pd.DataFrame(summ).to_csv(os.path.join(a.outdir, "v5_summary.csv"), index=False)
            for t in sorted(x for x in df["attack_type"].unique() if x != "normal"):
                sub = df[df["attack_type"] == t]
                row = {"class": t, "windows": len(sub)}
                for s, cols in FG.items():
                    cc = [c for c in cols if not c.endswith("cnt")]
                    row["pres_" + s] = round(float((sub[cc].fillna(0) != 0).any(axis=1).mean()), 4) if cc else 0.0
                pres.append(row)
            pd.DataFrame(pres).to_csv(os.path.join(a.outdir, "v5_presence.csv"), index=False)
            mc = df["modality_mask"].value_counts()
            pd.DataFrame({"mask": mc.index, "windows": mc.values}).to_csv(
                os.path.join(a.outdir, "v5_mask.csv"), index=False)
            print(f"[A] summary/presence/mask written; mask top: {mc.head(5).to_dict()}")

        # ---------- B. per-class RF detection + ablations ----------
        for lvl, col in (("stage", "stage"), ("sublabel", "attack_type")):
            for t in sorted(x for x in df[col].unique() if x != "normal"):
                yb = (df[col] == t).astype(int).values
                if yb[trv].sum() == 0 or yb[tev].sum() == 0:
                    continue
                r = {"W": W, "level": lvl, "class": t, "n_test_pos": int(yb[tev].sum())}
                singles = {}
                for s, cols in FG.items():
                    _, singles[s] = rf_fit_predict(cols, yb)
                    r["ap_" + s] = singles[s]
                _, r["ap_fused"] = rf_fit_predict(ALL, yb)
                valid = [k for k in singles if not np.isnan(singles[k])]
                dom = max(valid, key=lambda k: singles[k], default="-")
                best = max((singles[k] for k in valid), default=float("nan"))
                r["dominant"] = dom
                r["best_single"] = round(best, 4) if not np.isnan(best) else float("nan")
                r["fusion_gain"] = round(r["ap_fused"] - best, 4) if not (np.isnan(r["ap_fused"]) or np.isnan(best)) else float("nan")
                if lvl == "sublabel":
                    for s, cols in FG.items():
                        rest = [c for c in ALL if c not in cols]
                        _, r["loo_" + s] = rf_fit_predict(rest, yb)
                results["det"].append(r)
            print(f"[B] W{W} {lvl}: per-class RF detection done")

        # ---------- C. multiclass fused RF + confusion + bootstrap CI ----------
        mc_model = RandomForestClassifier(n_estimators=a.trees, n_jobs=-1, random_state=RS,
                                          class_weight="balanced").fit(Xall[tr.values], y[trv])
        yp = mc_model.predict(Xall[te.values])
        labs = sorted(set(yte) | set(yp))
        P, R, F, S = precision_recall_fscore_support(yte, yp, labels=labs, zero_division=0)
        macro_rf = macro(yte, yp, labs)
        acc = round(accuracy_score(yte, yp), 4)
        test_groups = df.loc[te, "grp"].astype(str).values
        uruns = np.unique(test_groups); rng = np.random.default_rng(RS); boots = []
        for _ in range(a.boot):
            pick = rng.choice(uruns, size=len(uruns), replace=True)
            idx = np.concatenate([np.where(test_groups == u)[0] for u in pick])
            boots.append(f1_score(yte[idx], yp[idx], average="macro",
                                  labels=[l for l in labs if l != "normal"], zero_division=0))
        lo, hi = np.percentile(boots, [2.5, 97.5]) if boots else (float("nan"), float("nan"))
        print(f"[C] W{W} multiclass fused RF: acc={acc} macroF1={macro_rf} CI95=[{lo:.3f},{hi:.3f}]")
        results["multiclass"].append({"W": W, "model": "RandomForest", "accuracy": acc,
                                      "macro_f1": macro_rf, "ci_lo": round(lo, 4), "ci_hi": round(hi, 4),
                                      "n_classes": len(labs)})
        if W == 1:
            pd.DataFrame({"class": labs, "precision": np.round(P, 4), "recall": np.round(R, 4),
                          "f1": np.round(F, 4), "support": S}).to_csv(
                os.path.join(a.outdir, "v5_multiclass.csv"), index=False)
            cm = confusion_matrix(yte, yp, labels=labs)
            pd.DataFrame(cm, index=labs, columns=labs).to_csv(os.path.join(a.outdir, "v5_confusion.csv"))

        # ---------- D. RF modality ablation on multiclass macro-F1 (W1) ----------
        if W == 1:
            abl, order = [], ["net", "host", "tel", "applog"]
            for s in order:
                cols = FG[s]
                if not cols:
                    continue
                mm = RandomForestClassifier(n_estimators=a.trees, n_jobs=-1, random_state=RS,
                                            class_weight="balanced").fit(df.loc[tr, cols].fillna(0), y[trv])
                abl.append({"config": s, "kind": "single",
                            "macro_f1": macro(yte, mm.predict(df.loc[te, cols].fillna(0)), labs)})
            for s in order:
                rest = [c for c in ALL if c not in FG[s]]
                mm = RandomForestClassifier(n_estimators=a.trees, n_jobs=-1, random_state=RS,
                                            class_weight="balanced").fit(df.loc[tr, rest].fillna(0), y[trv])
                abl.append({"config": "all-minus-" + s, "kind": "loo",
                            "macro_f1": macro(yte, mm.predict(df.loc[te, rest].fillna(0)), labs)})
            abl.append({"config": "all-four", "kind": "full", "macro_f1": macro_rf})
            pd.DataFrame(abl).to_csv(os.path.join(a.outdir, "v5_ablation.csv"), index=False)
            print(f"[D] W{W} RF ablation written ({len(abl)} configs)")

        # ---------- G. mutual information of features with the multiclass label ----------
        cap = min(a.mi_cap, len(df))
        sidx = np.random.default_rng(RS).choice(len(df), cap, replace=False) if cap < len(df) else np.arange(len(df))
        Xmi = Xall.to_numpy()[sidx]
        ymi = yidx[sidx]
        mi = mutual_info_classif(Xmi, ymi, random_state=RS)
        mi_feat = pd.DataFrame({"W": W, "feature": ALL, "mi": np.round(mi, 6)})
        results["mi"].append(mi_feat)
        agg = {}
        for s, cols in FG.items():
            m = [mi[ALL.index(c)] for c in cols if c in ALL]
            agg[s] = (round(float(np.sum(m)), 6), round(float(np.mean(m)), 6) if m else 0.0, len(m))
        results.setdefault("mi_agg", []).append(
            {"W": W, **{f"mi_sum_{s}": agg[s][0] for s in agg},
             **{f"mi_mean_{s}": agg[s][1] for s in agg}})
        print(f"[G] W{W} MI: " + " ".join(f"{s}={agg[s][0]:.3f}" for s in agg))

        # ---------- H. class overlap via K-means clustering ----------
        Xcl = StandardScaler().fit_transform(Xall.to_numpy()[sidx])
        k_overlap = len([l for l in labels if l != "normal"]) + 1  # clusters ~ n classes
        km = KMeans(n_clusters=k_overlap, random_state=RS, n_init=10).fit(Xcl)
        cl = km.labels_
        ari = adjusted_rand_score(ymi, cl)
        nmi = normalized_mutual_info_score(ymi, cl)
        hom, comp, vme = homogeneity_completeness_v_measure(ymi, cl)
        try:
            sil = silhouette_score(Xcl, cl, sample_size=min(5000, len(Xcl)), random_state=RS)
        except Exception:
            sil = float("nan")
        results["overlap"].append({"W": W, "k_clusters": k_overlap, "ari": round(ari, 4),
                                   "nmi": round(nmi, 4), "homogeneity": round(hom, 4),
                                   "completeness": round(comp, 4), "v_measure": round(vme, 4),
                                   "silhouette": round(float(sil), 4)})
        # class x cluster contingency + per-class dominant-cluster purity
        ct = pd.crosstab(pd.Series([labels[i] for i in ymi], name="class"),
                         pd.Series(cl, name="cluster"))
        ct.to_csv(os.path.join(a.outdir, f"v5_overlap_matrix_W{W}.csv"))
        print(f"[H] W{W} overlap: ARI={ari:.3f} NMI={nmi:.3f} homog={hom:.3f} sil={sil:.3f}")

        # ---------- I. multi-model grid: binary + multiclass, fused + best single ----------
        yb_bin = (df["attack_type"].values != "normal").astype(int)  # 1 = attack
        bin_labels = [0, 1]
        Xnp = Xall.to_numpy(np.float32)
        Xs = StandardScaler().fit_transform(Xnp).astype(np.float32)
        seq = build_seq(df, Xs, T=a.ctx) if ({"lstm", "gru"} & set(models)) else None

        def tab_multiclass(feats, model):
            Xtr, Xtes = df.loc[tr, feats].fillna(0), df.loc[te, feats].fillna(0)
            if model == "rf":
                m = RandomForestClassifier(n_estimators=a.trees, n_jobs=-1, random_state=RS,
                                           class_weight="balanced").fit(Xtr, y[trv])
                return m.predict(Xtes)
            if model == "gb":
                m = HistGradientBoostingClassifier(max_iter=a.trees, random_state=RS,
                                                   class_weight="balanced").fit(Xtr.to_numpy(), y[trv])
                return m.predict(Xtes.to_numpy())
            if model == "mlp":
                pr = fit_mlp_proba(Xtr.to_numpy(np.float32), yidx[trv], Xtes.to_numpy(np.float32),
                                   len(labels), ep=a.ep_mlp)
                return np.array([labels[i] for i in pr.argmax(1)])
            raise ValueError(model)

        def tab_binary_proba(feats, model):
            Xtr, Xtes = df.loc[tr, feats].fillna(0), df.loc[te, feats].fillna(0)
            if model == "rf":
                m = RandomForestClassifier(n_estimators=a.trees, n_jobs=-1, random_state=RS,
                                           class_weight="balanced").fit(Xtr, yb_bin[trv])
                return m.predict_proba(Xtes)[:, list(m.classes_).index(1)]
            if model == "gb":
                m = HistGradientBoostingClassifier(max_iter=a.trees, random_state=RS,
                                                   class_weight="balanced").fit(Xtr.to_numpy(), yb_bin[trv])
                return m.predict_proba(Xtes.to_numpy())[:, list(m.classes_).index(1)]
            if model == "mlp":
                pr = fit_mlp_proba(Xtr.to_numpy(np.float32), yb_bin[trv], Xtes.to_numpy(np.float32),
                                   2, ep=a.ep_mlp)
                return pr[:, 1]
            raise ValueError(model)

        name_map = {"rf": "RandomForest", "gb": "GradientBoosting", "mlp": "MLP",
                    "lstm": "LSTM", "gru": "GRU"}
        for model in models:
            nm = name_map.get(model, model)
            # ---- multiclass ----
            if model in ("rf", "gb", "mlp"):
                yp_f = tab_multiclass(ALL, model)
                fused_mc = macro(yte, yp_f, labs)
                best_single = float("-inf"); dom = "-"
                for s, cols in FG.items():
                    if not cols:
                        continue
                    v = macro(yte, tab_multiclass(cols, model), labs)
                    if v > best_single:
                        best_single, dom = v, s
                gain = round(fused_mc - best_single, 4)
                # ---- binary ----
                pb = tab_binary_proba(ALL, model)
                roc = round(roc_auc_score(yb_bin[tev], pb), 4)
                apb = round(average_precision_score(yb_bin[tev], pb), 4)
                f1b = round(f1_score(yb_bin[tev], (pb >= 0.5).astype(int), zero_division=0), 4)
                accb = round(accuracy_score(yb_bin[tev], (pb >= 0.5).astype(int)), 4)
            else:  # lstm / gru -- sequence, fused only
                pr = fit_rnn_proba(seq[trv], yidx[trv], seq[tev], len(labels), model, ep=a.ep_rnn)
                fused_mc = macro(yte, np.array([labels[i] for i in pr.argmax(1)]), labs)
                best_single, dom, gain = float("nan"), "-", float("nan")
                prb = fit_rnn_proba(seq[trv], yb_bin[trv], seq[tev], 2, model, ep=a.ep_rnn)
                pb = prb[:, 1]
                roc = round(roc_auc_score(yb_bin[tev], pb), 4)
                apb = round(average_precision_score(yb_bin[tev], pb), 4)
                f1b = round(f1_score(yb_bin[tev], (pb >= 0.5).astype(int), zero_division=0), 4)
                accb = round(accuracy_score(yb_bin[tev], (pb >= 0.5).astype(int)), 4)
            results["mgrid_mc"].append({"W": W, "model": nm, "fused_macroF1": fused_mc,
                                        "best_single_macroF1": (round(best_single, 4) if np.isfinite(best_single) else np.nan),
                                        "dominant_modality": dom, "fusion_gain": gain})
            results["mgrid_bin"].append({"W": W, "model": nm, "roc_auc": roc, "avg_precision": apb,
                                         "f1": f1b, "accuracy": accb})
            print(f"[I] W{W} {nm:14s} mc_fused={fused_mc} gain={gain} | bin roc={roc} ap={apb} f1={f1b}")

    # ----------------------------- write all outputs -----------------------------
    od = a.outdir
    pd.DataFrame(results["det"]).to_csv(os.path.join(od, "v5_detection.csv"), index=False)
    pd.DataFrame(results["multiclass"]).to_csv(os.path.join(od, "v5_window.csv"), index=False)
    pd.concat(results["mi"], ignore_index=True).to_csv(os.path.join(od, "v5_mutual_info.csv"), index=False)
    pd.DataFrame(results["mi_agg"]).to_csv(os.path.join(od, "v5_mutual_info_agg.csv"), index=False)
    # top-20 MI features per window
    top = (pd.concat(results["mi"], ignore_index=True)
             .sort_values(["W", "mi"], ascending=[True, False]).groupby("W").head(20))
    top.to_csv(os.path.join(od, "v5_mutual_info_top.csv"), index=False)
    pd.DataFrame(results["overlap"]).to_csv(os.path.join(od, "v5_overlap.csv"), index=False)
    pd.DataFrame(results["mgrid_mc"]).to_csv(os.path.join(od, "v5_modelgrid_multiclass.csv"), index=False)
    pd.DataFrame(results["mgrid_bin"]).to_csv(os.path.join(od, "v5_modelgrid_binary.csv"), index=False)

    # headline
    det = pd.DataFrame(results["det"])
    sub1 = det[(det.level == "sublabel") & (det.W == 1)] if len(det) else det
    print("\n================ HEADLINE ================")
    if len(sub1):
        helped = sub1[sub1.fusion_gain > 0.02]; hurt = sub1[sub1.fusion_gain < -0.02]
        print(f"sublabels (W1): {len(sub1)} | fusion HELPED(>0.02): {len(helped)} | "
              f"HURT(<-0.02): {len(hurt)} | neutral: {len(sub1)-len(helped)-len(hurt)}")
        print(f"mean fusion gain (sublabel W1 RF): {sub1.fusion_gain.mean():+.4f}")
    wdf = pd.DataFrame(results["multiclass"])
    if len(wdf):
        print("window-size effect (fused RF macro-F1): " +
              " ".join(f"W{int(r.W)}={r.macro_f1}" for _, r in wdf.iterrows()))
    print(f"results -> {od}")


if __name__ == "__main__":
    main()
