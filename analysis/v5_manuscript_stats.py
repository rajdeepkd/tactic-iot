#!/usr/bin/env python3
r"""Compute every descriptive statistic + data-quality audit the v5 Data Descriptor
tables need, straight from dataset_v5 nodes. Read-only."""
import glob, os, numpy as np, pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import f1_score, roc_auc_score

ROOT="dataset_v5"
def load(W):
    fs=glob.glob(f"{ROOT}/By_device_and_campaigns/*/*/preprocessed/windows_w{W}.csv")
    return pd.concat([pd.read_csv(f,dtype={"modality_mask":str},low_memory=False) for f in fs], ignore_index=True)

d1=load(1); d5=load(5); d8=load(8); d10=load(10)
NORMAL="normal"
# ---- stage/sublabel mapping from attack_type + stage columns ----
print("=== COUNTS per stage/sublabel (W1 | W5) ===")
def counts(df): return df.groupby(["stage","attack_type"]).size()
c1=counts(d1); c5=counts(d5)
stages=d1[d1.attack_type!=NORMAL].groupby("stage")["attack_type"].apply(lambda s: sorted(s.unique()))
for stg in sorted(stages.index):
    subs=stages[stg]
    s1=sum(int(c1.get((stg,a),0)) for a in subs); s5=sum(int(c5.get((stg,a),0)) for a in subs)
    print(f"STAGE {stg:22} tot W1={s1:6} W5={s5:5}")
    for a in subs:
        print(f"   {a:26} W1={int(c1.get((stg,a),0)):6} W5={int(c5.get((stg,a),0)):5}")
print("\n=== TOTALS ===")
for nm,df in [("W1",d1),("W5",d5),("W8",d8),("W10",d10)]:
    atk=(df.attack_type!=NORMAL).sum(); ben=(df.attack_type==NORMAL).sum()
    print(f"{nm}: total={len(df)} attack={atk} benign={ben}")

# ---- modality mask: all-four + distinct ----
mask=d1["modality_mask"].astype(str)
# mask bits: determine width; 'all active' = all chars '1'
def allfour(m):
    m=str(m)
    return len(m)>=4 and set(m)=={"1"}
print(f"\nmodality_mask distinct (W1): {mask.nunique()} ; sample {mask.value_counts().head(6).to_dict()}")
af=mask.apply(allfour).sum()
# also compute via per-modality cnt>0
for col in ["net__cnt","host__cnt","tel__cnt","applog__cnt"]:
    pass
cnts=[c for c in ["net__cnt","host__cnt","tel__cnt","applog__cnt"] if c in d1.columns]
present=(d1[cnts].apply(pd.to_numeric,errors="coerce").fillna(0)>0)
all4=int((present.all(axis=1)).sum())
print(f"all-four-modality windows (W1): mask-based={af} cnt-based={all4}")

# ---- actions (attack action slices) from labels ----
labs=glob.glob(f"dataset/v5_work/*/labels.csv")  # likely gone; try nodes/manifest
# fallback: count distinct (group_id, attack_type) attack segments in W1
grp=[c for c in ["group_id"] if c in d1.columns]
if grp:
    seg=d1[d1.attack_type!=NORMAL].groupby(["group_id","attack_type"]).ngroups
    print(f"attack action-segments (distinct group_id x attack_type, W1): {seg}")

# ---- data-quality audit (W1) ----
print("\n=== QUALITY AUDIT (W1) ===")
feat=[c for c in d1.columns if c.startswith(("net__","host__","tel__","applog__"))]
X=d1[feat].apply(pd.to_numeric,errors="coerce").fillna(0)
# all-zero windows
allzero=int((X.sum(axis=1)==0).sum())
print(f"all-zero (empty) windows: {allzero}")
# zero-variance columns
zv=int((X.nunique()<=1).sum())
print(f"zero-variance feature cols: {zv} of {len(feat)}")
# exact duplicate feature rows
dup=int(X.duplicated().sum()); print(f"exact duplicate feature rows: {dup} ({100*dup/len(X):.1f}%)")
# windows per attack class min/median
vc=d1[d1.attack_type!=NORMAL].attack_type.value_counts()
print(f"windows per attack class: min={vc.min()} median={int(vc.median())}")
# highest single-feature one-vs-rest AUC across sublabels
y=d1.attack_type.values
best_auc=0; best=None; ge999=0
rng=np.random.default_rng(0)
# subsample for speed
idx=rng.choice(len(d1), size=min(40000,len(d1)), replace=False)
Xs=X.iloc[idx].values; ys=y[idx]
for cls in [c for c in np.unique(ys) if c!=NORMAL]:
    yb=(ys==cls).astype(int)
    if yb.sum()<10: continue
    cmax=0
    for j in range(Xs.shape[1]):
        col=Xs[:,j]
        if np.ptp(col)==0: continue
        try: a=roc_auc_score(yb,col)
        except Exception: continue
        a=max(a,1-a); cmax=max(cmax,a)
    if cmax>=0.999: ge999+=1
    if cmax>best_auc: best_auc=cmax; best=cls
print(f"highest single-feature 1vR AUC: {best_auc:.3f} ({best}); classes with AUC>=0.999: {ge999}")

# ---- dedup effect on fused macro-F1 (grouped split, quick RF) ----
print("\n=== DEDUP macro-F1 (W1, grouped split) ===")
gid=d1["group_id"].astype(str)
runidx=pd.to_numeric(gid.str.extract(r"#(\d+)$")[0],errors="coerce").fillna(0).astype(int)
# representative grouped split: test = every 3rd group
groups=gid.values
uniq=pd.unique(groups); gmap={g:i for i,g in enumerate(uniq)}
gi=np.array([gmap[g] for g in groups])
test_mask=(gi%3==2)
def macro(trmask,temask,Xf,yf):
    rf=RandomForestClassifier(n_estimators=120,class_weight="balanced",n_jobs=-1,random_state=0)
    rf.fit(Xf[trmask],yf[trmask]); p=rf.predict(Xf[temask])
    return f1_score(yf[temask],p,average="macro")
Xv=X.values; yv=y
f_full=macro(~test_mask,test_mask,Xv,yv)
# dedup: drop exact duplicate feature rows (keep first)
keep=~X.duplicated().values
f_dd=macro((~test_mask)&keep,test_mask&keep,Xv,yv)
print(f"fused macro-F1 full={f_full:.3f} dedup={f_dd:.3f}")

# ---- presence per modality per class (for compose + presence fig) ----
print("\n=== MODALITY PRESENCE (median per-class, fraction of windows with cnt>0) ===")
for mod,c in [("net","net__cnt"),("host","host__cnt"),("tel","tel__cnt"),("applog","applog__cnt")]:
    if c not in d1.columns: continue
    pr=d1.groupby("attack_type").apply(lambda g:(pd.to_numeric(g[c],errors="coerce").fillna(0)>0).mean())
    print(f"  {mod}: median across classes={pr.median():.3f}")
