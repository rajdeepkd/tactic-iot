#!/usr/bin/env python3
r"""Emit exact LaTeX table bodies for the v5 Data Descriptor from dataset_v5 + v5_results."""
import glob, os, pandas as pd, numpy as np
ROOT="dataset_v5"; R="v5_results"
OUT="tables"
os.makedirs(OUT, exist_ok=True)

def load(W):
    fs=glob.glob(f"{ROOT}/By_device_and_campaigns/*/*/preprocessed/windows_w{W}.csv")
    return pd.concat([pd.read_csv(f,low_memory=False) for f in fs], ignore_index=True)
d1=load(1); d5=load(5)
def th(n): return f"{n:,}".replace(",","{,}")

# ---- tab:catalogue : stage -> sublabels with W1,W5 counts ----
c1=d1.groupby(["stage","attack_type"]).size(); c5=d5.groupby(["stage","attack_type"]).size()
NORMAL="normal"
stage_order=["recon","bruteforce","bruteforce_slow","ddos","unauthorized_control","mitm",
             "lateral","exfil","persistence","privesc","execution","defense_evasion"]
stages={}
for (stg,a),n in c1.items():
    if a==NORMAL: continue
    stages.setdefault(stg,[]).append(a)
lines=[]
tot1=tot5=0
single_stage={"bruteforce_slow":"slow","mitm":"arp","lateral":"scan","persistence":"cron",
              "privesc":"suidscan","execution":"lolbin","defense_evasion":"logtamper"}
for stg in stage_order:
    subs=sorted(stages.get(stg,[]))
    s1=sum(int(c1.get((stg,a),0)) for a in subs); s5=sum(int(c5.get((stg,a),0)) for a in subs)
    tot1+=s1; tot5+=s5
    stg_disp=stg.replace("_","\\_")
    if stg in single_stage:
        lines.append(f"\\textbf{{{stg_disp}}} ({single_stage[stg]}) & \\textbf{{{th(s1)}}} & \\textbf{{{th(s5)}}} \\\\")
    else:
        lines.append(f"\\textbf{{{stg_disp}}} & \\textbf{{{th(s1)}}} & \\textbf{{{th(s5)}}} \\\\")
        for a in subs:
            short=a.split("_",1)[1] if "_" in a and a.split("_",1)[0] in (stg,"recon","ddos","bruteforce","control","exfil") else a
            short=short.replace("_","\\_")
            lines.append(f"\\quad {short} & {th(int(c1.get((stg,a),0)))} & {th(int(c5.get((stg,a),0)))} \\\\")
    lines.append("\\midrule")
ben1=int((d1.attack_type==NORMAL).sum()); ben5=int((d5.attack_type==NORMAL).sum())
lines.append(f"\\textbf{{All attack classes}} & \\textbf{{{th(tot1)}}} & \\textbf{{{th(tot5)}}} \\\\")
lines.append(f"Benign & {th(ben1)} & {th(ben5)} \\\\")
with open(f"{OUT}/tab_catalogue.tex","w") as f: f.write("\n".join(lines)+"\n")
print("wrote tab_catalogue.tex; attack tot W1",tot1,"W5",tot5,"benign",ben1,ben5)

# ---- tab:detect : per-sublabel AP per modality, dom, fused, gain (W1), sorted by gain desc ----
det=pd.read_csv(f"{R}/v5_detection.csv")
d=det[(det.level=="sublabel")&(det.W==1)&(det["class"]!="normal")].copy().sort_values("fusion_gain",ascending=False)
rows=[]
for _,r in d.iterrows():
    g=float(r["fusion_gain"])
    gs=f"$+{g:.3f}$" if g>=0 else f"$-{abs(g):.3f}$"
    cls=str(r["class"]).replace("_","\\_")
    dom=r["dominant"]
    rows.append(f"{cls} & {r.ap_net:.3f} & {r.ap_host:.3f} & {r.ap_tel:.3f} & {r.ap_applog:.3f} & {dom} & {r.ap_fused:.3f} & {gs} \\\\")
with open(f"{OUT}/tab_detect.tex","w") as f: f.write("\n".join(rows)+"\n")
print("wrote tab_detect.tex; rows",len(rows),"mean fused",round(d.ap_fused.mean(),3),"mean best",round(d.best_single.mean(),3))
