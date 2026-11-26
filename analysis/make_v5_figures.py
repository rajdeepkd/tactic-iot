#!/usr/bin/env python3
r"""make_v5_figures.py -- generate camera-ready PGFPlots .tex sources for the V5
data-descriptor technical-validation figures, straight from experiments/v5_results/*.csv.
Target venue: Scientific Data (Springer Nature). Muted, grayscale-safe palette; legends
outside; CIs where available. No explicit LaTeX font-size commands.
Each figure is a standalone document -> compile with pdflatex to get source + PDF.
"""
import os, pandas as pd, numpy as np

R   = "v5_results"
OUT = "v5_figures"
TEX = os.path.join(OUT, "tex")
os.makedirs(TEX, exist_ok=True)

# ---- consistent muted palette (RGB 0-255), grayscale-separable ----
PAL = {
    "net":    (31, 59, 111),    # navy
    "host":   (200, 96, 30),    # dark orange
    "tel":    (42, 157, 143),   # teal
    "applog": (108, 122, 137),  # slate gray
    "c1": (31, 59, 111),   # navy
    "c2": (70, 130, 180),  # steel blue
    "c3": (42, 157, 143),  # teal
    "c4": (34, 139, 34),   # forest green
    "c5": (200, 96, 30),   # dark orange
    "c6": (150, 40, 40),   # muted red
}
def colordefs():
    return "\n".join(f"\\definecolor{{{k}}}{{RGB}}{{{r},{g},{b}}}" for k,(r,g,b) in PAL.items())

PRE = r"""\documentclass[border=3pt]{standalone}
\usepackage{pgfplots}
\usepackage{amsmath}
\pgfplotsset{compat=1.18}
\usepgfplotslibrary{groupplots}
\usetikzlibrary{patterns}
%COLORS%
\pgfplotsset{
  every axis/.append style={
    line width=0.6pt, tick align=outside, tick style={black, line width=0.5pt},
    grid=major, grid style={gray!25, line width=0.3pt},
    label style={black}, tick label style={black},
    legend cell align=left,
  },
}
\begin{document}
"""
def doc(body):
    return PRE.replace("%COLORS%", colordefs()) + body + "\n\\end{document}\n"

def write(name, body):
    p = os.path.join(TEX, name + ".tex")
    with open(p, "w") as f: f.write(doc(body))
    print("wrote", p)

# =====================================================================
# FIG 1 -- window-size effect x model : multiclass fused macro-F1 vs W
# =====================================================================
mg = pd.read_csv(f"{R}/v5_modelgrid_multiclass.csv")
models = ["RandomForest","GradientBoosting","MLP","LSTM","GRU"]
mcolor = {"RandomForest":"c1","GradientBoosting":"c5","MLP":"c3","LSTM":"c2","GRU":"c6"}
mmark  = {"RandomForest":"*","GradientBoosting":"square*","MLP":"triangle*","LSTM":"diamond*","GRU":"pentagon*"}
coords = {m: mg[mg.model==m].sort_values("W")[["W","fused_macroF1"]].values for m in models}
plots=[]
for m in models:
    pts=" ".join(f"({int(w)},{v:.4f})" for w,v in coords[m])
    plots.append(f"\\addplot[color={mcolor[m]}, mark={mmark[m]}, mark size=2.2pt, line width=0.9pt] coordinates {{{pts}}};\n\\addlegendentry{{{m}}}")
body = r"""\begin{tikzpicture}
\begin{axis}[
  width=9.2cm, height=6.4cm,
  xlabel={Window size $w$ (s)}, ylabel={Multiclass macro-F1 (fused)},
  xtick={1,5,8,10}, xmin=0.3, xmax=10.7, ymin=0.5, ymax=0.97,
  legend style={at={(1.02,1.0)}, anchor=north west, draw=gray!50},
  legend columns=1,
]
""" + "\n".join(plots) + r"""
\end{axis}
\end{tikzpicture}"""
write("fig_window_models", body)

# =====================================================================
# FIG 2 -- mutual information (sum) by modality across window sizes
# =====================================================================
mi = pd.read_csv(f"{R}/v5_mutual_info_agg.csv").sort_values("W")
Ws = [int(w) for w in mi.W]
bars=[]
for mod,col in [("net","net"),("host","host"),("tel","tel"),("applog","applog")]:
    pts=" ".join(f"({w},{v:.3f})" for w,v in zip(Ws, mi[f"mi_sum_{mod}"]))
    lbl={"net":"Network","host":"Host","tel":"Telemetry","applog":"Application"}[mod]
    bars.append(f"\\addplot[fill={col}, draw=black!55, line width=0.4pt] coordinates {{{pts}}};\n\\addlegendentry{{{lbl}}}")
body = r"""\begin{tikzpicture}
\begin{axis}[
  width=9.2cm, height=6.4cm, ybar=1.1pt, bar width=5.2pt,
  xlabel={Window size $w$ (s)}, ylabel={Mutual information with class (bits, $\sum$ features)},
  symbolic x coords={1,5,8,10}, xtick=data, ymin=0,
  legend style={at={(1.02,1.0)}, anchor=north west, draw=gray!50}, legend columns=1,
  enlarge x limits=0.18,
]
""" + "\n".join(bars) + r"""
\end{axis}
\end{tikzpicture}"""
write("fig_mi_modality", body)

# =====================================================================
# FIG 3 -- modality ablation : single vs LOO vs all (macro-F1)
# =====================================================================
ab = pd.read_csv(f"{R}/v5_ablation.csv")
allval = float(ab[ab.kind=="full"].macro_f1.iloc[0])
sing = {c:float(v) for c,v in zip(ab[ab.kind=="single"].config, ab[ab.kind=="single"].macro_f1)}
loo  = {c.replace("all-minus-",""):float(v) for c,v in zip(ab[ab.kind=="loo"].config, ab[ab.kind=="loo"].macro_f1)}
# order modalities by single-modality strength (desc), plot top->bottom
mods = sorted(sing, key=lambda k:-sing[k])
pname = {"net":"Network","host":"Host","tel":"Telemetry","applog":"Application"}
ylabels = [pname[m] for m in mods]
single_pts = " ".join(f"({sing[m]:.4f},{i})" for i,m in enumerate(mods))
loo_pts    = " ".join(f"({loo[m]:.4f},{i})" for i,m in enumerate(mods))
yt="{" + ",".join(str(i) for i in range(len(mods))) + "}"
ytl="{" + ",".join(ylabels) + "}"
body = r"""\begin{tikzpicture}
\begin{axis}[
  width=10.4cm, height=6.0cm, xbar=1.2pt, bar width=7pt,
  xlabel={Multiclass macro-F1 (W1)}, xmin=0, xmax=1.0,
  ytick=""" + yt + r""", yticklabels=""" + ytl + r""",
  y dir=reverse, y=0.95cm, enlarge y limits=0.16,
  legend style={at={(1.02,1.0)}, anchor=north west, draw=gray!50}, legend columns=1,
]
\addplot[fill=c1, draw=black!55, line width=0.4pt] coordinates {""" + single_pts + r"""};
\addlegendentry{modality alone}
\addplot[fill=c3, draw=black!55, line width=0.4pt] coordinates {""" + loo_pts + r"""};
\addlegendentry{leave-one-out (others)}
\draw[c6, line width=1.1pt, densely dashed] (axis cs:""" + f"{allval:.4f}" + r""",-0.6) -- (axis cs:""" + f"{allval:.4f}" + r""",""" + str(len(mods)-0.4) + r""");
\node[c6, anchor=west] at (axis cs:""" + f"{allval+0.012:.4f}" + r""",""" + str(len(mods)-1) + r""") {fused = """ + f"{allval:.3f}" + r"""};
\end{axis}
\end{tikzpicture}"""
write("fig_ablation", body)

# =====================================================================
# FIG 4 -- binary vs multiclass model grid at a representative window (W10)
# =====================================================================
Wrep=10
bg = pd.read_csv(f"{R}/v5_modelgrid_binary.csv"); bg=bg[bg.W==Wrep]
mc = mg[mg.W==Wrep]
rows=[]
for m in models:
    roc=float(bg[bg.model==m].roc_auc.iloc[0]); f1=float(bg[bg.model==m].f1.iloc[0])
    mcf=float(mc[mc.model==m].fused_macroF1.iloc[0])
    rows.append((m,roc,f1,mcf))
def bar(series, col, lbl):
    pts=" ".join(f"({m},{v:.4f})" for m,_,_,_ in rows for s,v in [(None,series(m))])
    return None
xcoords="{" + ",".join(m for m,_,_,_ in rows) + "}"
def addp(idx,col,lbl):
    pts=" ".join(f"({r[0]},{r[idx]:.4f})" for r in rows)
    return f"\\addplot[fill={col}, draw=black!55, line width=0.4pt] coordinates {{{pts}}};\n\\addlegendentry{{{lbl}}}"
body = r"""\begin{tikzpicture}
\begin{axis}[
  width=9.6cm, height=6.2cm, ybar=1.2pt, bar width=6pt,
  ylabel={Score}, symbolic x coords=""" + xcoords + r""", xtick=data,
  x tick label style={rotate=20, anchor=east}, ymin=0.5, ymax=1.03,
  legend style={at={(1.02,1.0)}, anchor=north west, draw=gray!50}, legend columns=1,
  enlarge x limits=0.14,
]
""" + addp(1,"c1","Binary ROC-AUC") + "\n" + addp(2,"c3","Binary F1") + "\n" + addp(3,"c5","Multiclass macro-F1") + r"""
\end{axis}
\end{tikzpicture}"""
write("fig_modelgrid", body)

# =====================================================================
# FIG 5 -- class overlap (unsupervised KMeans) vs window size
# =====================================================================
ov = pd.read_csv(f"{R}/v5_overlap.csv").sort_values("W")
Ws=[int(w) for w in ov.W]
series=[("ari","ARI","c1","*"),("nmi","NMI","c2","square*"),
        ("v_measure","V-measure","c3","triangle*"),("silhouette","Silhouette","c5","diamond*")]
plots=[]
for key,lbl,col,mk in series:
    pts=" ".join(f"({w},{v:.4f})" for w,v in zip(Ws, ov[key]))
    plots.append(f"\\addplot[color={col}, mark={mk}, mark size=2.2pt, line width=0.9pt] coordinates {{{pts}}};\n\\addlegendentry{{{lbl}}}")
body = r"""\begin{tikzpicture}
\begin{axis}[
  width=9.2cm, height=6.0cm,
  xlabel={Window size $w$ (s)}, ylabel={Clustering agreement with class labels},
  xtick={1,5,8,10}, xmin=0.3, xmax=10.7, ymin=0, ymax=0.75,
  legend style={at={(1.02,1.0)}, anchor=north west, draw=gray!50}, legend columns=1,
]
""" + "\n".join(plots) + r"""
\end{axis}
\end{tikzpicture}"""
write("fig_overlap", body)

# =====================================================================
# FIG 6 -- per-class fusion gain (sublabel, W1), sorted
# =====================================================================
det = pd.read_csv(f"{R}/v5_detection.csv")
d1 = det[(det.level=="sublabel") & (det.W==1)].copy()
d1 = d1[d1["class"]!="normal"].sort_values("fusion_gain")
cls=list(d1["class"]); gain=list(d1.fusion_gain)
coords=" ".join(f"({g:.4f},{i})" for i,g in enumerate(gain))
yt="{" + ",".join(str(i) for i in range(len(cls))) + "}"
ytl="{" + ",".join(c.replace("_","\\_") for c in cls) + "}"
# color: positive teal, negative red -> two addplots by sign
pos=" ".join(f"({g:.4f},{i})" for i,g in enumerate(gain) if g>=0)
neg=" ".join(f"({g:.4f},{i})" for i,g in enumerate(gain) if g<0)
body = r"""\begin{tikzpicture}
\begin{axis}[
  width=9.0cm, height=12.5cm, xbar, bar width=5pt,
  xlabel={Fusion gain $\Delta$macro-F1 (fused $-$ best single modality), W1},
  xmin=-0.1, xmax=0.45,
  ytick=""" + yt + r""", yticklabels=""" + ytl + r""",
  y=0.40cm, enlarge y limits=0.03,
  x tick label style={/pgf/number format/fixed},
]
\draw[gray!55, line width=0.5pt] ({axis cs:0,-0.6}) -- ({axis cs:0,""" + str(len(cls)-0.4) + r"""});
\addplot[fill=c3, draw=black!55, line width=0.3pt] coordinates {""" + pos + r"""};
\addplot[fill=c6, draw=black!55, line width=0.3pt] coordinates {""" + (neg if neg else "(0,-5)") + r"""};
\end{axis}
\end{tikzpicture}"""
write("fig_fusion_gain", body)

# =====================================================================
# FIG 7 -- confusion matrix heatmap (multiclass RF, W1), row-normalized
# =====================================================================
cm = pd.read_csv(f"{R}/v5_confusion.csv", index_col=0)
labels=list(cm.columns)
M=cm.values.astype(float)
rs=M.sum(axis=1, keepdims=True); rs[rs==0]=1
Mn=M/rs
n=len(labels)
# build matrix-plot table: x y C
tab=[]
for i in range(n):
    for j in range(n):
        tab.append(f"{j} {i} {Mn[i,j]:.4f}")
tabstr="\n".join(tab)
labesc=[l.replace("_","\\_") for l in labels]
xtl="{" + ",".join(labesc) + "}"
ytl="{" + ",".join(labesc) + "}"
ticks="{" + ",".join(str(i) for i in range(n)) + "}"
body = r"""\begin{tikzpicture}
\begin{axis}[
  width=13.5cm, height=13.5cm,
  enlargelimits=false, axis on top,
  xlabel={Predicted class}, ylabel={True class},
  xtick=""" + ticks + r""", xticklabels=""" + xtl + r""",
  ytick=""" + ticks + r""", yticklabels=""" + ytl + r""",
  x tick label style={rotate=90, anchor=east}, y dir=reverse,
  colorbar, colormap/viridis, point meta min=0, point meta max=1,
  colorbar style={ylabel={Row-normalized fraction}},
  grid=none,
]
\addplot[matrix plot*, point meta=explicit, mesh/cols=""" + str(n) + r""", mesh/rows=""" + str(n) + r"""]
  table[meta=C] {
x y C
""" + tabstr + r"""
};
\end{axis}
\end{tikzpicture}"""
write("fig_confusion", body)

# =====================================================================
# FIG 8 -- per-class modality presence heatmap (29 classes x 4 modalities)
# =====================================================================
pr = pd.read_csv(f"{R}/v5_presence.csv").sort_values("class")
cls=list(pr["class"]); mods=["net","host","tel","applog"]
mlab=["Network","Host","Telemetry","Application"]
n=len(cls)
tab=[]
for i,row in enumerate(pr.itertuples(index=False)):
    vals=[row.pres_net,row.pres_host,row.pres_tel,row.pres_applog]
    for j,v in enumerate(vals):
        tab.append(f"{j} {i} {v:.4f}")
tabstr="\n".join(tab)
clsesc=[c.replace("_","\\_") for c in cls]
body = r"""\begin{tikzpicture}
\begin{axis}[
  width=7.0cm, height=13.5cm,
  enlargelimits=false, axis on top,
  xlabel={Modality},
  xtick={0,1,2,3}, xticklabels={""" + ",".join(mlab) + r"""},
  x tick label style={rotate=35, anchor=east},
  ytick={""" + ",".join(str(i) for i in range(n)) + r"""}, yticklabels={""" + ",".join(clsesc) + r"""},
  y dir=reverse,
  colorbar, colormap/viridis, point meta min=0, point meta max=1,
  colorbar style={ylabel={Fraction of windows with modality active}},
  grid=none,
]
\addplot[matrix plot*, point meta=explicit, mesh/cols=4, mesh/rows=""" + str(n) + r"""]
  table[meta=C] {
x y C
""" + tabstr + r"""
};
\end{axis}
\end{tikzpicture}"""
write("fig_presence", body)

print("\nAll figure .tex sources written to", TEX)
