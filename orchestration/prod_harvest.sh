#!/bin/bash
# prod_harvest.sh <r0> <r1>  -- harvest+align runs r0..r1 -> dataset/pN_win.csv +
# the dataset_v2 dual store (persistent). Per-run windows come from the manifest.
# SCENARIO ISOLATION: set SCEN + MANIFEST in the environment to keep a collection
# apart from v1. Defaults reproduce the v1 PROD behaviour.
#   SCEN=PRODV2 MANIFEST=.../dataset/prodv2_manifest.txt bash prod_harvest.sh 0 5
DS=/d/Experiment/Objective_3/testbed/dataset; W=$DS/_work; mkdir -p "$W"
DV=/d/Experiment/Objective_3/testbed/dataset_v2   # dual-store root (device+label views)
SCEN="${SCEN:-PROD}"; MANIFEST="${MANIFEST:-$DS/prod_manifest.txt}"
K="$HOME/.ssh/obj3_testbed"; HARV=/d/Experiment/Objective_3/testbed/pipeline/harvest.sh; ALIGN=/d/Experiment/Objective_3/testbed/pipeline/align_windows.py
DUAL=/d/Experiment/Objective_3/testbed/pipeline/build_dual_layout.py
LAB="$DS/${SCEN}_labels.csv"
RPT="$DS/${SCEN}_ip_filter_report.txt"   # per-run outlier (non-testbed-IP) packet counts
[ -f "$RPT" ] || echo "# IP-scope filter: non-testbed-IP packets dropped per run (keep = {.32,.33,.50,.137} + ARP)" > "$RPT"
ssh -i "$K" -o BatchMode=yes cnc@192.168.0.50 "cat ~/campaigns/$SCEN/labels.csv" > "$LAB" 2>/dev/null
[ -s "$LAB" ] || { echo "WARN: no labels pulled for scenario $SCEN (hub ~/campaigns/$SCEN/labels.csv empty)"; }
for ((r=$1; r<=$2; r++)); do
  read _ VN _ _ START END MODE < <(grep "^$r " "$MANIFEST")
  [ -z "$VN" ] && { echo "run $r missing in manifest"; continue; }
  SSF=""; [ "$MODE" = single ] && SSF="--single-shot"   # B3: record run as single-shot
  PRI=$([ "$VN" = rpi3b1 ] && echo 192.168.0.32 || echo 192.168.0.33)
  rm -rf "$W/p$r"
  HOUT=$(bash "$HARV" pi@$PRI $VN cnc@192.168.0.50 "$START" "$END" p$r "$W" 2>&1)
  echo "$HOUT" | grep -E "arp rows" | sed "s/^/  run$r /"
  echo "$HOUT" | grep -E "IPFILTER" | sed "s/^IPFILTER/run$r/;s/^  IPFILTER/run$r/" >> "$RPT"
  echo "$HOUT" | grep -E "IPFILTER" | sed "s/^/  run$r /"
  cp "$LAB" "$W/p$r/labels.csv"
  # align at BOTH window sizes (W=1 stage-onset view, W=5 lower-FPR view) so the
  # dual store carries windows_w1 + windows_w5 per the v2 collection plan.
  python "$ALIGN" --captures "$W/p$r" --labels "$W/p$r/labels.csv" --out "$W/p${r}_al" --window-s 1,5 2>&1 | grep -o "[0-9]* windows" | sed "s/^/  run$r /"
  python - "$W/p${r}_al/fused_windows_W1.csv" "$START" "$END" "$DS/p${r}_win.csv" <<PY
import pandas as pd,sys
df=pd.read_csv(sys.argv[1],dtype={"modality_mask":str}); S,E=int(sys.argv[2]),int(sys.argv[3])
df["ws"]=pd.to_datetime(df["window_start_iso"],utc=True).astype("int64")//10**9
df[(df.ws>=S)&(df.ws<=E)].drop(columns=["ws"]).to_csv(sys.argv[4],index=False)
PY
  # file this run into the PRIMARY device tree (raw + preprocessed). pcaps are
  # optional here: harvest deletes the big pcaps after Zeek, so the raw pcap arrives
  # only when a batch has archived it to dataset/raw_pcaps/<VN> (Phase D step).
  PCARG=""; [ -d "$DS/raw_pcaps/$VN" ] && PCARG="--pcaps-dir $DS/raw_pcaps/$VN"
  python "$DUAL" ingest --run-idx "$r" --device "$VN" --scenario "$SCEN" \
    --work "$W/p$r" --aligned "$W/p${r}_al" --labels "$LAB" \
    --order-seed "$r" $SSF $PCARG --root "$DV" 2>&1 | sed "s/^/  run$r /"
done
# rebuild the DERIVED label view from the whole device tree (idempotent) + manifests
python "$DUAL" relabel --root "$DV" --manifest 2>&1 | tail -2
# roll up the per-run outlier counts into a single scenario total
awk '/^run[0-9]/{for(i=1;i<=NF;i++){if($i~/^total=/)t+=substr($i,7);if($i~/^kept=/)k+=substr($i,6);if($i~/^outliers=/)o+=substr($i,10)}} END{printf "# TOTALS: packets=%d kept=%d outliers_dropped=%d\n",t,k,o}' "$RPT" | tee -a "$RPT"
echo "HARVEST_DONE $1..$2 ; dual store -> $DV ; ip-filter report -> $RPT"
