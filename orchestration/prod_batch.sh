#!/bin/bash
# prod_batch.sh <start_run> <n>  -- run n PROD campaign runs (alternating victims:
# even=rpi3b1, odd=rpi3b2), appending to ~/campaigns/PROD/labels.csv on the hub +
# dataset/prod_manifest.txt. Persistent (project dir) so it survives sessions.
DS=/d/Experiment/Objective_3/testbed/dataset; mkdir -p "$DS"
K="$HOME/.ssh/obj3_testbed"; RC=/d/Experiment/Objective_3/testbed/orchestrator/run_campaign.py
# SCENARIO ISOLATION: set SCEN + MANIFEST to keep a collection apart from v1.
# Defaults reproduce v1 PROD. The v2 re-collection uses SCEN=PRODV2 + a v2 manifest.
SCEN="${SCEN:-PROD}"; MANIFEST="${MANIFEST:-$DS/prod_manifest.txt}"
# CATALOGUE: v2 collection MUST use campaigns_v2.yaml (IoT protocols + unauthorized_control).
# run_campaign.py defaults to the v1 campaigns.yaml, so this is passed explicitly.
CAT="${CAT:-/d/Experiment/Objective_3/testbed/orchestrator/campaigns_v2.yaml}"
S=$1; N=$2; STAGES="${3:-all}"   # optional 3rd arg: restrict to specific stage(s) for targeted fill
# optional 4th arg: comma list of run indices collected SINGLE-SHOT (B3). Every run
# is stage-order shuffled (C2); the recorded order seed defaults to the run index,
# which prod_harvest.sh replays to build_dual_layout, so the stored order is faithful.
SSLIST=",${4:-},"
for ((r=S; r<S+N; r++)); do
  if (( r % 2 == 0 )); then PRI=192.168.0.32; VN=rpi3b1; SEC=192.168.0.33
  else PRI=192.168.0.33; VN=rpi3b2; SEC=192.168.0.32; fi
  FLAGS="--shuffle-stages"; MODE=looped
  case "$SSLIST" in *",$r,"*) FLAGS="$FLAGS --single-shot"; MODE=single ;; esac
  ST=$(ssh -i "$K" -o BatchMode=yes pi@$PRI 'date +%s')
  python "$RC" --scenario "$SCEN" --run-idx "$r" --victim-ip "$PRI" --vname "$VN" --victim2-ip "$SEC" --catalogue "$CAT" --stages "$STAGES" --timeout 5400 $FLAGS > "$DS/${SCEN}_run$r.log" 2>&1
  EN=$(ssh -i "$K" -o BatchMode=yes pi@$PRI 'date +%s')
  echo "$r $VN $PRI $SEC $ST $EN $MODE" >> "$MANIFEST"
  echo "RUN $r DONE ($VN $MODE $((EN-ST))s)"
done
echo "BATCH_DONE ($S..$((S+N-1)))"
