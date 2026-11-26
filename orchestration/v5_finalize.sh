#!/bin/bash
# v5_finalize.sh -- run AFTER v5_collect.sh (+ topup) reports V5_COLLECT_DONE. Turns the
# verified per-run By_device working tree into the By_labels DELIVERABLE:
#   1. pull each valid run's whole-run pcap from the hub archive -> By_device raw/network
#   2. derive W5/W8/W10 from W1 for every run (derive_windows.py)
#   3. relabel -> By_labels (pools preprocessed + slices per-action pcap/host/tel/applog)
#   4. verify_dataset.py -- dataset-level CONTENT gate (per-sublabel coverage both devices,
#      all modalities non-empty, window floor, cross-run confound guard, benign realism)
#   5. (optional) drop By_device whole-run pcaps from control (hub keeps the master copy);
#      By_device preprocessed windows are KEPT (the analysis + reproducibility need them).
# "Save only By_labels": By_labels is the deliverable; By_device is the working/analysis tree.
set -u
TB=/d/Experiment/Objective_3/testbed; PY=/c/Python313/python
DUAL=$TB/pipeline/build_dual_layout.py; DERIVE=$TB/experiments/derive_windows.py
VERDS=$TB/pipeline/verify_dataset.py
K=$HOME/.ssh/obj3_testbed; HUB=cnc@192.168.0.50
SCEN=${SCEN:-V5}
DS=$TB/dataset; MAN=${MAN:-$DS/v5_manifest.txt}
DV=${DV:-$TB/dataset_v5}
SSH="ssh -i $K -o BatchMode=yes -o ConnectTimeout=20"
SCP="scp -i $K -o BatchMode=yes"
DROP_BYDEV_PCAP=${DROP_BYDEV_PCAP:-1}

echo "[finalize] runs in manifest: $(grep -c . "$MAN")"

# --- 1. pull whole-run pcaps hub -> By_device raw/network (Pass-2) ---
pulled=0
while read -r r VN PRI SEC ST EN _rest; do
  [ -z "$VN" ] && continue
  NN=$(printf '%02d' "$r"); NET=$DV/By_device_and_campaigns/$VN/run${NN}_${SCEN}/raw/network
  mkdir -p "$NET"
  if ls "$NET"/cap_*.pcap >/dev/null 2>&1; then continue; fi
  $SCP "$HUB:pcap_archive/p$r/cap_${VN}_*.pcap" "$NET/" 2>/dev/null && pulled=$((pulled+1))
done < "$MAN"
echo "[finalize] pulled $pulled whole-run pcaps to By_device"

# --- 2. derive W5/W8/W10 from W1 for every run ---
"$PY" "$DERIVE" --root "$DV" > "$DS/v5_derive.log" 2>&1 && echo "[finalize] W5/W8/W10 derived" || echo "[finalize] derive_windows WARN (see v5_derive.log)"

# --- 3. relabel -> By_labels (slices per-action pcaps now that By_device has them) ---
"$PY" "$DUAL" relabel --root "$DV" --manifest > "$DS/v5_relabel.log" 2>&1 && echo "[finalize] relabel done" || { echo "[finalize] relabel FAILED"; tail -20 "$DS/v5_relabel.log"; exit 2; }

# --- 4. dataset-level verify (content + confound + coverage) ---
"$PY" "$VERDS" --root "$DV" --scen "$SCEN" --manifest "$MAN" | tee "$DS/v5_verify_dataset.log"
vrc=${PIPESTATUS[0]}

# --- 5. optional: drop control-side whole-run pcaps (hub keeps master) ---
if [ "$DROP_BYDEV_PCAP" = 1 ] && [ "$vrc" = 0 ]; then
  find "$DV/By_device_and_campaigns" -path '*/raw/network/cap_*.pcap' -delete 2>/dev/null
  echo "[finalize] dropped By_device whole-run pcaps from control (hub archive is the master); By_labels + By_device windows retained"
fi

echo "[finalize] By_labels sublabels: $(find "$DV/By_labels" -maxdepth 2 -mindepth 2 -type d 2>/dev/null | wc -l)"
echo "[finalize] By_labels pcap slices: $(find "$DV/By_labels" -path '*/raw/*/*.pcap' | wc -l)"
[ "$vrc" = 0 ] && echo "V5_FINALIZE_DONE: dataset VALID" || { echo "V5_FINALIZE: dataset verification FAILED (see v5_verify_dataset.log)"; exit 1; }
