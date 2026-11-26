#!/bin/bash
# v5_add_pcaps.sh -- add real .pcap files to the F: dataset_v5, SECTIONED + CHECKPOINTED + size-verified.
#   Pull whole-run pcaps hub -> By_device/<dev>/run<NN>_V5/raw/network/ ; verify size ; checkpoint.
#   Only when ALL 32 are present+verified (and SLICE=1) does it relabel -> By_labels per-action slices.
# Usage: SEC_LO=0 SEC_HI=7 bash v5_add_pcaps.sh      # pull runs 0..7 (one section)
#        SLICE=1 bash v5_add_pcaps.sh                 # verify all 32 then slice into By_labels
# Re-run any section safely: checkpointed + size-verified files are skipped; a dropped file is re-pulled.
set -u
TB=/d/Experiment/Objective_3/testbed
PY=/c/Python313/python
DUAL=$TB/pipeline/build_dual_layout.py
K=$HOME/.ssh/obj3_testbed; HUB=cnc@192.168.0.50
SCEN=${SCEN:-V5}
MAN=$TB/dataset/v5_manifest.txt
DV=${DV:-/f/Experiment/Objective_3/testbed/dataset_v5}
CKPT=$TB/dataset/v5_pcap_checkpoint.txt
SSH="ssh -n -i $K -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=15"
SCP="scp -i $K -o BatchMode=yes -o ConnectTimeout=20 -o ServerAliveInterval=15"
SEC_LO=${SEC_LO:-0}; SEC_HI=${SEC_HI:-31}; SLICE=${SLICE:-0}
touch "$CKPT"

# --- guard: target drive mounted + writable ---
DROOT=$(echo "$DV" | sed -E 's#(/[a-z])/.*#\1#')
drive_ok(){ [ -d "$DROOT" ] && ( : > "$DROOT/.wtest" ) 2>/dev/null && rm -f "$DROOT/.wtest" 2>/dev/null; }
# wait up to ~WAIT_S seconds for the drive to come back writable (rides out transient drops)
wait_drive(){ local n=0 lim=${1:-120}; while ! drive_ok; do n=$((n+5)); [ "$n" -ge "$lim" ] && return 1; sleep 5; done; return 0; }
drive_ok || { echo "[addpcap] ABORT: drive $DROOT not mounted/writable. Reconnect + re-run."; exit 9; }
[ -d "$DV/By_device_and_campaigns" ] || { echo "[addpcap] ABORT: $DV dataset tree missing."; exit 9; }

# --- read manifest into arrays (NO stdin use inside loop) ---
mapfile -t LINES < "$MAN"
echo "[addpcap] DV=$DV ; section runs ${SEC_LO}..${SEC_HI} ; manifest=${#LINES[@]} runs ; SLICE=$SLICE"

pulled=0; vskip=0; failed=0; need=""
for line in "${LINES[@]}"; do
  set -- $line; r=$1; VN=$2
  [ -z "${VN:-}" ] && continue
  [ "$r" -lt "$SEC_LO" ] && continue
  [ "$r" -gt "$SEC_HI" ] && continue
  NN=$(printf '%02d' "$r")
  NET=$DV/By_device_and_campaigns/$VN/run${NN}_${SCEN}/raw/network
  # ride out any transient drive drop before touching the drive
  if ! wait_drive 180; then echo "[addpcap] run $r: DRIVE GONE >180s -- stop; reconnect + re-run same section"; failed=$((failed+1)); need="$need $r"; break; fi
  mkdir -p "$NET" 2>/dev/null
  hsz=$($SSH $HUB "stat -c %s ~/pcap_archive/p$r/cap_${VN}_*.pcap 2>/dev/null | head -1")
  lf="$NET/cap_${VN}_p${r}.pcap"; lsz=$(stat -c %s "$lf" 2>/dev/null || echo 0)
  if [ -n "$hsz" ] && [ "$lsz" = "$hsz" ]; then
    grep -qx "$r $VN $hsz" "$CKPT" || echo "$r $VN $hsz" >> "$CKPT"
    vskip=$((vskip+1)); continue
  fi
  # pull with up to 3 attempts, waiting for the drive between tries
  ok=0
  for attempt in 1 2 3; do
    wait_drive 180 || break
    rm -f "$NET"/cap_*.pcap 2>/dev/null
    if $SCP "$HUB:pcap_archive/p$r/cap_${VN}_*.pcap" "$NET/" 2>/dev/null; then
      lsz=$(stat -c %s "$NET"/cap_*.pcap 2>/dev/null | head -1)
      if [ -n "$hsz" ] && [ "$lsz" = "$hsz" ]; then ok=1; break; fi
      echo "[addpcap] run $r ($VN): attempt $attempt size mismatch (local=$lsz hub=$hsz), retrying"
    else
      echo "[addpcap] run $r ($VN): attempt $attempt pull failed, retrying"
    fi
    sleep 5
  done
  if [ "$ok" = 1 ]; then
    grep -qx "$r $VN $hsz" "$CKPT" || echo "$r $VN $hsz" >> "$CKPT"
    pulled=$((pulled+1)); echo "[addpcap] run $r ($VN): pulled+verified $((hsz/1048576))MB [ckpt]"
    sync 2>/dev/null
  else
    failed=$((failed+1)); need="$need $r"; echo "[addpcap] run $r ($VN): FAILED after retries (drive/net drop)"
  fi
done

have=$(find "$DV/By_device_and_campaigns" -path '*/raw/network/cap_*.pcap' 2>/dev/null | wc -l)
ck=$(sort -u "$CKPT" | grep -c .)
echo "[addpcap] section done: pulled=$pulled vskip=$vskip failed=$failed ; present=$have/32 ; checkpointed=$ck/32"
[ "$failed" -gt 0 ] && { echo "[addpcap] section INCOMPLETE. still needed:$need . Re-run this section to resume."; exit 2; }

if [ "$SLICE" != 1 ]; then echo "[addpcap] section OK (no slice). Run next section, or SLICE=1 when all 32 present."; exit 0; fi
[ "$have" -lt 32 ] && { echo "[addpcap] cannot slice: only $have/32 whole-run pcaps present. Pull remaining sections first."; exit 2; }

echo "[addpcap] all 32 present -> slicing per-action pcaps into By_labels ..."
"$PY" "$DUAL" relabel --root "$DV" --manifest > "$TB/dataset/v5_relabel_pcap.log" 2>&1 \
  && echo "[addpcap] relabel OK" || { echo "[addpcap] relabel FAILED (drop?) -- re-run with SLICE=1"; tail -15 "$TB/dataset/v5_relabel_pcap.log"; exit 3; }
nbd=$(find "$DV/By_device_and_campaigns" -path '*/raw/network/cap_*.pcap' | wc -l)
nbl=$(find "$DV/By_labels" -path '*/raw/network/*.pcap' | wc -l)
echo "[addpcap] DONE: By_device whole-run pcaps=$nbd ; By_labels slice pcaps=$nbl"
echo "V5_ADDPCAP_DONE"
