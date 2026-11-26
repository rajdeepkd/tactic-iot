#!/bin/bash
# v5_topup.sh [FLOOR_WINDOWS] -- top up V5 attack classes below the per-class WINDOW floor,
# with the SAME per-run content gate as v5_collect.sh. Unlike v4_topup (which used a
# labelled-SECONDS proxy and then needed a separate window-count corrective pass), this reads
# the ACTUAL accumulated per-class WINDOW counts from dataset_v5/By_device after each built
# run, so it targets exactly the classes short on windows and stops when every class clears.
# Safeguards from v4_topup kept: exclusive lock + hard-clean of hub/victim orphan procs.
set -u
TB=/d/Experiment/Objective_3/testbed; PY=/c/Python313/python
RC=$TB/orchestrator/run_campaign.py; CAT=$TB/orchestrator/campaigns_v2.yaml
HARV=$TB/pipeline/harvest.sh; ALIGN=$TB/pipeline/align_windows.py
DUAL=$TB/pipeline/build_dual_layout.py; VER=$TB/pipeline/verify_run.py
PREFLIGHT=$TB/orchestrator/v5_preflight.sh
K=$HOME/.ssh/obj3_testbed; HUB=cnc@192.168.0.50
SCEN=${SCEN:-V5}; EXPECT_TEL=${EXPECT_TEL:-37}
DS=$TB/dataset; MAN=${MAN:-$DS/v5_manifest.txt}
W=${WORKDIR:-$DS/v5_work}; mkdir -p "$W"
DV=${DV:-$TB/dataset_v5}; RUNLOG=$DS/v5_run_details.csv
FLOOR=${1:-4000}; MULT=${TOPUP_MULT:-8}
SSH="ssh -i $K -o BatchMode=yes -o ServerAliveInterval=15 -o ConnectTimeout=15"
source "$TB/orchestrator/v3_lib.sh"
LOCK=$DS/.v5_topup.lock
if [ -f "$LOCK" ]; then old=$(cat "$LOCK" 2>/dev/null)
  if [ -n "$old" ] && kill -0 "$old" 2>/dev/null; then echo "[FATAL] another v5_topup alive (pid $old)" >&2; exit 3; fi
  echo "[lock] stale lock (pid $old dead) -- taking over"; fi
echo $$ > "$LOCK"; trap 'rm -f "$LOCK"' EXIT

hard_clean(){
  for pass in 1 2; do
    $SSH "$HUB" 'pids=$(pgrep -f "hub_campaign|run_action|hping3|hydra|mosquitto_pub|mbpoll|nmap|ettercap|onesixtyone" | grep -vE "^'"$$"'$"); [ -n "$pids" ] && sudo kill -9 $pids 2>/dev/null; true' >/dev/null 2>&1
    sleep 2
  done
  for ip in 192.168.0.32 192.168.0.33; do
    V "$ip" 'sudo pkill -9 -f _rep 2>/dev/null; sudo pkill -9 -f .probe 2>/dev/null; crontab -r 2>/dev/null; true' >/dev/null 2>&1
  done
  $SSH "$HUB" 'rm -f /tmp/hub_campaign*.sh 2>/dev/null; true' >/dev/null 2>&1
}

# deficient classes by ACTUAL window count across By_device windows_w1.csv
deficient(){
  "$PY" - "$DV" "$FLOOR" <<'PY'
import sys, glob, os, collections, csv
root, floor = sys.argv[1], int(sys.argv[2])
cnt = collections.Counter()
for f in glob.glob(os.path.join(root, "By_device_and_campaigns", "*", "*", "preprocessed", "windows_w1.csv")):
    try:
        with open(f, newline="") as fh:
            rd = csv.DictReader(fh)
            for r in rd:
                a = r.get("attack_type")
                if a and a != "normal": cnt[a] += 1
    except Exception: pass
# the 29 attack classes (any present) under floor, NEEDIEST (lowest count) FIRST
# so a per-run stage cap concentrates effort on the thinnest classes.
short = [a for a, n in sorted(cnt.items(), key=lambda kv: kv[1]) if n < floor]
print(",".join(short))
import sys as _s
print("COUNTS " + ";".join(f"{a}:{cnt.get(a,0)}" for a in sorted(cnt)), file=_s.stderr)
PY
}

logdetail(){ local vlog=$1 run=$2 vn=$3 pri=$4 sec=$5 st=$6 en=$7 rc=$8
  "$PY" - "$vlog" "$run" "$vn" "$pri" "$sec" "$st" "$en" "$rc" "$RUNLOG" <<'PY'
import sys, json
vlog, run, vn, pri, sec, st, en, rc, out = sys.argv[1:10]
d={}
try:
  for ln in open(vlog):
    if ln.startswith("RUNDETAIL "): d=json.loads(ln[10:]); break
except Exception: pass
g=lambda k:d.get(k,"")
dur=(int(en)-int(st)) if (st and en) else ""
row=[run,vn,pri,sec,st,en,dur,rc,g("windows"),g("net_frac"),g("tel_frac"),g("host_frac"),g("app_frac"),
     g("audit_lines"),g("journald_lines"),g("applog_lines"),g("telemetry_rows"),g("zeek_conn_rows"),g("tel_cols"),d.get("verdict","?")]
open(out,"a").write(",".join(str(x) for x in row)+"\n")
PY
}

r=$(awk '{print $1}' "$MAN" 2>/dev/null | sort -n | tail -1); r=$((${r:-0}+1))
echo "[v5-topup] start r=$r FLOOR=${FLOOR} windows MULT=${MULT}x scenario=$SCEN (locked pid $$)"
consec_fail=0
while :; do
  DEF=$(deficient)
  [ -z "$DEF" ] && { echo "[v5-topup] ALL attack classes >= ${FLOOR} windows -- DONE"; break; }
  if [ -n "${TOPUP_ONLY:-}" ]; then
    DEF=$(echo "$DEF" | tr ',' '\n' | grep -Fxf <(echo "$TOPUP_ONLY" | tr ',' '\n') | paste -sd,)
    [ -z "$DEF" ] && { echo "[v5-topup] all TOPUP_ONLY classes filled -- DONE"; break; }
  fi
  ndef=$(( $(echo "$DEF" | tr ',' '\n' | wc -l) ))
  # OPTIMISATION: cap stages per run to the CAP neediest classes (DEF is neediest-first).
  # With duration-mult repeating each real attack MULT times, a capped batch at a higher
  # MULT yields far more windows per run for the thin classes AND stays within the campaign
  # --timeout (no stage truncation). Set TOPUP_STAGES_PER_RUN=0 to disable the cap.
  CAP=${TOPUP_STAGES_PER_RUN:-0}
  if [ "$CAP" -gt 0 ] && [ "$ndef" -gt "$CAP" ]; then
    DEF=$(echo "$DEF" | tr ',' '\n' | head -n "$CAP" | paste -sd,)
  fi
  nstage=$(( $(echo "$DEF" | tr ',' '\n' | wc -l) ))
  echo "[v5-topup] run $r: $ndef deficient, running $nstage (neediest-first) MULT=${MULT}x -> $DEF"
  if (( r % 2 == 0 )); then PRI=192.168.0.32; VN=rpi3b1; SEC=192.168.0.33; else PRI=192.168.0.33; VN=rpi3b2; SEC=192.168.0.32; fi
  NN=$(printf '%02d' "$r"); NODE=$DV/By_device_and_campaigns/$VN/run${NN}_${SCEN}
  if ! EXPECT_TEL=$EXPECT_TEL bash "$PREFLIGHT" > "$W/preflight_r$r.log" 2>&1; then
    echo "[v5-topup] run $r PRE-FLIGHT NO-GO -- HALT"; tail -20 "$W/preflight_r$r.log"; exit 3; fi
  hard_clean; health_check "$PRI" "$VN" 2>/dev/null || true
  ST=$(date +%s)
  "$PY" "$RC" --scenario "$SCEN" --run-idx "$r" --victim-ip "$PRI" --vname "$VN" --victim2-ip "$SEC" \
     --catalogue "$CAT" --stages "$DEF" --duration-mult "$MULT" --timeout 10800 --shuffle-stages \
     > "$DS/${SCEN}_topup_$r.log" 2>&1
  rc=$?; EN=$(date +%s)
  echo "[v5-topup] run $r ($VN) campaign rc=$rc dur=$((EN-ST))s -- harvest+verify"
  rm -rf "$W/p$r" "$W/p${r}_al" "$NODE"
  LAB=$W/${SCEN}_labels.csv
  for t in 1 2 3; do $SSH "$HUB" "cat ~/campaigns/$SCEN/labels.csv" > "$LAB" 2>/dev/null; [ -s "$LAB" ] && break; sleep 4; done
  TB_PCAP_TO_CONTROL=0 bash "$HARV" "pi@$PRI" "$VN" "$HUB" "$ST" "$EN" "p$r" "$W" > "$W/harv$r.log" 2>&1 </dev/null
  cp "$LAB" "$W/p$r/labels.csv" 2>/dev/null
  "$PY" "$ALIGN" --captures "$W/p$r" --labels "$W/p$r/labels.csv" --out "$W/p${r}_al" --window-s 1 > "$W/align$r.log" 2>&1 </dev/null
  "$PY" "$DUAL" ingest --run-idx "$r" --device "$VN" --scenario "$SCEN" --work "$W/p$r" --aligned "$W/p${r}_al" \
     --labels "$LAB" --order-seed "$r" --root "$DV" > "$W/ingest$r.log" 2>&1 </dev/null
  "$PY" "$VER" --node "$NODE" --device "$VN" --run "$r" --stage "$SCEN" --raw "$W/p$r" \
     --expect-telcols "$EXPECT_TEL" --start "$ST" --end "$EN" > "$W/verify$r.log" 2>&1
  vrc=$?; cat "$W/verify$r.log"; logdetail "$W/verify$r.log" "$r" "$VN" "$PRI" "$SEC" "$ST" "$EN" "$rc"
  if [ "$vrc" -eq 0 ]; then
    echo "$r $VN $PRI $SEC $ST $EN rc=$rc topup" >> "$MAN"; echo "[v5-topup] run $r VALID"; consec_fail=0; r=$((r+1))
  else
    consec_fail=$((consec_fail+1))
    echo "[v5-topup] run $r INVALID (verify FAIL) consec=$consec_fail -- re-collecting"
    rm -rf "$NODE"
    if [ "$consec_fail" -ge 4 ]; then echo "[v5-topup] 4 consecutive verify FAILs -- HALT"; exit 2; fi
    sleep 20
  fi
done
echo "V5_TOPUP_DONE r=$r"
