#!/bin/bash
# v5_collect.sh [NRUNS] -- TACTIC-IoT V5 collection with a PER-RUN CONTENT GATE.
#
# The single fix that closes every v4 defect: each run is harvested + aligned + ingested +
# VERIFIED immediately, and the driver advances ONLY when verify_run.py says the run is VALID
# (all 4 modalities non-empty + real signal, telemetry ns-scale + 37-col schema + correct
# device_id, auditd actually recorded execve, benign windows carry app activity). A failed run
# is re-collected once; a second failure HALTS the driver (no silent advance).
#
# Raw pcaps + the per-run audit/journald/telemetry/applog are archived on the HUB
# (~/pcap_archive, and harvest staging). By_device_and_campaigns/ here is a TRANSIENT working
# tree (no whole-run pcap pulled to control during collection). By_labels/ -- the deliverable --
# is built by v5_finalize.sh after collection. Per-run counts are logged to v5_run_details.csv.
set -u
TB=/d/Experiment/Objective_3/testbed; PY=/c/Python313/python
RC=$TB/orchestrator/run_campaign.py; CAT=$TB/orchestrator/campaigns_v2.yaml
HARV=$TB/pipeline/harvest.sh; ALIGN=$TB/pipeline/align_windows.py
DUAL=$TB/pipeline/build_dual_layout.py; VER=$TB/pipeline/verify_run.py
PREFLIGHT=$TB/orchestrator/v5_preflight.sh
K=$HOME/.ssh/obj3_testbed; HUB=cnc@192.168.0.50
SCEN=${SCEN:-V5}; EXPECT_TEL=${EXPECT_TEL:-37}
DS=$TB/dataset; MAN=${MAN:-$DS/v5_manifest.txt}; mkdir -p "$DS"
W=${WORKDIR:-$DS/v5_work}; mkdir -p "$W"
DV=${DV:-$TB/dataset_v5}
RUNLOG=$DS/v5_run_details.csv
STAGES=${STAGES:-bruteforce_dict,bruteforce_slow,bruteforce_telnet,bruteforce_mqtt,control_modbus_write,control_mqtt_cmdinject,ddos_ackflood,ddos_coap_conflood,ddos_icmpflood,ddos_mqtt_connflood,ddos_synflood,ddos_udpflood,evasion_logtamper,execution_lolbin,exfil_bulk,exfil_mqtt,lateral_scan,mitm_arp,persistence_cron,privesc_suidscan,recon_coap_discovery,recon_connectscan,recon_hostsweep,recon_modbus_scan,recon_mqtt_enum,recon_osdetect,recon_stealthscan,recon_synscan,recon_udpscan}
NRUNS=${1:-16}
TIMEOUT=${TIMEOUT:-5400}
SSH="ssh -i $K -o BatchMode=yes -o ServerAliveInterval=15 -o ConnectTimeout=15"
source "$TB/orchestrator/v3_lib.sh"   # V() + health_check()

[ -f "$RUNLOG" ] || echo "run,device,pri_ip,sec_ip,start_epoch,end_epoch,dur_s,rc,windows,net_frac,tel_frac,host_frac,app_frac,audit_lines,journald_lines,applog_lines,telemetry_rows,zeek_conn_rows,tel_cols,verdict" > "$RUNLOG"

fetch_labels(){ # -> $W/${SCEN}_labels.csv  (fresh from hub each run)
  local f=$W/${SCEN}_labels.csv
  for t in 1 2 3; do $SSH "$HUB" "cat ~/campaigns/$SCEN/labels.csv" > "$f" 2>/dev/null; [ -s "$f" ] && break; sleep 4; done
  echo "$f"
}

logdetail(){ # $1 = verify stdout log, $2.. = manifest fields
  local vlog=$1 run=$2 vn=$3 pri=$4 sec=$5 st=$6 en=$7 rc=$8
  "$PY" - "$vlog" "$run" "$vn" "$pri" "$sec" "$st" "$en" "$rc" "$RUNLOG" <<'PY'
import sys, json
vlog, run, vn, pri, sec, st, en, rc, out = sys.argv[1:10]
d = {}
try:
    for ln in open(vlog):
        if ln.startswith("RUNDETAIL "):
            d = json.loads(ln[len("RUNDETAIL "):]); break
except Exception: pass
g = lambda k: d.get(k, "")
dur = (int(en) - int(st)) if (st and en) else ""
row = [run, vn, pri, sec, st, en, dur, rc, g("windows"), g("net_frac"), g("tel_frac"),
       g("host_frac"), g("app_frac"), g("audit_lines"), g("journald_lines"), g("applog_lines"),
       g("telemetry_rows"), g("zeek_conn_rows"), g("tel_cols"), d.get("verdict","?")]
open(out, "a").write(",".join(str(x) for x in row) + "\n")
print("LOGGED " + d.get("verdict","?"))
PY
}

r=$(grep -c . "$MAN" 2>/dev/null || echo 0)
echo "[v5] START r=$r NRUNS=$NRUNS stages=$(echo $STAGES | tr ',' ' ' | wc -w) scenario=$SCEN timeout=$TIMEOUT"
echo "[v5] manifest=$MAN work=$W dataset=$DV runlog=$RUNLOG"

while [ "$r" -lt "$NRUNS" ]; do
  if (( r % 2 == 0 )); then PRI=192.168.0.32; VN=rpi3b1; SEC=192.168.0.33; else PRI=192.168.0.33; VN=rpi3b2; SEC=192.168.0.32; fi
  NN=$(printf '%02d' "$r"); NODE=$DV/By_device_and_campaigns/$VN/run${NN}_${SCEN}

  # ---- PRE-FLIGHT gate (both victims + hub benign) ----
  if ! EXPECT_TEL=$EXPECT_TEL bash "$PREFLIGHT" > "$W/preflight_r$r.log" 2>&1; then
    echo "[v5] run $r PRE-FLIGHT NO-GO -- see $W/preflight_r$r.log -- HALT"; tail -20 "$W/preflight_r$r.log"; exit 3
  fi
  health_check "$PRI" "$VN"

  # ---- RUN ----
  ST=$(date +%s)
  "$PY" "$RC" --scenario "$SCEN" --run-idx "$r" --victim-ip "$PRI" --vname "$VN" --victim2-ip "$SEC" \
     --catalogue "$CAT" --stages "$STAGES" --timeout "$TIMEOUT" --shuffle-stages > "$DS/${SCEN}_run$r.log" 2>&1
  rc=$?; EN=$(date +%s)
  echo "[v5] run $r ($VN) campaign rc=$rc dur=$((EN-ST))s -- harvesting"

  # ---- HARVEST (immediate; pcap archived on hub, NOT pulled to control) ----
  rm -rf "$W/p$r" "$W/p${r}_al"; rm -rf "$NODE"
  LAB=$(fetch_labels)
  TB_PCAP_TO_CONTROL=0 bash "$HARV" "pi@$PRI" "$VN" "$HUB" "$ST" "$EN" "p$r" "$W" > "$W/harv$r.log" 2>&1 </dev/null
  cp "$LAB" "$W/p$r/labels.csv" 2>/dev/null
  "$PY" "$ALIGN" --captures "$W/p$r" --labels "$W/p$r/labels.csv" --out "$W/p${r}_al" --window-s 1 > "$W/align$r.log" 2>&1 </dev/null
  "$PY" "$DUAL" ingest --run-idx "$r" --device "$VN" --scenario "$SCEN" \
     --work "$W/p$r" --aligned "$W/p${r}_al" --labels "$LAB" --order-seed "$r" --root "$DV" > "$W/ingest$r.log" 2>&1 </dev/null

  # ---- VERIFY (content gate) ----
  "$PY" "$VER" --node "$NODE" --device "$VN" --run "$r" --stage "$SCEN" --raw "$W/p$r" \
     --expect-telcols "$EXPECT_TEL" --start "$ST" --end "$EN" > "$W/verify$r.log" 2>&1
  vrc=$?
  cat "$W/verify$r.log"
  logdetail "$W/verify$r.log" "$r" "$VN" "$PRI" "$SEC" "$ST" "$EN" "$rc"

  if [ "$vrc" -eq 0 ]; then
    echo "$r $VN $PRI $SEC $ST $EN rc=$rc" >> "$MAN"      # COMMIT run as VALID
    echo "[v5] run $r VALID -- advancing"
    ATT=0; r=$((r+1))
  else
    ATT=$(( ${ATT:-0} + 1 ))
    if [ "$ATT" -lt 2 ]; then
      echo "[v5] run $r INVALID (verify FAIL) -- RE-COLLECTING (attempt $((ATT+1))/2)"; sleep 20
    else
      echo "[v5] run $r INVALID TWICE -- HALT. Inspect $W/verify$r.log + $W/harv$r.log"; exit 2
    fi
  fi
done
echo "V5_COLLECT_DONE r=$r  (valid runs in $MAN)"
