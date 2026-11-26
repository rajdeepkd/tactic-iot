#!/bin/bash
# run_action.sh -- the ground-truth-labelling wrapper for Objective-3 campaigns.
#
# WHY THIS EXISTS: labels are NOT inferred by inspecting captured data after the
# fact. They are CAUSED and TIMESTAMPED by the orchestrator at the moment each
# attack action runs. This wrapper is the only sanctioned way to launch an
# attack action; every launch appends one schema-correct row to labels.csv on
# the chrony MASTER clock (this node = RPi5 hub = stratum master), so the row's
# start/end are the reference against which every victim silo (telemetry / pcap /
# auditd / journald, all chrony-slaved at us offset) is interval-joined by
# testbed/pipeline/align_windows.py:label_window().
#
# labels.csv schema (consumed verbatim by align_windows.load_labels):
#   scenario_id,run_idx,attack_type,target,stage,start_iso,end_iso
#   - target    = the VICTIM hostname (rpi3b1 / rpi3b2), NOT the attacker: the
#                 label attaches to the victim's windows, where the footprint is.
#   - stage     = kill-chain stage {recon,bruteforce,delivery,execution,
#                 persistence,privesc,c2,exfil,ddos} -> the stage-dependence label.
#   - group_id downstream = scenario_id#run_idx (per-execution pooling view).
#   - start_iso/end_iso    = UTC ISO-8601, us precision, MASTER clock.
#
# An evidence line (rc + argv + wall time) is also appended to actions.jsonl for
# reproducibility -- but the .csv, not the tool's own output, is ground truth.
#
# Usage:
#   run_action.sh <outdir> <scenario_id> <run_idx> <attack_type> <stage> <target> -- <cmd> [args...]
# Example:
#   run_action.sh ~/campaigns/C07 C07 0 recon recon rpi3b2 -- nmap -sS -T3 192.168.0.32
#
# NB benign windows are NOT written here: benign = every window that overlaps no
# labels.csv interval. Record a quiescent baseline (no run_action calls) around
# each campaign so "benign" is a real distribution, not merely gaps.
set -u

if [ "$#" -lt 8 ]; then
  echo "usage: $0 <outdir> <scenario_id> <run_idx> <attack_type> <stage> <target> -- <cmd...>" >&2
  exit 2
fi
OUT="$1"; SCEN="$2"; RUN="$3"; ATYPE="$4"; STAGE="$5"; TARGET="$6"; shift 6
if [ "$1" != "--" ]; then echo "expected -- before command, got: $1" >&2; exit 2; fi
shift
if [ "$#" -lt 1 ]; then echo "no command given after --" >&2; exit 2; fi

# --- validate label fields: they must not break the 7-column labels.csv schema ---
for v in "$SCEN" "$ATYPE" "$STAGE" "$TARGET"; do
  case "$v" in
    *,* | *'"'* | *"'"*) echo "ERROR: label field '$v' contains comma/quote -> would corrupt labels.csv" >&2; exit 2;;
  esac
done
case "$RUN" in ''|*[!0-9]*) echo "ERROR: run_idx must be a non-negative integer, got '$RUN'" >&2; exit 2;; esac
RUN=$((10#$RUN))   # normalise (strip leading zeros -> valid CSV int AND valid JSON number)

esc() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }   # JSON string escape

mkdir -p "$OUT"
CSV="$OUT/labels.csv"
EVID="$OUT/actions.jsonl"
[ -f "$CSV" ] || echo "scenario_id,run_idx,attack_type,target,stage,start_iso,end_iso" > "$CSV"

# --- MASTER-clock timestamps bracket the action (this node is stratum master) ---
START_ISO="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"
START_NS="$(date -u +%s%N)"

# run the action; do NOT let its non-zero rc abort labelling (scans legitimately
# return non-zero). Capture rc + a truncated stdout tail for the evidence log.
# PER-ACTION TIMEOUT (hang guard): no single action may stall the whole campaign.
# Default 900s is well above the slowest legitimate stage (exfil_bulk ~460s,
# bruteforce_telnet ~230s) but catches a true hang; a timed-out action returns 124.
LOG="$(mktemp)"
timeout -k 10 "${TB_ACTION_TIMEOUT:-900}" "$@" >"$LOG" 2>&1
RC=$?

END_ISO="$(date -u +%Y-%m-%dT%H:%M:%S.%6NZ)"
END_NS="$(date -u +%s%N)"
DUR_MS=$(( (END_NS - START_NS) / 1000000 ))

# --- ground-truth row (interval) ---
echo "${SCEN},${RUN},${ATYPE},${TARGET},${STAGE},${START_ISO},${END_ISO}" >> "$CSV"

# --- evidence row (reproducibility, not ground truth) ---
# argv is JSON-escaped minimally; tail kept short to avoid storing payloads.
ARGV_JSON="$(printf '%s\n' "$@" | sed 's/\\/\\\\/g; s/"/\\"/g' | paste -sd'|' -)"
TAIL="$(tail -c 400 "$LOG" | tr '\n\t' '  ' | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g')"
printf '{"scenario":"%s","run":%s,"attack_type":"%s","stage":"%s","target":"%s","host":"%s","start":"%s","end":"%s","dur_ms":%s,"rc":%s,"argv":"%s","tail":"%s"}\n' \
  "$(esc "$SCEN")" "$RUN" "$(esc "$ATYPE")" "$(esc "$STAGE")" "$(esc "$TARGET")" "$(esc "$(hostname)")" "$START_ISO" "$END_ISO" "$DUR_MS" "$RC" "$ARGV_JSON" "$TAIL" >> "$EVID"
rm -f "$LOG"

echo "[run_action] ${SCEN}#${RUN} ${ATYPE}/${STAGE} -> ${TARGET}  ${DUR_MS}ms rc=${RC}" >&2
exit "$RC"
