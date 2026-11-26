#!/bin/bash
# Objective-3 FIRST synchronized benign capture (pipeline validation, NO attacks).
# Starts telemetry + on-device tcpdump, runs a benign local load for DUR seconds
# (execve churn + network + light CPU), then stops and snapshots host logs.
# Produces, under OUT, files named so align_windows.py's device_from_filename
# resolves them to this board's hostname:
#   telemetry_<host>_<day>.csv  capture_<host>.pcap  audit_<host>.log  journald_<host>.json
set -u
OUT="${1:-/tmp/cap}"; DUR="${2:-60}"; SESS="${3:-benignval}"
DEV="$(hostname)"
mkdir -p "$OUT"
rm -f "$OUT"/DONE "$OUT"/*.pcap "$OUT"/*.csv "$OUT"/*.log "$OUT"/*.json 2>/dev/null
START_EPOCH="$(date +%s)"
echo "capture start $DEV $(date -u +%FT%TZ) dur=${DUR}s" > "$OUT/capture.meta"

# --- telemetry (background) ---
nohup python3 "$HOME/telemetry_reader.py" --out "$OUT" --hz 2 --session "$SESS" >/dev/null 2>&1 &
TEL_PID=$!

# --- network (background, on-device tcpdump; sudo passwordless on this board) ---
sudo nohup tcpdump -i eth0 -w "$OUT/capture_${DEV}.pcap" -U >/dev/null 2>&1 &

# --- benign local load for DUR seconds (populates all 3 modalities) ---
END=$(( START_EPOCH + DUR ))
while [ "$(date +%s)" -lt "$END" ]; do
  ls -lR /etc/default >/dev/null 2>&1        # execve churn (audit)
  cat /proc/loadavg /proc/meminfo >/dev/null 2>&1
  ping -c 1 -W 1 192.168.0.50 >/dev/null 2>&1 # network (pcap)
  ( head -c 200000 /dev/zero | sha256sum ) >/dev/null 2>&1  # brief CPU (telemetry)
  sleep 2
done

# --- stop collectors ---
sudo pkill -f "tcpdump -i eth0 -w $OUT" 2>/dev/null
kill "$TEL_PID" 2>/dev/null
sleep 1

# --- host log snapshots for the window ---
# slice audit.log to THIS capture window (records whose audit(EPOCH...) >= start),
# so we don't drag in boot-time host-only windows. mawk-portable (no gawk arrays).
sudo cat /var/log/audit/audit.log 2>/dev/null \
  | awk -v s="$START_EPOCH" '{ if (match($0,/audit\([0-9]+/)) { t=substr($0,RSTART+6); sub(/\..*/,"",t); if (t+0>=s) print } }' \
  > "$OUT/audit_${DEV}.log"
sudo journalctl -o json --since "@${START_EPOCH}" > "$OUT/journald_${DEV}.json" 2>/dev/null
sudo chown "$(id -un)":"$(id -gn)" "$OUT"/*.log "$OUT"/*.json 2>/dev/null

echo "capture end $(date -u +%FT%TZ)" >> "$OUT/capture.meta"
{ echo "files:"; ls -l "$OUT"; } >> "$OUT/capture.meta"
touch "$OUT/DONE"
