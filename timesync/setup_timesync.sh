#!/usr/bin/env bash
# setup_timesync.sh -- idempotent time-sync bring-up for one Objective-3 board.
# Run ON each Linux board (the orchestrator pushes+runs it over SSH).
#
#   sudo ./setup_timesync.sh server            # on rpi5-hub (10.0.0.1)
#   sudo ./setup_timesync.sh client 10.0.0.1   # on rpi3b-1 / jetson-1 / attacker
#
# What it does:
#   1. installs chrony, disables competing timesyncd/ntpd,
#   2. drops the matching config (chrony-server.conf / chrony-client.conf),
#   3. restarts chrony and waits until |offset| < 1 ms (the preflight gate),
#   4. writes a JSON tracking snapshot to /var/log/testbed/timesync/ so every
#      capture can record the clock state it was collected under.
set -euo pipefail

ROLE="${1:?usage: setup_timesync.sh server|client [server_ip]}"
SRV_IP="${2:-10.0.0.1}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SNAP_DIR="/var/log/testbed/timesync"
GATE_MS="${GATE_MS:-1.0}"     # preflight skew gate in milliseconds
GATE_WAIT="${GATE_WAIT:-120}" # seconds to wait for convergence

echo "[timesync] role=$ROLE server=$SRV_IP host=$(hostname)"

# 1. install chrony, remove competitors -------------------------------------
if ! command -v chronyd >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq && apt-get install -y -qq chrony
fi
systemctl disable --now systemd-timesyncd 2>/dev/null || true
systemctl disable --now ntp 2>/dev/null || true          # legacy ntpd, if present

# 2. drop the config ---------------------------------------------------------
if [ "$ROLE" = "server" ]; then
  install -m 0644 "$HERE/chrony-server.conf" /etc/chrony/chrony.conf
else
  # substitute the server IP in case it is not the default 10.0.0.1
  sed "s/10\.0\.0\.1/$SRV_IP/g" "$HERE/chrony-client.conf" > /etc/chrony/chrony.conf
fi

mkdir -p /var/log/chrony "$SNAP_DIR"
systemctl enable --now chrony 2>/dev/null || systemctl enable --now chronyd
systemctl restart chrony 2>/dev/null || systemctl restart chronyd
chronyc -a makestep >/dev/null 2>&1 || true   # one allowed step at bring-up

# 3. wait for convergence to the gate ----------------------------------------
echo "[timesync] waiting up to ${GATE_WAIT}s for |offset| < ${GATE_MS} ms ..."
ok=0
for _ in $(seq 1 "$GATE_WAIT"); do
  # "Last offset" is in seconds; abs value in ms via awk.
  off_ms=$(chronyc tracking 2>/dev/null | awk -F: '/Last offset/{o=$2; gsub(/[^0-9eE.+-]/,"",o); print (o<0?-o:o)*1000}')
  if [ -n "${off_ms:-}" ] && awk "BEGIN{exit !($off_ms < $GATE_MS)}"; then ok=1; break; fi
  sleep 1
done

# 4. snapshot the clock state ------------------------------------------------
BOOT_ID=$(cat /proc/sys/kernel/random/boot_id)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
SNAP="$SNAP_DIR/${HOSTNAME:-$(hostname)}_${STAMP}.json"
{
  echo "{"
  echo "  \"host\": \"$(hostname)\","
  echo "  \"role\": \"$ROLE\","
  echo "  \"boot_id\": \"$BOOT_ID\","
  echo "  \"snapshot_utc\": \"$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)\","
  echo "  \"gate_ms\": $GATE_MS, \"gate_passed\": $([ $ok -eq 1 ] && echo true || echo false),"
  echo "  \"tracking\": \"$(chronyc tracking | tr '\n' '|' | sed 's/"/\\"/g')\","
  echo "  \"sourcestats\": \"$(chronyc sourcestats | tr '\n' '|' | sed 's/"/\\"/g')\""
  echo "}"
} > "$SNAP"
echo "[timesync] snapshot -> $SNAP"
chronyc tracking | sed 's/^/    /'

if [ $ok -ne 1 ]; then
  echo "[timesync] FAIL: offset did not converge under ${GATE_MS} ms -- do NOT capture." >&2
  exit 1
fi
echo "[timesync] OK: offset < ${GATE_MS} ms; safe to capture."
