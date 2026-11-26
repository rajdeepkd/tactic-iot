#!/bin/bash
# run_capture.sh -- always-on network capture for an Objective-3 victim board.
# Rotating nanosecond pcaps named so align_windows.device_from_filename resolves
# the board (cap_<host>_<UTCstamp>.pcap). Ships to the RPi5 hub for Zeek.
# NB victims are 0.9 GB RAM -> tcpdump only, NEVER Zeek on-board (Zeek on the hub).
set -u
IFACE="${TB_IFACE:-eth0}"
DIR="${TB_DIR:-/var/log/testbed}"
ROT="${TB_ROT:-600}"          # seconds per pcap file
KEEP_MIN="${TB_KEEP_MIN:-2880}" # retain pcaps this many minutes (default 48h) -> survive until archived to hub
SNAP="${TB_SNAP:-0}"          # snaplen; V4 default 0 = FULL packets (true raw release). v3 used 128 (headers only).
# CAPTURE-TIME SCOPE FILTER (V4): only process testbed-node traffic + ARP. The lab is
# meant to be air-gapped, but when it is on a live network a burst of non-testbed noise
# at FULL snaplen overwhelms the 0.9 GB Pi's capture buffer and DROPS packets, silently
# losing low-rate attack traffic (smoke 2026-11-13: a 3450 pkt/s burst dropped a synscan
# and synflood). Filtering at capture keeps the Pi's load low (no drops) AND makes the
# raw pcap release clean at the source. Hosts: rpi3b1/.32 rpi3b2/.33 hub/.50 control/.137.
if [ -n "${TB_FILTER:-}" ]; then FILTER="$TB_FILTER"
else FILTER="(host 192.168.0.32 or host 192.168.0.33 or host 192.168.0.50 or host 192.168.0.137) or arp"; fi
H="$(hostname)"
mkdir -p "$DIR"
# -U line-buffered, nanosecond stamps, time-based rotation via strftime filename.
# -s 0 (V4): capture FULL packets incl. MQTT/CoAP/Modbus payloads, for a genuine raw
#   pcap release. These are archived per-run to the hub then offloaded (see harvest).
# -Z root: do NOT drop privileges after opening the device, so the rotated pcap files
#   can always be written to the root-owned $DIR (v3 rpi3b2 crash-looped on "Permission
#   denied" because tcpdump dropped to user tcpdump which could not write the rotation).
tcpdump -i "$IFACE" --time-stamp-precision=nano -s "$SNAP" -Z root -U -G "$ROT" \
  -w "$DIR/cap_${H}_%Y%m%d_%H%M%S.pcap" "$FILTER" &
TP=$!
# bounded retention: prune old pcaps while tcpdump runs (0.9 GB victims must not
# fill their SD during a long always-on campaign). Ship+prune upstream if longer
# retention is needed. Ends when tcpdump dies (systemd Restart=always respawns).
trap 'kill "$TP" 2>/dev/null' TERM INT
while kill -0 "$TP" 2>/dev/null; do
  find "$DIR" -name "cap_${H}_*.pcap" -mmin +"$KEEP_MIN" -delete 2>/dev/null
  sleep 300
done
wait "$TP"
