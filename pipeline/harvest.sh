#!/bin/bash
# harvest.sh -- pull one time-window of all-modality data for a victim and run
# PRODUCTION Zeek on the hub. Runs on the Windows control box (Git Bash).
#
# v2 (2026-09-29): the network pcap is BIG (full-port scans + bulk exfil + ddos
# => 0.8-1.5 GB per run). So:
#   * pcap files are selected by mtime WITHIN the window (no unbounded over-grab),
#   * the hub pulls them DIRECTLY from the victim (cap_*.pcap are world-readable)
#     via the hub->victim key -- the giant pcap never transits the control PC,
#   * only the small Zeek logs + host/telemetry slices land on the control PC.
#
# Usage:
#   harvest.sh <victim_ssh> <vname> <hub_ssh> <start_epoch> <end_epoch> <session> <outdir>
set -u
VSSH="$1"; VNAME="$2"; HUB="$3"; START="$4"; END="$5"; SESS="$6"; OUT="$7"
KEY="$HOME/.ssh/obj3_testbed"
SSH="ssh -i $KEY -o BatchMode=yes"
SCP="scp -i $KEY -o BatchMode=yes"
VIP="${VSSH#*@}"
DST="$OUT/$SESS"; mkdir -p "$DST"
PAD=5
# a file OPEN at START may have opened up to one rotation (600s) before START, and a
# file open at END closes up to 600s after END -> widen both bounds by a rotation so
# window-selection never misses the covering file (snaplen keeps the over-grab small).
LOMT=$((START-605)); HIMT=$((END+605))

echo "[harvest] $VNAME window [$START,$END] -> $DST"

# --- 1. victim: slice host modalities + telemetry (small) -------------------
$SSH "$VSSH" "bash -s" <<EOF
set -u
W=/tmp/harvest_$SESS; rm -rf \$W; mkdir -p \$W
sudo bash -c 'cat /var/log/audit/audit.log*' 2>/dev/null \
 | awk -v lo=$((START-PAD)) -v hi=$((END+PAD)) '{ if (match(\$0,/audit\([0-9]+/)) { t=substr(\$0,RSTART+6); sub(/\..*/,"",t); if (t+0>=lo && t+0<=hi) print } }' \
 > \$W/audit_$VNAME.log
sudo journalctl -o json --since @$START --until @$((END+PAD)) > \$W/journald_$VNAME.json 2>/dev/null
# Telemetry is written as ONE FILE PER DAY. Slice the window out of EVERY telemetry file,
# not just the newest -- a run harvested on a later day (as at build time) would otherwise
# find its window only in whatever file happened to be newest, so every run whose window
# lived in an earlier day's file got ZERO telemetry rows (the runs 0-23 telemetry gap,
# 2026-11-10). The window is a narrow epoch range, so only the matching day's file yields rows.
TFS=\$(ls /var/log/testbed/telemetry_${VNAME}_*.csv 2>/dev/null)
if [ -n "\$TFS" ]; then
  # v5 FIX: take the header from the NEWEST file (current 37-col schema), NOT the
  # alphabetically-first (= OLDEST, which may be a stale 30/33/34-col schema -> header/data
  # width mismatch -> pandas column-shift, the v4 telemetry bug). Only append rows from files
  # whose width matches the newest (skip old-schema day files).
  NEWF=\$(ls -t /var/log/testbed/telemetry_${VNAME}_*.csv 2>/dev/null | head -1)
  head -1 "\$NEWF" > \$W/telemetry_${VNAME}_win.csv
  NW=\$(head -1 "\$NEWF" | awk -F, '{print NF}')
  for f in \$TFS; do
    fw=\$(head -1 "\$f" | awk -F, '{print NF}'); [ "\$fw" != "\$NW" ] && continue
    cc=\$(head -1 "\$f" | tr ',' '\n' | grep -n '^ts_realtime_ns\$' | cut -d: -f1)
    [ -z "\$cc" ] && continue
    awk -F, -v c="\$cc" -v lo=${START}000000000 -v hi=${END}000000000 'NR>1{if(\$c+0>=lo && \$c+0<=hi)print}' "\$f" >> \$W/telemetry_${VNAME}_win.csv
  done
fi
# APPLICATION-PROTOCOL LOGS (4th modality): broker/coap/modbus, sliced to the window.
# Each line is 'epoch: message'; keep lines whose leading epoch is in [START-PAD,END+PAD].
for al in mqtt:/var/log/mosquitto/mosquitto.log coap:/var/log/testbed/coap_tactic.log modbus:/var/log/testbed/modbus_tactic.log; do
  pr=\${al%%:*}; pf=\${al#*:}
  sudo awk -v lo=$((START-PAD)) -v hi=$((END+PAD)) '{e=\$1+0; if(e>=lo && e<=hi) print}' "\$pf" 2>/dev/null > \$W/applog_\${pr}_$VNAME.log
done
# list (do NOT copy) the window's pcap files by mtime, for the hub to pull
for f in /var/log/testbed/cap_${VNAME}_*.pcap; do
  m=\$(stat -c%Y "\$f" 2>/dev/null) || continue
  if [ "\$m" -ge $LOMT ] && [ "\$m" -le $HIMT ]; then echo "\$f"; fi
done > \$W/pcaplist.txt
sudo chown -R \$(id -un):\$(id -gn) \$W 2>/dev/null
echo "  victim staged: \$(ls \$W | tr '\n' ' ') | window pcaps: \$(wc -l < \$W/pcaplist.txt)"
EOF

# --- 2. control pulls the SMALL slices only (host + the three app-log slices) ----
$SCP "$VSSH:/tmp/harvest_$SESS/audit_$VNAME.log" "$VSSH:/tmp/harvest_$SESS/journald_$VNAME.json" \
     "$VSSH:/tmp/harvest_$SESS/telemetry_${VNAME}_win.csv" \
     "$VSSH:/tmp/harvest_$SESS/applog_mqtt_$VNAME.log" \
     "$VSSH:/tmp/harvest_$SESS/applog_coap_$VNAME.log" \
     "$VSSH:/tmp/harvest_$SESS/applog_modbus_$VNAME.log" "$DST/" 2>/dev/null

# C3 (dossier): project the collector-apparatus load columns out of the telemetry
# slice into a standalone collector_cpu CSV (the dual store keeps it as raw
# provenance; the SAME columns also stay in the telemetry slice, where align turns
# them into tel__col_* per-window gauges). Skipped cleanly if the telemetry predates
# the C3 reader (no col_cpu_pct column).
TS="$DST/telemetry_${VNAME}_win.csv"
if [ -s "$TS" ] && head -1 "$TS" | grep -q 'col_cpu_pct'; then
  awk -F, 'NR==1{for(i=1;i<=NF;i++)ix[$i]=i;
            want="ts_realtime_ns ts_iso col_cpu_pct col_cap_cpu_pct col_rss_mb col_n"; n=split(want,Wc," ");
            out=""; for(j=1;j<=n;j++){c[j]=ix[Wc[j]]; out=out (j>1?",":"") Wc[j]} print out; next}
          {out=""; for(j=1;j<=n;j++){out=out (j>1?",":"") (c[j]?$(c[j]):"")} print out}' \
    "$TS" > "$DST/collector_cpu_${VNAME}.csv"
fi

# --- 3. hub pulls the window pcaps DIRECTLY from the victim + runs Zeek ------
PCAPS=$($SSH "$VSSH" "cat /tmp/harvest_$SESS/pcaplist.txt" 2>/dev/null | tr '\n' ' ')
$SSH "$HUB" "bash -s" <<EOF
set -u
export PATH=/opt/zeek/bin:\$PATH
# Stage pcaps on the hub's DISK (home, 117G/~91G free), NOT /tmp. /tmp is a 4G tmpfs,
# and a single V4 run's full-snaplen window pcaps (exfil + floods) reach ~3-5 GB, which
# overflows the tmpfs mid-scope and silently truncates the capture (V4 pilot: run0 = 2.8 GB
# of window pcaps, peaking higher during per-file .scoped rewrite). Disk has ample room.
W=\$HOME/zeekrun_$SESS; rm -rf \$W; mkdir -p \$W; cd \$W
VK=\$HOME/.ssh/hub_to_victim
for f in $PCAPS; do
  scp -i \$VK -o BatchMode=yes pi@$VIP:"\$f" \$W/ 2>/dev/null
done
shopt -s nullglob
# IP-SCOPE FILTER (software air-gap filtration): keep only packets that involve a
# testbed node -- the 3 Pis + hub (192.168.0.32/.33/.50) and the control box
# (192.168.0.137) as src or dst -- plus ARP (needed for the MITM/ARP features), and
# drop pure third-party IP traffic. This scopes EVERY downstream feature (Zeek conn/
# app logs, arp/coap/pkts csvs) to testbed traffic. It also counts the dropped
# "outlier" packets so the dataset reports exactly how much non-testbed traffic the
# raw capture carried. IPv4 multicast sourced by a testbed node (mDNS/SSDP/CoAP) is
# kept because the node's IPv4 is the src; IPv6 link-local chatter is out of scope
# and counted as outliers (the labeled attack/benign flows are all IPv4).
TBF='(host 192.168.0.32 or host 192.168.0.33 or host 192.168.0.50 or host 192.168.0.137) or arp'
pkc(){ capinfos -c -M "\$1" 2>/dev/null | awk -F'[=:] *' '/[Nn]umber of packets/{print \$2+0;f=1} END{if(!f)exit 1}' || tcpdump -nn -r "\$1" 2>/dev/null | wc -l; }
FTOT=0; FKEPT=0
for pc in \$W/cap_${VNAME}_*.pcap; do
  [ -e "\$pc" ] || continue
  t=\$(pkc "\$pc")
  tcpdump -nn -r "\$pc" -w "\$pc.scoped" "\$TBF" 2>/dev/null
  k=\$(pkc "\$pc.scoped"); mv -f "\$pc.scoped" "\$pc"
  FTOT=\$((FTOT+t)); FKEPT=\$((FKEPT+k))
done
echo "  IPFILTER ${VNAME} total=\$FTOT kept=\$FKEPT outliers=\$((FTOT-FKEPT))"
# v2: load the MQTT analyzer (modbus/snmp log by default on standard ports). The
# load script must be shipped to the hub at ~/pipeline/zeek_tactic.zeek; absent it,
# v1 behaviour (conn/ssh/dns/http/weird) is unchanged.
ZL=\$HOME/pipeline/zeek_tactic.zeek; [ -f "\$ZL" ] || ZL=""
for pc in \$W/cap_${VNAME}_*.pcap; do
  d=\${pc%.pcap}_logs; mkdir -p \$d
  ( cd \$d && zeek -C -r "\$pc" \$ZL 2>/dev/null )
done
# v1 logs + v2 IoT application-protocol logs. mqtt_* / modbus / snmp only appear
# when that protocol was present in the pcap, so missing logs are simply skipped.
for L in conn ssh dns http weird mqtt_connect mqtt_publish mqtt_subscribe modbus snmp; do
  first=1
  for lf in \$W/cap_${VNAME}_*_logs/\$L.log; do
    [ -e "\$lf" ] || continue
    if [ \$first -eq 1 ]; then cp "\$lf" \$W/\$L.log.$VNAME; first=0
    else grep -v '^#' "\$lf" >> \$W/\$L.log.$VNAME; fi
  done
done
# ARP layer (Zeek IP flows are blind to it) -> per-packet ts + reply/request via
# tcpdump, for the MITM/ARP-spoof feature. Reading a pcap file needs no root.
echo "ts,arp_total,arp_reply,arp_request" > \$W/arp.$VNAME.csv
for pc in \$W/cap_${VNAME}_*.pcap; do
  [ -e "\$pc" ] || continue
  tcpdump -nn -tt -r "\$pc" arp 2>/dev/null | awk '{r=(\$3=="Reply")?1:0; q=(\$3=="Request")?1:0; if(\$1 ~ /^[0-9]/) print \$1","1","r","q}' >> \$W/arp.$VNAME.csv
done
# CoAP layer (Zeek has no CoAP analyzer) -> per-message ts + confirmable/GET via
# tshark, for the v2 CoAP features. Skipped cleanly if tshark is absent.
echo "ts,coap_msg,coap_con,coap_get" > \$W/coap.$VNAME.csv
if command -v tshark >/dev/null 2>&1; then
  for pc in \$W/cap_${VNAME}_*.pcap; do
    [ -e "\$pc" ] || continue
    tshark -r "\$pc" -Y coap -T fields -e frame.time_epoch -e coap.type -e coap.code 2>/dev/null \
      | awk -F'\t' '{con=(\$2==0)?1:0; get=(\$3==1)?1:0; if(\$1 ~ /^[0-9]/) print \$1","1","con","get}' >> \$W/coap.$VNAME.csv
  done
fi
# C1 FIX (dossier): PER-WINDOW packet + byte counts straight from the wire, so a
# long single-connection transfer fills EVERY second it spans, not only the second
# Zeek stamps its one conn record. Without this, exfil/ddos look network-blind
# purely as an extractor artifact. Per-packet ts + length -> align sums per window
# into net__pkts / net__bytes. tcpdump (no root to read a file) is the fallback when
# tshark is absent; both emit "ts,pkts,bytes" with pkts=1, bytes=wire length.
echo "ts,pkts,bytes" > \$W/pkts.$VNAME.csv
for pc in \$W/cap_${VNAME}_*.pcap; do
  [ -e "\$pc" ] || continue
  if command -v tshark >/dev/null 2>&1; then
    tshark -r "\$pc" -T fields -e frame.time_epoch -e frame.len 2>/dev/null \
      | awk -F'\t' '{if(\$1 ~ /^[0-9]/) print \$1","1","\$2}' >> \$W/pkts.$VNAME.csv
  else
    tcpdump -nn -tt -r "\$pc" -e 2>/dev/null \
      | awk '{if(\$1 ~ /^[0-9]/){n=\$NF; if(n ~ /^[0-9]+\$/) print \$1","1","n}}' >> \$W/pkts.$VNAME.csv
  fi
done
echo "  hub pulled \$(ls \$W/cap_*.pcap 2>/dev/null | wc -l) pcap(s); zeek logs: \$(ls \$W/*.log.$VNAME 2>/dev/null | xargs -n1 basename 2>/dev/null | tr '\n' ' '); arp rows: \$(( \$(wc -l < \$W/arp.$VNAME.csv) - 1 )); coap rows: \$(( \$(wc -l < \$W/coap.$VNAME.csv) - 1 )); pkt rows: \$(( \$(wc -l < \$W/pkts.$VNAME.csv) - 1 ))"
# V4: ARCHIVE the IP-scoped, full-snaplen per-run pcap(s) to a PERSISTENT hub store
# (NOT deleted). These are the genuine raw-network release artifact; they are offloaded
# from the hub to external/control storage after collection and then ingested into the
# dataset (By_device raw/network + per-action By_labels slices). Keyed by session so
# runs never collide. Merged into one per-run pcap when mergecap is available.
ARCH=\$HOME/pcap_archive/$SESS; mkdir -p \$ARCH
if ls \$W/cap_${VNAME}_*.pcap >/dev/null 2>&1; then
  if command -v mergecap >/dev/null 2>&1; then
    # -F nsecpcap: classic libpcap with NANOSECOND precision. NOT pcapng (mergecap's
    # default) -- the per-action slicer (build_dual_layout.slice_pcap) and most tools
    # read classic libpcap, not pcapng, so a pcapng merge silently yields 0 By_labels
    # pcap slices (smoke 2026-11-13). nsecpcap preserves the capture's ns timestamps.
    mergecap -F nsecpcap -w \$ARCH/cap_${VNAME}_${SESS}.pcap \$W/cap_${VNAME}_*.pcap 2>/dev/null \
      && echo "  ARCHIVED merged pcap -> \$ARCH/cap_${VNAME}_${SESS}.pcap (\$(du -h \$ARCH/cap_${VNAME}_${SESS}.pcap 2>/dev/null | cut -f1))"
  else
    cp -f \$W/cap_${VNAME}_*.pcap \$ARCH/ 2>/dev/null \
      && echo "  ARCHIVED \$(ls \$W/cap_${VNAME}_*.pcap | wc -l) window pcap(s) -> \$ARCH (mergecap absent)"
  fi
fi
rm -f \$W/cap_${VNAME}_*.pcap   # free the big working-copy pcaps on the hub after archiving
EOF

# --- 4. control pulls only the small Zeek logs + ARP/CoAP csvs --------------
# (hub staging now lives in ~/zeekrun_$SESS on disk, not /tmp -- see step 3)
$SCP "$HUB:zeekrun_$SESS/*.log.$VNAME" "$DST/" 2>/dev/null
$SCP "$HUB:zeekrun_$SESS/arp.$VNAME.csv" "$DST/" 2>/dev/null
$SCP "$HUB:zeekrun_$SESS/coap.$VNAME.csv" "$DST/" 2>/dev/null
$SCP "$HUB:zeekrun_$SESS/pkts.$VNAME.csv" "$DST/" 2>/dev/null
# V4: for a SMALL/smoke build, also pull the archived per-run pcap to control so ingest
# places it into By_device raw/network. For the full run the pcaps stay on the hub
# (control disk is tight) and are offloaded + ingested afterward.
if [ "${TB_PCAP_TO_CONTROL:-0}" = "1" ]; then
  $SCP "$HUB:pcap_archive/$SESS/cap_${VNAME}_*.pcap" "$DST/" 2>/dev/null \
    && echo "[harvest] pulled archived pcap(s) to control: $(ls "$DST"/cap_${VNAME}_*.pcap 2>/dev/null | wc -l)"
fi
echo "[harvest] assembled: $DST"; ls -1 "$DST"

# V5: archive the per-run RAW LOG slices on the HUB (the master raw store, alongside the
# pcaps already in ~/pcap_archive). The user's design is "store all log and pcap files in the
# hub"; control keeps only the By_labels deliverable + By_device windows. Small (~40 MB/run,
# mostly audit). If the hub is low on disk these also exist on control (By_device raw) to ship.
if [ "${TB_RAW_TO_HUB:-1}" = "1" ]; then
  $SSH "$HUB" "mkdir -p ~/v5_raw/$SESS" 2>/dev/null
  $SCP "$DST"/audit_*.log "$DST"/journald_*.json "$DST"/telemetry_*_win.csv \
       "$DST"/applog_*.log "$DST"/*.log."$VNAME" "$DST"/*.csv "$HUB:v5_raw/$SESS/" 2>/dev/null \
    && echo "[harvest] archived raw log slices -> hub ~/v5_raw/$SESS/"
fi

# free remote tmpfs staging (victim + hub) so /tmp (a 454M tmpfs) does not fill
# over a long multi-run collection. Source pcaps stay in /var/log/testbed; these
# are only per-run staging copies, already pulled to $DST above. Leftover
# /tmp/harvest_* dirs filling the victim tmpfs is what silently zeroed the pcap
# selection for rpi3b1 runs 12/14 (pcaplist.txt write -> No space left on device).
$SSH "$VSSH" "rm -rf /tmp/harvest_$SESS" 2>/dev/null
$SSH "$HUB" "rm -rf \$HOME/zeekrun_$SESS" 2>/dev/null
