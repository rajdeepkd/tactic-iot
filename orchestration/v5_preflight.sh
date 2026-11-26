#!/bin/bash
# v5_preflight.sh -- GO/NO-GO before every V5 run. Stricter than v4: also requires auditd
# ACTIVE+ADVANCING (the v4 host defect), telemetry ACTIVE+ADVANCING with device_id==hostname
# and the unified 37-col schema (the v4 telemetry defects), and BOTH benign generators up on
# the hub (tb-iot-benign = authenticated IoT client; tb-benign-host = SSH admin -> auth_ok;
# the v4 benign-realism defect). Exits 0 only if every critical check passes.
set -u
K=$HOME/.ssh/obj3_testbed; HUB=cnc@192.168.0.50
SSH="ssh -i $K -o BatchMode=yes -o ConnectTimeout=12 -o ServerAliveInterval=10"
EXPECT_TEL=${EXPECT_TEL:-37}
GO=1
VCHK=$(cat <<'VEOF'
h=$(hostname)
ref=$(chronyc tracking 2>/dev/null | grep -oE "C0A80032")
cap=$(pgrep -a tcpdump 2>/dev/null | grep -c "s 0")
flt=$(pgrep -a tcpdump 2>/dev/null | grep -c arp)
nf=$(ls -t /var/log/testbed/cap_${h}_*.pcap 2>/dev/null | head -1)
s1=$(stat -c%s "$nf" 2>/dev/null)
# Active probe: a short ping burst to the hub (matches the capture filter host 192.168.0.50)
# guarantees captured packets, so a momentary benign-traffic lull cannot read as "not writing".
ping -c 4 -i 0.25 -W 1 192.168.0.50 >/dev/null 2>&1 &
sleep 2
s2=$(stat -c%s "$nf" 2>/dev/null)
nf2=$(ls -t /var/log/testbed/cap_${h}_*.pcap 2>/dev/null | head -1)
# Writing if the same file grew OR a newer file appeared (rotation is itself proof of writing).
capgrow=$( { [ "${s2:-0}" -gt "${s1:-0}" ] || [ "$nf2" != "$nf" ]; } && echo yes || echo no )
wait 2>/dev/null
ar=$(sudo auditctl -l 2>/dev/null | wc -l)
aact=$(systemctl is-active auditd 2>/dev/null)
a1=$(sudo wc -l < /var/log/audit/audit.log 2>/dev/null); sleep 2; a2=$(sudo wc -l < /var/log/audit/audit.log 2>/dev/null)
audgrow=$([ "${a2:-0}" -gt "${a1:-0}" ] && echo yes || echo no)
tact=$(systemctl is-active tb-telemetry 2>/dev/null)
tf=$(ls -t /var/log/testbed/telemetry_${h}_*.csv 2>/dev/null | head -1)
t1=$(stat -c%s "$tf" 2>/dev/null); sleep 2; t2=$(stat -c%s "$tf" 2>/dev/null)
telgrow=$([ "${t2:-0}" -gt "${t1:-0}" ] && echo yes || echo no)
teldev=$(sed -n 2p "$tf" 2>/dev/null | cut -d, -f1)
telcols=$(head -1 "$tf" 2>/dev/null | awk -F, '{print NF}')
echo "host=$h ref=$ref snaplen0=$cap filter=$flt capgrow=$capgrow auditrules=$ar auditactive=$aact auditgrow=$audgrow telactive=$tact telgrow=$telgrow teldev=$teldev telcols=$telcols"
VEOF
)
echo "===================== V5 PRE-FLIGHT ====================="
for n in "192.168.0.32:rpi3b1" "192.168.0.33:rpi3b2"; do
  ip=${n%:*}; vn=${n#*:}
  r=$(echo "$VCHK" | timeout 60 $SSH "$HUB" "ssh -i ~/.ssh/hub_to_victim -o BatchMode=yes -o ConnectTimeout=10 pi@$ip 'bash -s'" 2>&1)
  echo "[$vn] $r"
  echo "$r" | grep -q "host=$vn"        || { echo "  !! hostname wrong"; GO=0; }
  echo "$r" | grep -q "ref=C0A80032"    || { echo "  !! not chrony-synced to hub"; GO=0; }
  echo "$r" | grep -q "snaplen0=1"      || { echo "  !! capture not full-snaplen"; GO=0; }
  echo "$r" | grep -q "filter=1"        || { echo "  !! capture filter not active"; GO=0; }
  echo "$r" | grep -q "capgrow=yes"     || { echo "  !! capture not writing"; GO=0; }
  echo "$r" | grep -q "auditactive=active" || { echo "  !! auditd not active"; GO=0; }
  echo "$r" | grep -qE "auditrules=1[0-9]|auditrules=[2-9][0-9]" || { echo "  !! auditd rules not loaded"; GO=0; }
  echo "$r" | grep -q "auditgrow=yes"   || { echo "  !! auditd not advancing (no events)"; GO=0; }
  echo "$r" | grep -q "telactive=active"|| { echo "  !! tb-telemetry not active"; GO=0; }
  echo "$r" | grep -q "telgrow=yes"     || { echo "  !! telemetry not writing"; GO=0; }
  echo "$r" | grep -q "teldev=$vn"      || { echo "  !! telemetry device_id != $vn (stale hostname)"; GO=0; }
  echo "$r" | grep -q "telcols=$EXPECT_TEL" || { echo "  !! telemetry schema width != $EXPECT_TEL"; GO=0; }
done
echo "----- hub -----"
hr=$(timeout 30 $SSH "$HUB" '
  echo "mergecap=$(command -v mergecap >/dev/null && echo ok || echo MISSING) zeek=$(ls /opt/zeek/bin/zeek >/dev/null 2>&1 && echo ok || echo MISSING) diskfreeG=$(df -BG / | tail -1 | awk "{print \$4}" | tr -d G)"
  echo "iotbenign=$(systemctl is-active tb-iot-benign 2>/dev/null) benignhost=$(systemctl is-active tb-benign-host 2>/dev/null) iotprocs=$(pgrep -fc service_traffic.py)"
  echo "orphan_attacks=$(sudo pgrep -c -f "[h]ping3|[e]ttercap|[m]edusa|[h]ydra" 2>/dev/null || echo 0)"
' 2>&1)
echo "$hr"
echo "$hr" | grep -q "mergecap=ok" || { echo "  !! mergecap missing on hub"; GO=0; }
echo "$hr" | grep -q "zeek=ok"     || { echo "  !! zeek missing on hub"; GO=0; }
echo "$hr" | grep -q "iotbenign=active"  || { echo "  !! tb-iot-benign (benign IoT client) not active"; GO=0; }
echo "$hr" | grep -q "benignhost=active" || { echo "  !! tb-benign-host (benign SSH admin) not active"; GO=0; }
hdisk=$(echo "$hr" | grep -oE "diskfreeG=[0-9]+" | cut -d= -f2)
[ "${hdisk:-0}" -lt 10 ] && { echo "  !! hub disk < 10G (ship raw to control)"; }
echo "========================================================"
[ "$GO" = 1 ] && echo "PRE-FLIGHT: GO" || echo "PRE-FLIGHT: NO-GO (fix the !! items above)"
exit $((1-GO))
