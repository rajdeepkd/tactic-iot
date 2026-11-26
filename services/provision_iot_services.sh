#!/bin/bash
# provision_iot_services.sh -- stand up the TACTIC-IoT v2 IoT services on a
# VICTIM board. Idempotent. Run as root ON the victim after copying the whole
# testbed/services/ dir to /opt/testbed/services/:
#   scp -r -i ~/.ssh/obj3_testbed testbed/services pi@192.168.0.32:/tmp/svc
#   ssh -i ~/.ssh/obj3_testbed pi@192.168.0.32 \
#       'sudo mkdir -p /opt/testbed && sudo cp -r /tmp/svc /opt/testbed/services && sudo bash /opt/testbed/services/provision_iot_services.sh'
#
# Installs MQTT (mosquitto), CoAP, Modbus, SNMP, mDNS (avahi), optional RTSP and
# telnet, then enables the always-on units. Telnet + RTSP are gated by hostname
# (telnet on rpi3b1 only; RTSP on a board with the mediamtx binary + clip).
#
# Do this while the uplink is still connected (apt needs the local mirror or
# internet). Disable wlan0 / unplug the router WAN afterwards for the captured run.
set -u
SVC=/opt/testbed/services
H="$(hostname)"
log() { echo "[provision $H] $*"; }

log "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -y >/dev/null 2>&1 || log "apt update failed (check mirror/uplink)"
apt-get install -y \
  mosquitto mosquitto-clients \
  snmp snmpd \
  avahi-daemon avahi-utils \
  python3-paho-mqtt python3-aiocoap python3-pymodbus \
  busybox ffmpeg >/dev/null 2>&1 || log "some packages failed; continuing"

# ---- MQTT broker: drop-in config, use the packaged mosquitto.service --------
if [ -f "$SVC/mosquitto_tactic.conf" ]; then
  install -D -m 0644 "$SVC/mosquitto_tactic.conf" /etc/mosquitto/conf.d/tactic.conf
  systemctl enable --now mosquitto >/dev/null 2>&1
  systemctl restart mosquitto
  log "mosquitto up on 1883 (anonymous, plaintext for Zeek)"
fi

# ---- SNMP agent -------------------------------------------------------------
if [ -f "$SVC/snmpd_tactic.conf" ]; then
  # the pass-handler that gives control_snmp_set a host footprint (see snmpd conf)
  [ -f "$SVC/snmp_setlog.py" ] && install -D -m 0755 "$SVC/snmp_setlog.py" /opt/testbed/services/snmp_setlog.py
  install -D -m 0644 "$SVC/snmpd_tactic.conf" /etc/snmp/snmpd.conf
  systemctl enable --now snmpd >/dev/null 2>&1
  systemctl restart snmpd
  log "snmpd up on 161 (ro public, scratch rw tactic_rw, pass OID set-logger)"
fi

# ---- mDNS / DNS-SD advertisements ------------------------------------------
systemctl enable --now avahi-daemon >/dev/null 2>&1
mkdir -p /etc/avahi/services
for s in mqtt:_mqtt._tcp:1883 coap:_coap._udp:5683 modbus:_modbus._tcp:502 rtsp:_rtsp._tcp:8554; do
  name="${s%%:*}"; rest="${s#*:}"; typ="${rest%%:*}"; port="${rest##*:}"
  cat > "/etc/avahi/services/tactic-$name.service" <<AV
<?xml version="1.0" standalone='no'?><!DOCTYPE service-group SYSTEM "avahi-service.dtd">
<service-group><name replace-wildcards="yes">%h $name</name>
<service><type>$typ</type><port>$port</port></service></service-group>
AV
done
systemctl restart avahi-daemon
log "avahi advertising _mqtt/_coap/_modbus/_rtsp"

# ---- our Python device servers ---------------------------------------------
for u in tb-coap tb-modbus tb-cmd-handler; do
  if [ -f "$SVC/systemd/$u.service" ]; then
    install -D -m 0644 "$SVC/systemd/$u.service" "/etc/systemd/system/$u.service"
  fi
done
systemctl daemon-reload
systemctl enable --now tb-coap tb-modbus tb-cmd-handler >/dev/null 2>&1
log "tb-coap / tb-modbus / tb-cmd-handler enabled"

# ---- RTSP (only if the mediamtx binary + clip are present) ------------------
if [ -x /opt/testbed/bin/mediamtx ] && [ -f /opt/testbed/media/clip.ts ]; then
  install -D -m 0644 "$SVC/systemd/tb-rtsp.service" /etc/systemd/system/tb-rtsp.service
  systemctl daemon-reload
  systemctl enable --now tb-rtsp >/dev/null 2>&1
  log "tb-rtsp enabled (mediamtx on 8554)"
else
  log "RTSP skipped (need /opt/testbed/bin/mediamtx + /opt/testbed/media/clip.ts)"
fi

# ---- Telnet legacy surface: rpi3b1 only ------------------------------------
if [ "$H" = "rpi3b1" ]; then
  cat > /etc/systemd/system/tb-telnetd.service <<'TN'
[Unit]
Description=TACTIC-IoT legacy telnetd (busybox, rpi3b1 only)
After=network-online.target
[Service]
ExecStart=/usr/bin/busybox telnetd -F -p 23
Restart=always
RestartSec=5
[Install]
WantedBy=multi-user.target
TN
  systemctl daemon-reload
  systemctl enable --now tb-telnetd >/dev/null 2>&1
  log "tb-telnetd enabled on 23 (legacy IoT surface)"
fi

log "listening sockets:"; ss -ltnup 2>/dev/null | grep -E ':1883|:161|:502|:5683|:8554|:23|:5353' || true
log "done. Verify benign clients connect from the hub, then run Gate B."
