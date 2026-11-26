#!/bin/bash
# run_iot_benign.sh -- always-on benign IoT CLIENT, runs ON THE HUB (the operator).
# Generates continuous legitimate MQTT/CoAP/Modbus/SNMP(/RTSP) client traffic to
# EACH victim, INCLUDING occasional legitimate control operations (a command on
# iot/<dev>/cmd, a Modbus register write, an SNMP SET of the vendor config OID, a
# CoAP actuator PUT). This is what makes the unauthorized_control classes a real
# multimodal problem: benign windows also contain control ops, so no single silo
# separates attack from benign on control-PRESENCE -- only the attack's burst rate,
# co-occurring stage activity, and the ground-truth label do.
#
# Supervised by tb-iot-benign.service (systemd). This script itself restarts any
# individual loop that dies, and forwards SIGTERM to all children on stop.
set -u
ST=/opt/testbed/benign/service_traffic.py
PY=python3
# victim roster: name:ip  (the hub is the client; these are the device targets)
VICTIMS="rpi3b1:192.168.0.32 rpi3b2:192.168.0.33"
# Synthetic lab MQTT account for the AUTHENTICATED broker. Benign clients present
# these valid credentials -> the broker logs auth SUCCESS; the bruteforce_mqtt attack
# sends wrong credentials -> auth FAILURE. These are placeholders: set a real synthetic
# password for your own testbed via the environment (MQTT_BENIGN_USER / MQTT_BENIGN_PW).
MQTT_USER="${MQTT_BENIGN_USER:-iotuser}"
MQTT_PW="${MQTT_BENIGN_PW:-CHANGE_ME}"

declare -A CMD PID
reg() { CMD["$1"]="$2"; }                       # register a loop command by key
spawn() { local k="$1"; eval "${CMD[$k]}" >/dev/null 2>&1 & PID[$k]=$!; }

for v in $VICTIMS; do
  vn="${v%%:*}"; vip="${v##*:}"
  reg "mqtt-$vn"   "$PY $ST --proto mqtt   --broker $vip --devname $vn --interval 15 --control-every 12 --username $MQTT_USER --password $MQTT_PW"
  reg "coap-$vn"   "$PY $ST --proto coap   --host   $vip --devname $vn --interval 18 --control-every 15"
  reg "modbus-$vn" "$PY $ST --proto modbus --host   $vip --devname $vn --interval 12 --control-every 14"
  # SNMP omitted from the dataset (net-snmp v2c gives no agent app-log signal).
  # RTSP pull only if the victim actually serves it on 8554
  if timeout 3 bash -c "exec 3<>/dev/tcp/$vip/8554" 2>/dev/null; then
    reg "rtsp-$vn" "$PY $ST --proto rtsp --url rtsp://$vip:8554/stream1 --interval 30"
  fi
done

cleanup() { for p in "${PID[@]:-}"; do kill "$p" 2>/dev/null; done; exit 0; }
trap cleanup TERM INT

for k in "${!CMD[@]}"; do spawn "$k"; done
echo "[iot-benign] launched ${#PID[@]} loops: ${!CMD[*]}"

# supervise: restart any dead loop
while true; do
  sleep 10
  for k in "${!CMD[@]}"; do
    if ! kill -0 "${PID[$k]}" 2>/dev/null; then
      echo "[iot-benign] restarting $k"
      spawn "$k"
    fi
  done
done
