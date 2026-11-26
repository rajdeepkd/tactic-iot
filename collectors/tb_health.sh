#!/bin/bash
# tb_health.sh -- runs ON a victim; prints the age (seconds) of the newest file for
# each of the four modalities, e.g. "net:2 tel:0 host:1 app:4". NONE = no file.
# Used by the v3 collection driver's per-run health check (deployed to /opt/testbed).
N=$(date +%s)
age(){ local p; p=$(ls -t $1 2>/dev/null | head -1)
  if [ -z "$p" ]; then echo -n "$2:NONE "; else echo -n "$2:$((N-$(sudo stat -c%Y "$p" 2>/dev/null || stat -c%Y "$p"))) "; fi; }
age '/var/log/testbed/cap_*.pcap' net
age '/var/log/testbed/telemetry_*.csv' tel
age '/var/log/audit/audit.log' host
age '/var/log/mosquitto/mosquitto.log' app
echo
