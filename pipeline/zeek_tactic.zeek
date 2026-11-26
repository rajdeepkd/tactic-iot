# zeek_tactic.zeek -- TACTIC-IoT v2 Zeek load script for offline pcap analysis on
# the hub. Pass it to zeek after the pcap:
#     zeek -C -r cap_<dev>_<ts>.pcap /opt/testbed/pipeline/zeek_tactic.zeek
#
# conn/ssh/dns/http/weird are produced by Zeek's defaults. The MQTT analyzer only
# WRITES its logs when its policy is loaded, so load it here. The Modbus and SNMP
# analyzers log by default on their standard ports (502, 161), so no extra load is
# needed for modbus.log / snmp.log. CoAP has no Zeek analyzer and is extracted from
# the pcap with tshark in harvest.sh (coap.<dev>.csv).
#
# Anti-identity (P7) is enforced downstream in align_windows.py, which keeps only
# behavioural counters from these logs and drops every identity string (topics,
# OIDs, register values, client ids).

# Zeek 9.0 ships the MQTT, Modbus and SNMP analyzers in base/ (auto-loaded), not
# policy/. Loading the base path explicitly is a no-op if already loaded and keeps
# the intent clear. The old policy/protocols/mqtt path does not exist in 9.0 and
# aborts with a fatal error, so do not use it.
@load base/protocols/mqtt
@load base/protocols/modbus
@load base/protocols/snmp

# If a future capture moves a service off its standard port, register the port
# here so DPD still binds the analyzer, e.g.:
# const mqtt_ports: set[port] = { 1883/tcp } &redef;
