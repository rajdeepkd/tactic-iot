# services/

Victim-side IoT services. These daemons make the Raspberry Pi victims behave like
real IoT devices, so that application-service logs become a genuine fourth
modality and so that protocol-specific attacks (MQTT/CoAP/Modbus/SNMP) have a
realistic target.

## Files

| File | Service |
|------|---------|
| `coap_server.py` | CoAP server (`aiocoap`). |
| `modbus_server.py` | Modbus/TCP simulated PLC (`pymodbus`), with realistic register behaviour. |
| `tactic-cmd-handler.py` | Command handler backing the unauthorized-control attack cases. |
| `mosquitto_tactic.conf` | Mosquitto (MQTT broker) config with an authenticated account for benign clients. |
| `snmpd_tactic.conf`, `snmptrapd_tactic.conf`, `snmp_setlog.py` | SNMP agent/trap config and a set-logging helper. |
| `mediamtx_tactic.yml`, `setup_rtsp.sh`, `provision_iot_services.sh` | RTSP media stream and service provisioning. |
| `systemd/` | Unit files for the CoAP, Modbus, RTSP, and command-handler services. |

## A note on credentials

The MQTT account and SNMP community strings here are **synthetic, documented lab
settings** chosen to generate labelled auth-success / auth-failure signal (the
benign client authenticates; the brute-force attack fails). They are placeholders
(`CHANGE_ME`, `public`, `tactic_rw`) and are **not** real secrets. Replace them
before using any of this outside an isolated lab.
