# benign/

Benign-activity generators. These produce the normal-behaviour baseline that runs
alongside (and between) attacks, so the dataset is not a pile of attacks with an
artificially quiet "normal" class. Benign traffic exercises the same authenticated
IoT services the attacks target.

## Files

| File | Role |
|------|------|
| `benignd.py`, `systemd/benignd.service` | Benign activity daemon and its unit. |
| `service_traffic.py` | Client traffic to the live services (MQTT publish/subscribe, HTTP health, RTSP pull, Modbus reads). |
| `run_iot_benign.sh`, `systemd/tb-iot-benign.service` | Launcher that registers per-victim benign IoT clients. |
| `admin_session.py`, `admin_driver.py`, `benign_host_v3.sh` | Scripted benign SSH/Telnet admin sessions, including a realistic "fat-finger" model that produces occasional benign failed-auth events (distinct from a brute-force flood). |
| `discovery.py`, `discovery_inventory.yaml` | Benign service discovery across the inventory. |
| `backup_xfer.py` | Benign backup/file-transfer activity. |
| `cron/` | Scheduled benign maintenance (local apt mirror update, housekeeping). |
| `bin/` | A small CPU/IO worker in C and Go (`worker.c`, `worker.go`, `Makefile`, `run_worker.sh`) for benign host load. |
| `workloads.yaml` | Declarative benign workload mix and the host/network signals each neutralises. |
| `record_env.sh` | Records the benign environment for provenance. |

## Notes

- MQTT credentials default to a `CHANGE_ME` placeholder; set `MQTT_BENIGN_USER` /
  `MQTT_BENIGN_PW` in the environment to your own synthetic lab values.
- `creds.yaml.template` shows the expected (synthetic) credential layout for the
  scripted admin sessions. Copy it to `creds.yaml` (git-ignored) and fill in lab
  values; never commit real credentials.
