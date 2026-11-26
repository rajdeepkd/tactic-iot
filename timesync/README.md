# timesync/

Time synchronisation for the one-master-clock design. Every board disciplines its
clock to a single reference so that records from the four modalities, captured on
different hosts, can be aligned onto a common one-second grid and labelled against
the orchestrator's timeline.

| File | Role |
|------|------|
| `chrony-server.conf` | chrony config for the time master (the hub). Its disciplined `CLOCK_REALTIME` is authoritative for labelling. |
| `chrony-client.conf` | chrony config for the victim boards (slaved to the master). |
| `rsyslog-50-highprecision.conf` | High-precision (sub-second) syslog timestamp format, so host-log events carry enough resolution for one-second windowing. |
| `setup_timesync.sh` | Installs and enables the above on a board. |

Accurate time sync is a prerequisite for correct window alignment; run this before
collecting.
