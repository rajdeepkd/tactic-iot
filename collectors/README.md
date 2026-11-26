# collectors/

On-board data collection — the sensors that record the four modalities on each
victim board. These run as systemd services under the one-master-clock design so
that every record is timestamped against the same reference.

## Layout

| Path | Modality / role |
|------|-----------------|
| `audit/` | auditd rule sets and installer (host audit events). |
| `hostlog/` | Host-log parsers and shippers: `auditlog_parser.py`, `authlog_shipper.py`, `applog_features.py`, journald config. |
| `syscall/` | Syscall collection with graceful fallback: eBPF/BCC collector (`syscall_ebpf_collector.py`), `perf` capture, and `strace` fallback, plus canonicalisation (`syscall_canon.py`) and windowing (`syscall_windowizer.py`). |
| `telemetry_reader.py`, `telemetry.service` | Resource telemetry (CPU/memory/process stats via `psutil`). |
| `ship/` | Log/capture shipping to the hub (`log_puller.py` pull model, `ship.sh` push model). |
| `meta/` | Per-device metadata recorder (kernel, board, capabilities). |
| `sync_beacon.py` | Emits a timing beacon used to validate cross-board clock alignment. |
| `bench_capture.sh`, `tb_health.sh` | Capture benchmark and a board health check. |
| `provision_node.sh` | One-shot provisioning of a collecting board. |
| `systemd/` | The unit/timer files and installers (`install_collectors.sh`, `install_services.sh`) that run everything on each board. `testbed.env` selects the right syscall collector per board. |

## Notes

- The syscall collector auto-selects per board: eBPF (BCC) where the kernel
  supports it (e.g. RPi 5), `perf` where it does not (e.g. older Jetson kernels).
  Select the command in `systemd/testbed.env`.
- These collectors require root and are meant to run **on the victim boards**, not
  on the analyst's machine. System packages (`auditd`, `bcc`, `zeek`, `tcpdump`,
  `chrony`, `linux-perf`) must be installed on the boards; see the root
  `requirements.txt`.
