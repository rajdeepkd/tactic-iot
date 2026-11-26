#!/usr/bin/env bash
# record_device_meta.sh -- capture the per-device CONFIGURATION metadata that
# pilot P5 proved we must control. On CIC-YNU, telemetry was ~93% an
# architecture/VM-image fingerprint (different RAM, kernel, process set per
# arch), NOT a behavioural signal. To stop that confound here we (a) run on
# identically configured boards where possible, and (b) RECORD the config as
# metadata so any residual per-device offset is a known nuisance variable, and
# we (c) tie the run to a per-device benign baseline captured in the SAME
# campaign (--baseline).
#
# It ALSO saves `ausyscall --dump` (the ABI number->name table) that
# syscall_windowizer.py needs to resolve eBPF/perf syscall numbers for THIS
# board -- so meta collection and canonicalisation are wired together.
#
# Usage:
#   sudo ./record_device_meta.sh /var/log/testbed/meta            # snapshot now
#   sudo ./record_device_meta.sh /var/log/testbed/meta --baseline 120  # + 120s idle telemetry baseline
set -euo pipefail
OUT="${1:-/var/log/testbed/meta}"
mkdir -p "$OUT"
HOST="$(hostname)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
JSON="$OUT/meta_${HOST}_${TS}.json"

kv() { printf '  "%s": %s,\n' "$1" "$2"; }
jstr() { python3 -c 'import json,sys;print(json.dumps(sys.stdin.read()))'; }

# save the ABI syscall table for the windowizer (idempotent, stable per board)
if command -v ausyscall >/dev/null 2>&1; then
  ausyscall --dump > "$OUT/ausyscall_${HOST}.txt" || true
fi

{
  echo "{"
  kv device_id "\"$HOST\""
  kv ts_iso "\"$(date -u +%Y-%m-%dT%H:%M:%S%z)\""
  kv machine "\"$(uname -m)\""
  kv kernel "\"$(uname -r)\""
  kv uname "$(uname -a | jstr)"
  kv os_release "$( (cat /etc/os-release 2>/dev/null || echo) | jstr)"
  kv mem_total_kb "$(awk '/MemTotal/{print $2}' /proc/meminfo)"
  kv cpuinfo "$( (grep -m1 -E 'model name|Model|Hardware' /proc/cpuinfo 2>/dev/null || echo) | jstr)"
  kv ncpu "$(nproc)"
  kv governor "$( (cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo none) | jstr)"
  kv cgroup_version "$( ([ -f /sys/fs/cgroup/cgroup.controllers ] && echo v2 || echo v1) | jstr)"
  kv btf_present "$( ([ -f /sys/kernel/btf/vmlinux ] && echo yes || echo no) | jstr)"
  # tool availability drives which syscall collector the systemd unit selects
  kv has_bcc "$(command -v python3-bcc >/dev/null 2>&1 || python3 -c 'import bcc' 2>/dev/null && echo true || echo false)"
  kv has_bpftrace "$(command -v bpftrace >/dev/null 2>&1 && echo true || echo false)"
  kv has_perf "$(command -v perf >/dev/null 2>&1 && echo true || echo false)"
  kv has_strace "$(command -v strace >/dev/null 2>&1 && echo true || echo false)"
  kv auditd_ver "$( (auditctl -v 2>/dev/null || echo) | jstr)"
  kv audit_rules "$( (auditctl -l 2>/dev/null || echo) | jstr)"
  kv audit_status "$( (auditctl -s 2>/dev/null || echo) | jstr)"
  kv chrony_tracking "$( (chronyc tracking 2>/dev/null || echo) | jstr)"
  kv sshd_config_sha256 "\"$(sha256sum /etc/ssh/sshd_config 2>/dev/null | awk '{print $1}')\""
  kv pkg_versions "$( (dpkg -l auditd bpfcc-tools bpftrace linux-perf strace chrony python3-psutil 2>/dev/null | awk '/^ii/{print $2"="$3}' || echo) | jstr)"
  # the "running process set" P5 flagged as a per-image confound
  kv process_set "$( (ps -eo comm= | sort | uniq -c | sort -rn | head -80) | jstr)"
  kv nprocs "$(ls -d /proc/[0-9]* | wc -l)"
  kv running_units "$( (systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null | awk '{print $1}') | jstr)"
  echo "  \"_end\": true"
  echo "}"
} > "$JSON"
echo "[meta] wrote $JSON"
echo "[meta] wrote $OUT/ausyscall_${HOST}.txt (ABI table for the windowizer)"

# optional per-device benign baseline: N seconds of telemetry with the box idle,
# captured in THIS campaign so telemetry can be per-device baseline-corrected
if [ "${2:-}" = "--baseline" ]; then
  SECS="${3:-120}"
  echo "[meta] recording ${SECS}s idle benign telemetry baseline..."
  timeout "$SECS" python3 "$(dirname "$0")/../telemetry_reader.py" \
      --out "$OUT/baseline_${HOST}_${TS}" --hz 1 || true
  echo "[meta] baseline -> $OUT/baseline_${HOST}_${TS}"
fi
