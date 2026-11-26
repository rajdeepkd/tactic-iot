#!/usr/bin/env bash
# record_env.sh -- capture per-device configuration metadata at campaign start.
# Directly answers P5 (telemetry was 93% an architecture/VM-image fingerprint):
# so the pipeline can treat device/arch as a controlled nuisance variable and
# verify the boards are identically configured, we record RAM, kernel, CPU
# governor, the steady-state process set, package versions, and the linkage
# manifest of the benign binaries. Written once per campaign per device.
#
# Usage: bash record_env.sh /var/log/testbed/env
set -u
OUT="${1:-/var/log/testbed/env}"
mkdir -p "$OUT"
DEV="$(hostname)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
F="$OUT/env_${DEV}_${TS}.json"
HERE="$(cd "$(dirname "$0")" && pwd)"

gov="$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)"
kern="$(uname -srvmo 2>/dev/null)"
arch="$(uname -m)"
memtotal="$(awk '/MemTotal/{print $2}' /proc/meminfo 2>/dev/null)"
model="$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo unknown)"
nproc_="$(nproc 2>/dev/null || echo 0)"
libc="$(ldd --version 2>/dev/null | head -n1)"
py="$(python3 --version 2>&1)"
# steady-state process set (names only -> compare across boards for parity)
procset="$(ps -eo comm= 2>/dev/null | sort | uniq -c | sort -rn | head -n 40 | sed 's/"/\\"/g' | awk '{printf "%s ",$0}')"
pkgs="$(dpkg -l 2>/dev/null | awk '/^ii/{print $2"="$3}' | tr '\n' ';' | head -c 4000)"

# linkage balance of the benign worker binaries (should be ~50/50)
linkage_csv="$HERE/bin/linkage_manifest.csv"
linkage="$( [ -f "$linkage_csv" ] && tr '\n' '|' < "$linkage_csv" || echo missing )"

cat > "$F" <<EOF
{
  "device_id": "${DEV}",
  "captured_utc": "${TS}",
  "model": "${model}",
  "arch": "${arch}",
  "nproc": ${nproc_:-0},
  "mem_total_kb": ${memtotal:-0},
  "kernel": "${kern}",
  "cpu_governor": "${gov}",
  "libc": "${libc}",
  "python": "${py}",
  "steady_process_set": "${procset}",
  "linkage_manifest": "${linkage}",
  "packages_head": "${pkgs}"
}
EOF
echo "[record_env] wrote $F"
