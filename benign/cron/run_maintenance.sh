#!/usr/bin/env bash
# run_maintenance.sh -- benign periodic maintenance that fork/exec/exits MANY
# short-lived helpers and polls, reproducing the process-churn + select/poll
# syscall profile that (in CIC-YNU) only the BENIGN class had. Running it in
# BOTH the benign campaign AND alongside malware makes exit_group / wait4 /
# clone / _newselect counts non-diagnostic (P7).
#
# Everything here is ordinary housekeeping: log rotation, a log-parse pipeline,
# a health report, a checksum sweep. No network egress beyond the lab.
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
LOGDIR="${TESTBED_LOG:-/var/log/testbed}"
WORKDIR="$(mktemp -d)"

# 1) log-parse pipeline (spawns grep/awk/sort/uniq/wc -> churn + pipes)
for f in "$LOGDIR"/*.log /var/log/syslog /var/log/auth.log; do
  [ -r "$f" ] || continue
  grep -aE 'error|warn|fail' "$f" 2>/dev/null | awk '{print $1,$2,$3}' \
    | sort | uniq -c | sort -rn | head -n 20 > "$WORKDIR/report_$(basename "$f").txt" 2>/dev/null || true
done

# 2) logrotate dry-run (reads config, forks helpers)
if command -v logrotate >/dev/null 2>&1; then
  logrotate -d /etc/logrotate.conf >/dev/null 2>&1 || true
fi

# 3) checksum sweep over a data dir (open/read/close churn + mmap)
DATA="${TESTBED_DATA:-/var/lib/testbed/data}"
if [ -d "$DATA" ]; then
  find "$DATA" -type f 2>/dev/null | head -n 200 | while read -r p; do
    sha256sum "$p" >/dev/null 2>&1 || true
  done
fi

# 4) short health report (many small exec's, like an admin one-liner)
{
  uptime
  df -h / 2>/dev/null
  free -m 2>/dev/null
  ps -eo pid,comm,%cpu --sort=-%cpu 2>/dev/null | head -n 10
  ss -s 2>/dev/null
} > "$WORKDIR/health.txt" 2>/dev/null || true

# 5) exercise the compiled worker twins (both linkages) if present
if [ -x "$HERE/../bin/run_worker.sh" ]; then
  "$HERE/../bin/run_worker.sh" dynamic 127.0.0.1 8080 || true
  "$HERE/../bin/run_worker.sh" static  127.0.0.1 8080 || true
fi

rm -rf "$WORKDIR" 2>/dev/null || true
