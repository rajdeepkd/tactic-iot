#!/usr/bin/env bash
# run_worker.sh <linkage> <health_host> <health_port>
# Launch the requested-linkage worker twin (C first, Go as a second toolchain
# variant, chosen at random within the linkage). Also runs a matching coreutils
# vs busybox command so the SHELL side of process-churn is linkage-balanced too:
#   dynamic -> GNU coreutils (glibc, dynamic)
#   static  -> busybox       (single static musl binary)
# Both do the same ls|grep|sort|wc pipeline, so the syscall churn is identical
# and only the linkage differs -- neutralising the P7 loader-signature shortcut.
set -u
LINKAGE="${1:-dynamic}"
HOST="${2:-127.0.0.1}"
PORT="${3:-8080}"
HERE="$(cd "$(dirname "$0")" && pwd)"

# --- pick the compiled worker twin for this linkage ---
declare -a CANDIDATES
if [ "$LINKAGE" = "static" ]; then
  CANDIDATES=("worker-musl-static" "go-worker-static")
else
  CANDIDATES=("worker-glibc-dynamic" "go-worker-dynamic")
fi
BIN=""
for c in "${CANDIDATES[@]}"; do
  if [ -x "$HERE/$c" ]; then BIN="$HERE/$c"; break; fi
done
if [ -n "$BIN" ]; then
  "$BIN" "$HOST" "$PORT" || true
else
  echo "run_worker: no $LINKAGE worker built (run 'make' in $HERE)" >&2
fi

# --- linkage-balanced shell pipeline (coreutils vs busybox) ---
TMPD="$(mktemp -d)"
seq 1 200 | awk '{print $1, $1*7 % 13}' > "$TMPD/data" 2>/dev/null || true
if [ "$LINKAGE" = "static" ] && command -v busybox >/dev/null 2>&1; then
  busybox ls -l "$TMPD" | busybox grep data | busybox sort | busybox wc -l >/dev/null 2>&1 || true
  busybox cat "$TMPD/data" | busybox sort -n | busybox uniq | busybox wc -l >/dev/null 2>&1 || true
else
  ls -l "$TMPD" | grep data | sort | wc -l >/dev/null 2>&1 || true
  cat "$TMPD/data" | sort -n | uniq | wc -l >/dev/null 2>&1 || true
fi
rm -rf "$TMPD" 2>/dev/null || true
