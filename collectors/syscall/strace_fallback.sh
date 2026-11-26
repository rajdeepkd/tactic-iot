#!/usr/bin/env bash
# strace_fallback.sh -- LAST-RESORT syscall capture, and the CIC-YNU-FAITHFUL
# path for the execution-stage reproduction (scenario 4 contained sample).
#
# Two distinct uses:
#  (1) Fallback where neither BCC nor perf is usable on a board.
#  (2) Deliberately reproduce CIC-YNU-IoTMal's own collection method (they used
#      strace) when we run a contained malware sample once, so the testbed
#      "execution stage" is maximally comparable to the CIC-YNU baseline.
#
# strace uses ptrace and perturbs timing/telemetry, so it is NOT used for the
# always-on stream -- only for a bounded, single-process (or -f process-tree)
# capture that the windowizer parses with --format strace.
#
# -f      follow forks (whole execution tree = one "execution", like CIC-YNU Hash)
# -qq     suppress attach/detach noise
# -tt -T  wall time + syscall duration (kept for reference; windowizer ignores)
# -e trace=all   every syscall (names come out directly -> canonicalised by name)
# -o      per-execution trace file; filename encodes the exec key
#
# Usage:
#   sudo ./strace_fallback.sh /var/log/testbed/syscall/exec_<label> -- <cmd> [args...]
set -euo pipefail
OUTBASE="$1"; shift
[ "${1:-}" = "--" ] && shift
mkdir -p "$(dirname "$OUTBASE")"
HOST="$(hostname)"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${OUTBASE}_${HOST}_${TS}.strace"
echo "[strace] capturing '$*' -> $OUT" >&2
exec strace -f -qq -tt -T -e trace=all -o "$OUT" -- "$@"
