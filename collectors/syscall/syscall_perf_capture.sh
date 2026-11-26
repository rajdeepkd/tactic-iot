#!/usr/bin/env bash
# syscall_perf_capture.sh -- portable syscall-event capture using perf's
# raw_syscalls:sys_enter tracepoint. This is the FALLBACK for boards where BCC
# will not build -- notably the Jetson Nano (L4T Linux 4.9: has the tracepoint
# and perf ring buffer, but no BPF ringbuf/CO-RE, and old BCC packages).
#
# perf uses a kernel ring buffer (NOT ptrace), so overhead is far below strace.
# We rotate the capture with --switch-output so an always-on service produces a
# stream of bounded perf.data files; perf_to_ndjson.sh converts each rolled file
# to the same NDJSON schema the eBPF collector emits, then the windowizer treats
# both identically.
#
# Usage:
#   sudo ./syscall_perf_capture.sh /var/log/testbed/syscall
set -euo pipefail
OUT="${1:-/var/log/testbed/syscall}"
mkdir -p "$OUT"
HOST="$(hostname)"
DAY="$(date -u +%Y%m%d)"
# -a system-wide; -T timestamps; switch to a new file every 128 MiB.
# --exclude-perf drops perf's own samples. We keep only the enter tracepoint;
# the id field is the (per-ABI) syscall number, resolved later by the windowizer.
exec perf record -a -T --exclude-perf \
    -e raw_syscalls:sys_enter \
    --switch-output=128M \
    -o "$OUT/perf_${HOST}_${DAY}.data"
