#!/usr/bin/env bash
# perf_to_ndjson.sh -- convert a rolled perf.data (from syscall_perf_capture.sh)
# into the SAME NDJSON schema that syscall_ebpf_collector.py emits, so the
# windowizer is source-agnostic.
#
# perf script prints, per event:
#   <comm> <pid>/<tid> <cpu> <timestamp> raw_syscalls:sys_enter: NR 0xID ...
# We pull comm, tid(pid), tgid(pid field), the monotonic-ish perf timestamp, and
# the syscall id. perf does not expose task->start_time, so the execution key
# falls back to (tgid, first-seen-ts bucket); this is coarser than the eBPF key
# but still groups by process for the P7(c) anti-leakage split.
#
# Usage: ./perf_to_ndjson.sh perf_jetson_20260927.data.2026... > out.ndjson
set -euo pipefail
DATA="$1"
HOST="$(hostname)"
# mono<->real offset (perf ts is CLOCK_MONOTONIC by default on modern perf)
REAL0="$(date -u +%s.%N)"; MONO0="$(cat /proc/uptime | awk '{print $1}')"

perf script -i "$DATA" -F comm,pid,tid,time,event,trace 2>/dev/null | \
awk -v host="$HOST" -v real0="$REAL0" -v mono0="$MONO0" '
/raw_syscalls:sys_enter/ {
    comm=$1;
    # pid/tid token like 1234/1240
    split($2, a, "/"); tgid=a[1]; tid=(a[2]!=""?a[2]:a[1]);
    # timestamp token ends with ":"
    ts=$3; gsub(/:$/,"",ts);
    # syscall id: find "id:" or the NR after the event name; perf prints
    #   ... raw_syscalls:sys_enter: NR 221 ...   -> grab the integer after NR
    id="";
    for (i=1;i<=NF;i++){ if ($i=="NR" && (i+1)<=NF){ id=$(i+1); break } }
    if (id=="") next;
    tsreal = real0 + (ts - mono0);
    printf "{\"device_id\":\"%s\",\"ts_mono\":%s,\"ts_real\":%.6f,\"tgid\":%s,\"pid\":%s,\"comm\":\"%s\",\"syscall_id\":%s}\n",
           host, ts, tsreal, tgid, tid, comm, id;
}'
