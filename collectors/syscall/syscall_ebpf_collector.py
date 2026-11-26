#!/usr/bin/env python3
"""
syscall_ebpf_collector.py -- always-on, low-overhead system-call *event* stream
via eBPF (BCC), attached to the raw_syscalls:sys_enter tracepoint.

This is the EFFICIENT replacement for strace (no ptrace stop/continue per call).
It emits one NDJSON record per syscall entry:

    {"device_id","ts_iso","ts_mono","tgid","pid","ppid","comm","exe_start_ns",
     "syscall_id"}

`syscall_id` is a NUMBER (per-ABI); syscall_windowizer.py resolves it to a name
with the board's own `ausyscall --dump` table and canonicalises it. exe_start_ns
(task->start_time) + tgid form the stable execution key used to GROUP windows
(prevents the P7(c) window-level train/test leakage).

Timestamps: ts_mono comes from bpf_ktime_get_ns (CLOCK_MONOTONIC, the same clock
telemetry_reader.py stamps); ts_iso is CLOCK_REALTIME (chrony-synced) taken in
userspace with a one-time mono<->real offset so every source aligns on the
orchestrator clock.

PORTABILITY: uses BPF_PERF_OUTPUT (perf ring), NOT BPF_RINGBUF, so it also runs
on the Jetson Nano's Linux 4.9. Uses bpf_probe_read (not the CO-RE _kernel
variant) for the same reason. Prefer this on RPi 5 (kernel 6.x, BTF); on the
Jetson (4.9) prefer syscall_perf_capture.sh if BCC will not build there.

Requires: python3-bpfcc (Debian: `apt install bpfcc-tools python3-bpfcc`) and
matching kernel headers. Run as root / CAP_BPF+CAP_PERFMON (see systemd unit).

Usage:
  sudo python3 syscall_ebpf_collector.py --out /var/log/testbed/syscall --rotate-mb 128
"""
import argparse, json, os, socket, time, ctypes
from datetime import datetime, timezone

DEVICE_ID = socket.gethostname()

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct evt_t {
    u64 ts_mono;      // bpf_ktime_get_ns (CLOCK_MONOTONIC)
    u64 exe_start_ns; // task->start_time -> stable per-execution key
    u32 tgid;         // thread-group id (== userspace PID)
    u32 pid;          // kernel pid (thread id)
    u32 ppid;         // parent tgid
    u32 syscall_id;   // raw syscall number (per-ABI)
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(raw_syscalls, sys_enter) {
    struct evt_t e = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    e.tgid = pid_tgid >> 32;
    e.pid  = pid_tgid & 0xffffffff;

    // drop our own tracer so it never appears in the dataset
    if (e.tgid == OWN_TGID) { return 0; }

    e.ts_mono     = bpf_ktime_get_ns();
    e.syscall_id  = (u32)args->id;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    e.exe_start_ns = task->start_time;
    struct task_struct *parent = NULL;
    bpf_probe_read(&parent, sizeof(parent), &task->real_parent);
    if (parent) {
        bpf_probe_read(&e.ppid, sizeof(e.ppid), &parent->tgid);
    }
    bpf_get_current_comm(&e.comm, sizeof(e.comm));
    events.perf_submit(args, &e, sizeof(e));
    return 0;
}
"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="/var/log/testbed/syscall")
    ap.add_argument("--rotate-mb", type=int, default=128,
                    help="roll the NDJSON file when it exceeds this size")
    args = ap.parse_args()

    from bcc import BPF  # imported here so --help works without BCC

    os.makedirs(args.out, exist_ok=True)
    own = os.getpid()
    text = BPF_TEXT.replace("OWN_TGID", str(own))
    b = BPF(text=text)

    # one-time offset so we can turn the per-event monotonic ns into wall-clock
    real0 = time.time()
    mono0 = time.monotonic()

    state = {"fh": None, "path": None, "day": None, "bytes": 0, "idx": 0}

    def roll():
        if state["fh"]:
            state["fh"].close()
        day = datetime.now(timezone.utc).strftime("%Y%m%d")
        state["idx"] = state["idx"] + 1 if state["day"] == day else 0
        state["day"] = day
        p = os.path.join(args.out,
                         f"syscalls_{DEVICE_ID}_{day}_{state['idx']:03d}.ndjson")
        state["fh"] = open(p, "a", buffering=1)
        state["path"] = p
        state["bytes"] = os.path.getsize(p) if os.path.exists(p) else 0
        print(f"[syscall] writing {p}", flush=True)

    roll()

    def handle(cpu, data, size):
        e = b["events"].event(data)
        ts_real = real0 + (e.ts_mono / 1e9 - mono0)
        rec = {
            "device_id": DEVICE_ID,
            "ts_iso": datetime.fromtimestamp(ts_real, timezone.utc).isoformat(),
            "ts_mono": round(e.ts_mono / 1e9, 6),
            "tgid": e.tgid, "pid": e.pid, "ppid": e.ppid,
            "comm": e.comm.decode("utf-8", "replace"),
            "exe_start_ns": e.exe_start_ns,
            "syscall_id": e.syscall_id,
        }
        line = json.dumps(rec, separators=(",", ":")) + "\n"
        state["fh"].write(line)
        state["bytes"] += len(line)
        if state["bytes"] >= args.rotate_mb * 1024 * 1024:
            roll()

    b["events"].open_perf_buffer(handle, page_cnt=256)
    print(f"[syscall] device={DEVICE_ID} own_tgid={own} tracepoint=raw_syscalls:sys_enter",
          flush=True)
    while True:
        try:
            b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()
