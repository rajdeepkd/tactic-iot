#!/usr/bin/env python3
"""
syscall_canon.py -- canonicalise architecture-specific syscall names into ONE
vocabulary that is directly comparable to the CIC-YNU-IoTMal 2026 strace
features (the `Call_<name>` columns used by P4_pilot.py / P7_binary_controlled.py).

WHY THIS EXISTS (two distinct problems, both hit in the pilots)
---------------------------------------------------------------
1) eBPF/perf emit syscall *numbers*, not names, and the number->name map differs
   per ABI:  RPi 3B+ = aarch32 (ARM EABI table);  RPi 5 + Jetson Nano = aarch64
   (asm-generic table).  We resolve number->name with the *board's own* audit
   table via `ausyscall --dump` (see load_arch_table); that map is always correct
   for the running kernel and is captured per board by record_device_meta.sh.

2) The SAME logical call has different NAMES per ABI (the "chown/chown32,
   mmap/mmap2" alias problem from P4/P7):
       aarch32 : mmap2, fstat64, _newselect, fcntl64, chown32, _llseek, statx,
                 sendfile64, ftruncate64, geteuid32, ugetrlimit, *_time64 ...
       aarch64 : openat (no `open`), newfstatat/statx (no `stat`), pselect6
                 (no `select`), ppoll (no `poll`), the *at forms (no link/unlink/
                 rename/mkdir/chmod/chown), dup3 (no dup2), pipe2, clone3 ...
   ALIAS below folds both ABIs onto the CIC-YNU canonical base names so that
   RPi 3B+ (aarch32), RPi 5 and Jetson (aarch64) produce comparable count
   vectors, and so testbed host features drop straight into the P4/P7 pipeline.

ALIAS is a strict SUPERSET of P4_pilot.py's ALIAS (every P4 entry is kept), plus
the aarch64 asm-generic *at/no-legacy forms and the glibc-2.34+ *_time64 forms
that a modern 32-bit Raspberry Pi OS actually issues.

NOTE ON TRUNC: CIC-YNU's published strace tokens were truncated (`fc`, `mmap`,
`rt_sig`...), an artefact of their collection. eBPF/perf/strace here yield full
names, so we do NOT truncate. `--cic-compat` re-applies the CIC-YNU TRUNC drop
only when you want a maximally like-for-like comparison against their tables.
"""
import re
import shutil
import subprocess

# --- CIC-YNU pilot ALIAS (verbatim from P4_pilot.py) -----------------------
_ALIAS_P4 = {
    "chown32": "chown", "geteuid32": "geteuid", "getgid32": "getgid",
    "getuid32": "getuid", "setgid32": "setgid", "setuid32": "setuid",
    "setresuid32": "setresuid", "ugetrlimit": "getrlimit", "prlimit64": "getrlimit",
    "clock_gettime64": "clock_gettime", "syscall_0x193": "clock_gettime",
    "gettimeofday": "clock_gettime", "time": "clock_gettime",
    "clock_nanosleep_time64": "nanosleep", "fstat64": "stat", "fstatat64": "stat",
    "stat64": "stat", "lstat": "stat", "lstat64": "stat", "statx": "stat",
    "fstat": "stat", "getdents": "getdents64", "mmap2": "mmap",
    "ftruncate64": "truncate", "truncate64": "truncate", "openat": "open",
    "unlinkat": "unlink", "set_thread_area": "set_tls", "tgkill": "tkill",
    "umount2": "umount", "_llseek": "lseek", "fcntl64": "fcntl",
    "_newselect": "select", "sendfile64": "sendfile", "statfs64": "statfs",
}

# --- aarch64 asm-generic + remaining aarch32 forms not covered by P4 --------
_ALIAS_EXT = {
    # identity / uid-gid 32-bit variants (aarch32) not already in P4
    "getegid32": "getegid", "fchown32": "chown", "lchown32": "chown",
    "lchown": "chown", "setregid32": "setregid", "setreuid32": "setreuid",
    "setresgid32": "setresgid", "setfsuid32": "setfsuid", "setfsgid32": "setfsgid",
    # aarch64 has no bare open/stat/select/poll/access -- fold the *at forms
    "openat2": "open", "newfstatat": "stat", "faccessat": "access",
    "faccessat2": "access", "pselect6": "select", "pselect6_time64": "select",
    "ppoll": "poll", "ppoll_time64": "poll",
    # aarch64 *at file ops (no bare link/unlink/rename/mkdir/rmdir/symlink)
    "linkat": "link", "renameat": "rename", "renameat2": "rename",
    "mkdirat": "mkdir", "symlinkat": "symlink", "fchmodat": "chmod",
    "fchownat": "chown", "readlinkat": "readlink", "mknodat": "mknod",
    "utimensat": "utimes", "utimensat_time64": "utimes", "futimesat": "utimes",
    # aarch64 "clean" replacements for legacy multiplexed/duped calls
    "dup3": "dup2", "pipe2": "pipe", "clone3": "clone",
    "epoll_create1": "epoll_create", "epoll_pwait": "epoll_wait",
    "epoll_pwait2": "epoll_wait", "inotify_init1": "inotify_init",
    "eventfd2": "eventfd", "signalfd4": "signalfd", "getrandom": "getrandom",
    # glibc >= 2.34 time64 syscalls issued by modern 32-bit Raspberry Pi OS
    "clock_settime64": "clock_settime", "clock_getres_time64": "clock_getres",
    "timer_gettime64": "timer_gettime", "timer_settime64": "timer_settime",
    "timerfd_gettime64": "timerfd_gettime", "timerfd_settime64": "timerfd_settime",
    "futex_time64": "futex", "sched_rr_get_interval_time64": "sched_rr_get_interval",
    "mq_timedsend_time64": "mq_timedsend", "mq_timedreceive_time64": "mq_timedreceive",
    "semtimedop_time64": "semtimedop", "rt_sigtimedwait_time64": "rt_sigtimedwait",
    "recvmmsg_time64": "recvmmsg", "ppoll_time64": "poll",
    "io_pgetevents_time64": "io_pgetevents", "adjtimex": "adjtimex",
    "clock_adjtime64": "clock_adjtime", "ppoll_time32": "poll",
    # misc aarch32 <-> aarch64
    "sigreturn": "rt_sigreturn", "waitpid": "wait4", "socketcall": "socketcall",
}

ALIAS = dict(_ALIAS_P4)
ALIAS.update(_ALIAS_EXT)

# CIC-YNU truncated-token set (P4_pilot.py TRUNC) -- only used with --cic-compat
TRUNC = {"cloc", "fc", "g", "ge", "get", "getd", "gett", "getti", "gettime",
         "ioct", "na", "r", "re", "readlin", "rt_", "rt_si", "rt_sig",
         "rt_sigact", "s", "setso", "socke", "tim", "wri"}


def canon(name: str) -> str:
    """Fold one raw syscall name to its CIC-YNU canonical base."""
    if name is None:
        return "unknown"
    n = name.strip()
    # strip any perf/audit decoration like "sys_" prefix if present
    if n.startswith("sys_"):
        n = n[4:]
    return ALIAS.get(n, n)


def load_arch_table(dump_text: str) -> dict:
    """Parse `ausyscall --dump` output (one 'NN  name' per line) -> {int: name}.

    ausyscall is part of the auditd package and prints the number->name table
    for the RUNNING machine's ABI, so it is correct for aarch32 on the RPi 3B+
    and aarch64 on the RPi 5 / Jetson without us shipping per-arch tables.
    """
    table = {}
    for line in dump_text.splitlines():
        line = line.strip()
        if not line or line.lower().startswith(("known", "the ")):
            continue
        m = re.match(r"^(\d+)\s+(\S+)", line)
        if m:
            table[int(m.group(1))] = m.group(2)
    return table


def arch_table_from_host() -> dict:
    """Run `ausyscall --dump` on the local host and parse it."""
    exe = shutil.which("ausyscall")
    if not exe:
        raise RuntimeError("ausyscall not found; install auditd or pass --arch-table")
    out = subprocess.check_output([exe, "--dump"], text=True)
    return load_arch_table(out)


if __name__ == "__main__":
    # smoke test: show a few canonicalisations for both ABIs
    for s in ["mmap2", "openat", "newfstatat", "pselect6", "fcntl64",
              "clock_gettime64", "chown32", "unlinkat", "dup3", "getdents"]:
        print(f"{s:22s} -> {canon(s)}")
