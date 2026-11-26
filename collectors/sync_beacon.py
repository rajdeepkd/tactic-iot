#!/usr/bin/env python3
"""
sync_beacon.py -- cross-modal time fiducial (DEFENSIVE INSTRUMENTATION ONLY).

Runs ON a victim board (invoked by the orchestrator over SSH, or on a systemd
timer). Each beacon deliberately leaves ONE coincident mark in all three
modalities so alignment error can be measured per (board, modality) directly,
instead of only inferred by cross-correlation:

  host      : one journald line  tag=SYNCBEACON  (journald stamps realtime +
              monotonic + boot_id itself -> our reference clock triple)
  network   : ONE small UDP datagram to a fixed marker port, magic payload,
              so Zeek/pcap on the same box records a uniquely findable packet
  telemetry : a bounded, fixed-duration CPU spin (default 200 ms) -> a blip in
              cpu_pct/temp visible to telemetry_reader.py

None of this is attack behaviour: it is one log line, one datagram, and one
short busy-loop. It emits its own high-resolution emit-time (the ground truth),
prints a JSON receipt on stdout for the orchestrator to collect, and exits.

Usage (on the board):
  python3 sync_beacon.py --seq 7 --udp 10.0.0.1:52525 --spin-ms 200 --tag SYNCBEACON
"""
import argparse, json, os, socket, subprocess, sys, time, uuid

MAGIC = b"O3-SYNCBEACON\x00"   # 14-byte prefix -> trivially greppable in pcap


def clock_triple():
    """(realtime_ns UTC, monotonic_ns, boot_id) -- the same triple every
    collector logs, so residuals are computed on a common basis."""
    real = time.clock_gettime_ns(time.CLOCK_REALTIME)
    mono = time.clock_gettime_ns(time.CLOCK_MONOTONIC)
    try:
        boot_id = open("/proc/sys/kernel/random/boot_id").read().strip()
    except OSError:
        boot_id = ""
    return real, mono, boot_id


def busy_spin(ms):
    """Fixed-duration CPU burst using MONOTONIC (immune to any clock slew)."""
    end = time.monotonic_ns() + ms * 1_000_000
    x = 0
    while time.monotonic_ns() < end:
        x = (x * 1_103_515_245 + 12_345) & 0x7FFFFFFF
    return x


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seq", type=int, required=True, help="beacon sequence no.")
    ap.add_argument("--udp", default="", help="host:port for the marker datagram")
    ap.add_argument("--spin-ms", type=int, default=200, help="telemetry-blip duration")
    ap.add_argument("--tag", default="SYNCBEACON", help="journald syslog tag")
    ap.add_argument("--run-id", default="", help="capture/run id for provenance")
    a = ap.parse_args()

    bid = uuid.uuid4().hex[:12]           # per-beacon id, appears in every modality
    device_id = socket.gethostname()

    # --- emit time is taken as close to the marks as possible ---------------
    real, mono, boot_id = clock_triple()
    payload = {"beacon": bid, "seq": a.seq, "device_id": device_id,
               "emit_real_ns": real, "emit_mono_ns": mono, "boot_id": boot_id,
               "run_id": a.run_id}

    # (1) HOST mark: journald carries its own realtime/monotonic/boot_id.
    subprocess.run(["logger", "-t", a.tag, json.dumps(payload)], check=False)

    # (2) NETWORK mark: exactly one datagram, magic prefix + JSON.
    if a.udp:
        host, _, port = a.udp.partition(":")
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(MAGIC + json.dumps(payload).encode(), (host, int(port)))
            s.close()
        except OSError as e:
            payload["udp_error"] = str(e)

    # (3) TELEMETRY mark: bounded CPU spin.
    busy_spin(a.spin_ms)
    end_real, end_mono, _ = clock_triple()
    payload["spin_end_real_ns"] = end_real
    payload["spin_end_mono_ns"] = end_mono

    # receipt for the orchestrator / validate_alignment.py (ground truth times)
    print(json.dumps(payload))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
