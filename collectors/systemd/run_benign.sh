#!/bin/bash
# run_benign.sh -- always-on BENIGN BACKGROUND workload for an Objective-3 victim.
# WHY: network-dominant attacks (recon/ddos/exfil/mitm) otherwise leave almost no
# host trace, and quiescent benign leaves almost no network trace -> (a) a
# multimodal model has no host signal to fuse during net attacks, and (b) "any
# network activity" trivially separates attack from benign (the pilot's confound).
# This generates light, continuous HOST (execve/file) + NETWORK (local pings/lookups)
# activity so BOTH modalities are populated in ~every window, in benign AND during
# attacks. It is deliberately non-discriminative background, not an attack.
set -u
HUB="${TB_HUB:-192.168.0.50}"
GW="${TB_GW:-192.168.0.1}"
while true; do
  # host silo: execve churn + file reads (auditd tb_exec + baseline)
  ls -lR /etc/default >/dev/null 2>&1
  cat /proc/loadavg /proc/meminfo /etc/os-release >/dev/null 2>&1
  id >/dev/null 2>&1; uname -a >/dev/null 2>&1
  head -c 80000 /dev/zero | sha256sum >/dev/null 2>&1
  # network silo: benign flows (so benign is not network-silent)
  ping -c 1 -W 1 "$HUB" >/dev/null 2>&1
  ping -c 1 -W 1 "$GW"  >/dev/null 2>&1
  getent hosts localhost >/dev/null 2>&1
  sleep $(( RANDOM % 2 + 1 ))   # 1-2s cadence -> host+net present in ~every window
done
