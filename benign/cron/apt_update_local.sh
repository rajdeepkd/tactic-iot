#!/usr/bin/env bash
# apt_update_local.sh <mirror_ip> -- benign package-update check against the
# AIR-GAPPED LOCAL mirror on the hub (no internet). Reproduces the delivery-stage
# network+host footprint of a real update: HTTP(S) fetch of index/package files,
# dpkg/apt spawning many helper processes, file writes under /var. Makes
# "download + new files + process spawn == malicious delivery" ambiguous.
#
# Set up the mirror once on the hub (e.g. apt-mirror or a plain http dir of
# .deb + Packages.gz) and point sources.list at it. This script only READS.
set -u
MIRROR="${1:-127.0.0.1}"

# Prefer a dedicated sources file that points at the local mirror, so the real
# system sources are untouched and there is zero egress risk.
LOCAL_SRC="/etc/apt/sources.list.d/testbed-local-mirror.list"
if [ -f "$LOCAL_SRC" ]; then
  sudo apt-get -o Dir::Etc::sourcelist="$LOCAL_SRC" \
               -o Dir::Etc::sourceparts="/dev/null" \
               -o APT::Get::List-Cleanup="0" update >/dev/null 2>&1 || true
  # simulate-only upgrade: resolves deps, spawns dpkg helpers, installs nothing
  sudo apt-get -s upgrade >/dev/null 2>&1 || true
else
  # Fallback: plain HTTP fetch of the mirror index (still delivery-shaped traffic)
  if command -v wget >/dev/null 2>&1; then
    wget -q -O /dev/null "http://${MIRROR}/mirror/dists/stable/Release" || true
    wget -q -O /dev/null "http://${MIRROR}/mirror/dists/stable/main/binary-$(dpkg --print-architecture 2>/dev/null)/Packages.gz" || true
  else
    curl -fsS -o /dev/null "http://${MIRROR}/mirror/dists/stable/Release" || true
  fi
fi
