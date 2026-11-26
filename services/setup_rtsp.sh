#!/bin/bash
# setup_rtsp.sh -- self-contained RTSP camera provisioning for a TACTIC-IoT v2
# victim. scp this file to the victim and run it with sudo. It downloads the
# mediamtx static binary for the local arch, writes the config + systemd unit
# INLINE (no dependency on a pre-deployed /opt/testbed/services tree), encodes a
# looped clip, and enables tb-rtsp. Idempotent: safe to re-run.
set -e
MMVER=v1.21.3
case "$(uname -m)" in
  aarch64) ARCH=arm64 ;;
  armv7l)  ARCH=armv7 ;;
  armv6l)  ARCH=armv6 ;;
  *) echo "unknown arch $(uname -m)"; exit 1 ;;
esac

mkdir -p /opt/testbed/bin /opt/testbed/media /opt/testbed/services

# --- 1. mediamtx binary --------------------------------------------------------
if [ ! -x /opt/testbed/bin/mediamtx ]; then
  URL="https://github.com/bluenviron/mediamtx/releases/download/${MMVER}/mediamtx_${MMVER}_linux_${ARCH}.tar.gz"
  echo "downloading $URL"
  curl -sL "$URL" -o /tmp/mediamtx.tgz
  file /tmp/mediamtx.tgz | grep -q gzip || { echo "download is not a tarball:"; head -c 200 /tmp/mediamtx.tgz; echo; exit 1; }
  tar xzf /tmp/mediamtx.tgz -C /tmp mediamtx
  install -m 0755 /tmp/mediamtx /opt/testbed/bin/mediamtx
  echo "installed mediamtx -> /opt/testbed/bin/mediamtx"
else
  echo "mediamtx already present, skipping download"
fi

# --- 2. looped clip (encode once) ---------------------------------------------
if [ ! -s /opt/testbed/media/clip.ts ]; then
  echo "encoding clip.ts ..."
  ffmpeg -y -f lavfi -i testsrc=size=640x360:rate=15 -t 20 -c:v libx264 -preset ultrafast -b:v 300k -f mpegts /opt/testbed/media/clip.ts >/dev/null 2>&1
  echo "encoded /opt/testbed/media/clip.ts"
else
  echo "clip.ts already present, skipping encode"
fi

# --- 3. config (inline) --------------------------------------------------------
cat > /opt/testbed/services/mediamtx_tactic.yml <<'CFG'
rtspAddress: :8554
hls: no
webrtc: no
rtmp: no
api: no
metrics: no
logLevel: warn

paths:
  stream1:
    runOnInit: >
      ffmpeg -re -stream_loop -1 -i /opt/testbed/media/clip.ts
      -c copy -f rtsp rtsp://localhost:8554/stream1
    runOnInitRestart: yes
CFG

# --- 4. systemd unit (inline) --------------------------------------------------
cat > /etc/systemd/system/tb-rtsp.service <<'UNIT'
[Unit]
Description=TACTIC-IoT RTSP camera server (Objective 3 v2)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/opt/testbed/bin/mediamtx /opt/testbed/services/mediamtx_tactic.yml
Restart=always
RestartSec=5
Nice=10
CPUQuota=40%
MemoryMax=180M

[Install]
WantedBy=multi-user.target
UNIT

# --- 5. enable + verify --------------------------------------------------------
systemctl daemon-reload
systemctl enable --now tb-rtsp
sleep 3
if ss -ltn | grep -q ':8554'; then
  echo "RTSP UP on $(hostname)"
else
  echo "RTSP NOT up on $(hostname)"
  journalctl -u tb-rtsp -n 20 --no-pager
  exit 1
fi
