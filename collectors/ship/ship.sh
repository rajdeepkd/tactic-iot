#!/usr/bin/env bash
# ship.sh -- ALTERNATIVE shipping (push model), runs ON A BOARD via
# testbed-ship.timer. Use this only if you prefer boards to push to the RPi 5
# hub (Linux->Linux, easy) rather than the control machine pulling. If
# CONTROL_TARGET is blank, this is a no-op (pull model in use -- log_puller.py).
#
# rsync --append-verify is incremental and safe on append-only rotated logs.
set -euo pipefail
: "${LOG_ROOT:=/var/log/testbed}"
: "${CONTROL_TARGET:=}"        # e.g. pi@10.0.0.10:/srv/testbed/captures
: "${SSH_KEY:=/etc/testbed/ship_key}"
HOST="$(hostname)"
if [ -z "$CONTROL_TARGET" ]; then
  echo "[ship] CONTROL_TARGET empty -> pull model in use; nothing to push"
  exit 0
fi
exec rsync -az --append-verify --partial \
    -e "ssh -i $SSH_KEY -o BatchMode=yes -o StrictHostKeyChecking=accept-new" \
    "$LOG_ROOT/" "${CONTROL_TARGET}/${HOST}/"
