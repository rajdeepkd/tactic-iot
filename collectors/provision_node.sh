#!/usr/bin/env bash
# provision_node.sh -- standardize an Objective-3 testbed node BEFORE capture.
#
# This script operationalizes the P5 anti-fingerprint controls: telemetry on the
# emulated CIC-YNU dataset was ~93% an architecture/VM-image fingerprint because
# the guest images differed (RAM, kernel, ~42 vs ~72 idle tasks, DVFS policy).
# We cannot make ARM32/ARM64/Tegra hardware identical, but we hold EVERYTHING
# controllable identical across boards and RECORD the rest as metadata, so
# architecture/config becomes a controlled nuisance variable, not a shortcut.
#
# Run once per board as root, before the campaign:
#   sudo ./provision_node.sh <role: rpi3|rpi5|jetson> <session_id>
#
# It (1) pins one CPU governor policy on every board, (2) strips the idle daemon
# set to an identical minimum, (3) forces UTC + disables auto power/thermal
# management drift, (4) enables I2C for INA sensors, (5) installs the collector +
# deps, (6) writes /etc/testbed/telemetry.env, (7) emits the config manifest and
# prints the config_id + chrony offset for the deploy gate.
set -euo pipefail

ROLE="${1:?usage: provision_node.sh <rpi3|rpi5|jetson> <session_id>}"
SESSION="${2:?provide a session id, e.g. 2026-10-01_run1}"
OUT=/var/log/testbed/telemetry
GOV=performance          # ONE governor policy for all boards (removes DVFS-policy
                         # variance so CPU%/power reflect workload, not arch policy)

echo "== [1/7] identical CPU frequency policy =="
for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
  [ -w "$g" ] && echo "$GOV" > "$g" || true
done
# make it stick across reboot
if command -v cpufreq-set >/dev/null 2>&1; then
  apt-get install -y cpufrequtils >/dev/null 2>&1 || true
fi

echo "== [2/7] strip idle daemon set to an identical minimum =="
# Same disabled set on every board so the baseline process list / idle CPU / idle
# power are as close as hardware allows (P5 'process set' fingerprint).
STOP_UNITS="bluetooth avahi-daemon modemmanager cups cups-browsed \
            triggerhappy wpa_supplicant hciuart apt-daily.timer \
            apt-daily-upgrade.timer man-db.timer unattended-upgrades"
for u in $STOP_UNITS; do
  systemctl disable --now "$u" >/dev/null 2>&1 || true
done

echo "== [3/7] UTC + fixed power/thermal management =="
timedatectl set-timezone UTC || true
case "$ROLE" in
  jetson)
    # fixed power model (MAXN) so the INA3221 side-channel is not confounded by
    # nvpmodel switching; jetson_clocks pins max clocks (governor 'performance' analog)
    nvpmodel -m 0 || true
    jetson_clocks || true
    ;;
  rpi5|rpi3)
    # flag any undervolt/throttle now -- it distorts the power/thermal channel
    if command -v vcgencmd >/dev/null 2>&1; then
      echo "   vcgencmd throttled: $(vcgencmd get_throttled)"
    fi
    ;;
esac

echo "== [4/7] enable I2C for INA219/INA260 (RPi) =="
case "$ROLE" in
  rpi3|rpi5)
    if command -v raspi-config >/dev/null 2>&1; then
      raspi-config nonint do_i2c 0 || true      # 0 = enable
    fi
    grep -q '^dtparam=i2c_arm=on' /boot/firmware/config.txt 2>/dev/null || \
      grep -q '^dtparam=i2c_arm=on' /boot/config.txt 2>/dev/null || \
      echo "   NOTE: add dtparam=i2c_arm=on to config.txt and reboot if i2cdetect is empty"
    modprobe i2c-dev || true
    ;;
esac

echo "== [5/7] install collector + deps =="
install -d /opt/testbed/collectors /etc/testbed "$OUT"
install -m 0755 "$(dirname "$0")/telemetry_reader.py" /opt/testbed/collectors/telemetry_reader.py
install -m 0644 "$(dirname "$0")/telemetry.service" /etc/systemd/system/telemetry.service
# psutil optional (falls back to /proc); smbus2 needed for INA219/INA260 only.
python3 -m pip install --quiet psutil smbus2 >/dev/null 2>&1 || \
  apt-get install -y python3-psutil python3-smbus i2c-tools >/dev/null 2>&1 || true

echo "== [6/7] write per-node telemetry.env =="
case "$ROLE" in
  rpi5)   PW="--power ina260 --shunt 0.002 --power-hz 10" ;;   # up to 5 A -> INA260
  rpi3)   PW="--power ina219 --shunt 0.1  --power-hz 10" ;;    # ~1.2 A peak -> INA219
  jetson) PW="--power jetson --power-hz 5" ;;                  # onboard INA3221
  *)      PW="--power none" ;;
esac
cat > /etc/testbed/telemetry.env <<EOF
TELEM_ARGS=--out $OUT --hz 1 --session $SESSION $PW --power-raw
EOF
echo "   $(cat /etc/testbed/telemetry.env)"

echo "== [7/7] emit config manifest + deploy-gate checks =="
# shellcheck disable=SC2046
python3 /opt/testbed/collectors/telemetry_reader.py --emit-config \
        --out "$OUT" --session "$SESSION" $PW
if command -v chronyc >/dev/null 2>&1; then
  echo "   chrony: $(chronyc tracking 2>/dev/null | grep -E 'Last offset|Stratum' | tr '\n' ' ')"
fi
if command -v i2cdetect >/dev/null 2>&1 && [ "$ROLE" != "jetson" ]; then
  echo "   i2cdetect bus 1 (expect a sensor at 0x40):"; i2cdetect -y 1 || true
fi

systemctl daemon-reload
echo "Provisioned $ROLE for session $SESSION."
echo "Enable the collector with:  sudo systemctl enable --now telemetry.service"
echo "Config manifest written under $OUT (config_<host>_$SESSION.json)."
