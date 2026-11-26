#!/usr/bin/env bash
# install_services.sh -- provision one board's host collectors. Run as root on
# each of RPi 3B+, RPi 5, Jetson Nano. Idempotent.
#
#   sudo ./install_services.sh
#
# Steps:
#  1. lay code under /opt/testbed, logs under /var/log/testbed
#  2. create the 'testbed' service user (journal + adm read)
#  3. install journald persistence + auditd rules (arch-aware)
#  4. install + enable the systemd units
#  5. snapshot device meta + save the ABI syscall table
set -euo pipefail
SRC="$(cd "$(dirname "$0")/.." && pwd)"    # .../collectors
DEST=/opt/testbed/collectors
LOG=/var/log/testbed

echo "[1/5] staging code"
install -d "$DEST" "$LOG"/{syscall,hostlog,telemetry,meta} /etc/testbed
cp -r "$SRC"/. "$DEST"/
[ -f /etc/testbed/testbed.env ] || cp "$SRC/systemd/testbed.env" /etc/testbed/testbed.env
chmod +x "$DEST"/**/*.sh 2>/dev/null || true

echo "[2/5] service user"
id testbed >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin testbed
usermod -aG systemd-journal,adm testbed || true
chown -R testbed:testbed "$LOG"

echo "[3/5] journald + auditd config"
install -D "$SRC/hostlog/journald-testbed.conf" /etc/systemd/journald.conf.d/10-testbed.conf
systemctl restart systemd-journald
apt-get install -y auditd audispd-plugins >/dev/null 2>&1 || echo "  (install auditd manually if offline)"
bash "$SRC/audit/install_audit_rules.sh"

echo "[4/5] systemd units"
cp "$SRC"/systemd/testbed-*.service "$SRC"/systemd/testbed-*.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now testbed-meta.service
systemctl enable --now testbed-telemetry.service
systemctl enable --now testbed-authlog.service
systemctl enable --now testbed-syscall.service
systemctl enable --now testbed-auditship.timer
# push model only if CONTROL_TARGET set in testbed.env:
if grep -q '^CONTROL_TARGET=.\+' /etc/testbed/testbed.env; then
  cp "$SRC"/../ship/ship.sh "$DEST"/ship.sh 2>/dev/null || true
fi

echo "[5/5] meta snapshot + ABI table"
bash "$SRC/meta/record_device_meta.sh" "$LOG/meta" --baseline 120

echo "[done] status:"
systemctl --no-pager --plain status testbed-syscall testbed-authlog testbed-telemetry 2>/dev/null | grep -E 'Active|Loaded' || true
echo "verify clock skew < 1ms:  chronyc tracking | grep 'System time'"
