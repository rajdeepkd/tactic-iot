#!/bin/bash
# install_collectors.sh -- run ON a victim board (has passwordless sudo).
# Installs the always-on tb-telemetry + tb-capture services and makes the
# auditd rule set persistent across reboot. Idempotent. Expects the staged
# files beside this script:
#   telemetry_reader.py run_capture.sh tb-telemetry.service tb-capture.service testbed_v1.rules
set -eu
SRC="$(cd "$(dirname "$0")" && pwd)"
# The file installs are the ONLY hard prerequisites -> keep set -e for these.
sudo mkdir -p /opt/testbed /var/log/testbed
sudo install -m 0755 "$SRC/telemetry_reader.py"  /opt/testbed/telemetry_reader.py
sudo install -m 0755 "$SRC/run_capture.sh"       /opt/testbed/run_capture.sh
sudo install -m 0755 "$SRC/run_benign.sh"        /opt/testbed/run_benign.sh
sudo install -m 0644 "$SRC/tb-telemetry.service" /etc/systemd/system/tb-telemetry.service
sudo install -m 0644 "$SRC/tb-capture.service"   /etc/systemd/system/tb-capture.service
sudo install -m 0644 "$SRC/tb-benign.service"    /etc/systemd/system/tb-benign.service

# Everything below is best-effort and INDEPENDENT: a failure in the audit-rules
# step must never prevent the collectors from starting (or vice-versa), and the
# diagnostics must never abort the script (they run 'is-active' which is non-zero
# when a unit is down -- exactly the case we want to SEE, not crash on).
set +e

# --- always-on collectors (started FIRST so audit-rule issues can't block them) ---
# restart (not just enable --now) so a redeploy actually reloads changed code
sudo systemctl daemon-reload
sudo systemctl enable tb-telemetry.service tb-capture.service tb-benign.service >/dev/null 2>&1
sudo systemctl restart tb-telemetry.service
sudo systemctl restart tb-capture.service
sudo systemctl restart tb-benign.service

# --- persistent auditd rules (were runtime-only via auditctl -> lost on reboot) ---
# Flush the kernel rule set FIRST so re-loading is idempotent (else a still-loaded
# runtime rule makes augenrules abort at the first duplicate with "Rule exists").
sudo rm -f /etc/audit/rules.d/testbed.rules   # drop any stale pre-v1 copy (would double-load)
if [ -f "$SRC/testbed_v1.rules" ]; then
  sudo install -m 0640 "$SRC/testbed_v1.rules" /etc/audit/rules.d/testbed_v1.rules
  sudo auditctl -D >/dev/null 2>&1
  sudo augenrules --load 2>&1 | grep -viE "Old style watch rules are slower|^No rules$"
  sudo systemctl enable auditd >/dev/null 2>&1
else
  echo "WARN: testbed_v1.rules not staged -> auditd rules NOT updated (collectors still up)" >&2
fi

sleep 3
echo "=== active? ==="; systemctl is-active tb-telemetry.service tb-capture.service tb-benign.service auditd
echo "=== auditd rules loaded ==="; sudo auditctl -l | wc -l
echo "=== outputs ==="; ls -l /var/log/testbed/ 2>/dev/null | tail -6
exit 0
