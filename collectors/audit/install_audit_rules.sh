#!/usr/bin/env bash
# install_audit_rules.sh -- render testbed.rules.template for THIS board's ABI
# and load it. Solves the auditctl arch problem: a `-F arch=b64` rule fails to
# load on the 32-bit RPi 3B+ kernel, and the 32-bit priv-syscall aliases
# (setuid32, ...) do not exist on aarch64. We detect the ABI and emit only the
# rules that will actually load.
#
#   RPi 3B+  : Raspberry Pi OS 32-bit  -> aarch32 kernel -> b32 ONLY
#   RPi 5    : Raspberry Pi OS 64-bit  -> aarch64 kernel -> b64 (+ b32 compat)
#   Jetson   : L4T / Ubuntu 18.04      -> aarch64 kernel -> b64 (+ b32 compat)
#
# Usage:  sudo ./install_audit_rules.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/testbed.rules.template"
OUT=/etc/audit/rules.d/10-testbed.rules

MACH="$(uname -m)"   # armv7l / armv6l (aarch32) | aarch64 | arm64

# --- execve + privilege rules for a 64-bit ABI -----------------------------
b64_block() {
cat <<'EOF'
## --- aarch64 (b64): process creation ---
-a always,exit -F arch=b64 -S execve,execveat -k proc_exec
## --- aarch64 (b64): privilege change (privilege-escalation stage) ---
-a always,exit -F arch=b64 -S setuid,setgid,setreuid,setregid,setresuid,setresgid,setfsuid,setfsgid -k priv_change
-a always,exit -F arch=b64 -S capset -k priv_cap
## setuid/setgid bit set on a file (persistence via SUID dropper)
-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F a1&06000 -k suid_bit
EOF
}

# --- execve + privilege rules for the 32-bit ARM ABI -----------------------
# NOTE: aarch32 has BOTH the legacy 16-bit-uid calls (setuid #23) AND the
# 32-bit-uid calls (setuid32 #213); glibc uses the *32 forms. List both so we
# never miss a privilege change regardless of libc.
b32_block() {
cat <<'EOF'
## --- aarch32 (b32): process creation ---
-a always,exit -F arch=b32 -S execve,execveat -k proc_exec
## --- aarch32 (b32): privilege change (both 16-bit and 32-bit uid ABIs) ---
-a always,exit -F arch=b32 -S setuid,setuid32,setgid,setgid32,setreuid,setreuid32,setregid,setregid32 -k priv_change
-a always,exit -F arch=b32 -S setresuid,setresuid32,setresgid,setresgid32,setfsuid,setfsuid32,setfsgid,setfsgid32 -k priv_change
-a always,exit -F arch=b32 -S capset -k priv_cap
-a always,exit -F arch=b32 -S chmod,fchmod,fchmodat -F a1&06000 -k suid_bit
EOF
}

case "$MACH" in
  aarch64|arm64)
    echo "[install] aarch64 board (RPi 5 / Jetson): b64 + b32 compat rules"
    ARCHLINES="$(b64_block)
$(b32_block)"
    ;;
  armv7l|armv6l|armhf)
    echo "[install] aarch32 board (RPi 3B+): b32 rules only"
    ARCHLINES="$(b32_block)"
    ;;
  *)
    echo "[install] unknown machine '$MACH'; defaulting to b64+b32" >&2
    ARCHLINES="$(b64_block)
$(b32_block)"
    ;;
esac

# render template
python3 - "$TEMPLATE" "$OUT" <<PY
import sys
tpl, out = sys.argv[1], sys.argv[2]
archlines = """$ARCHLINES"""
text = open(tpl).read().replace("__ARCHLINES__", archlines)
open(out, "w").write(text)
print("[install] wrote", out)
PY

echo "[install] loading rules with augenrules..."
augenrules --load
echo "[install] active rules:"
auditctl -l | sed 's/^/    /'
echo "[install] status:"
auditctl -s | sed 's/^/    /'
echo "[install] NOTE: also save the number->name table for the windowizer:"
echo "           ausyscall --dump > /var/log/testbed/meta/ausyscall_\$(hostname).txt"
