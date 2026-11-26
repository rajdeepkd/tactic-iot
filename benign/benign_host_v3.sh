#!/bin/bash
# benign_host_v3.sh -- benign HOST/ADMIN activity generator for TACTIC-IoT v3.
# Runs ON THE HUB (the operator), targeting both victims. Produces realistic benign
# syslog/auth-log traces so benign windows are NOT trivially separable from attacks.
# Uses only built-in ssh/scp + the SSH_ASKPASS mechanism (NO sshpass/paramiko, so it
# works behind the captive portal / fully offline).
#
# BENIGN ACTIVITIES (documented for the dataset / manuscript):
#   1. admin_ssh   -- a legitimate operator logs in with the KEY (-> 'Accepted
#                     publickey for pi'), runs a few read-only admin commands, logs
#                     out. RARELY (~1 in 167, i.e. 0.6%) the operator fat-fingers the
#                     password FIRST via SSH_ASKPASS (-> one benign 'Failed password
#                     for pi'), then logs in with the key. This matches the brute's
#                     auth-log signature so a single failed login is NOT separable
#                     from an attack; the rate is kept deliberately low (genuine
#                     logins rarely typo) so benign failed-auth never dominates.
#   2. cron_maint  -- periodic maintenance: a syslog health report + a dry-run
#                     logrotate + a stale-pcap scan (-> benign journald/process churn
#                     that overlaps persistence_cron / execution).
#   3. backup      -- periodic scp of a log file victim->hub (-> benign bulk transfer
#                     that overlaps exfil_bulk).
# Ground truth is appended to ~/benign_host_activity.csv on the hub.
#
# IMPORTANT (realism, per design): keep the typo rate LOW (P_TYPO_DENOM>=100) and the
# activity rates MODERATE so benign does not swamp the attack signal.
set -u
K="$HOME/.ssh/hub_to_victim"
VICTIMS="rpi3b1:192.168.0.32 rpi3b2:192.168.0.33"
LOG="$HOME/benign_host_activity.csv"
P_TYPO_DENOM="${P_TYPO_DENOM:-167}"     # ~1 benign login in 167 mistypes the password
SSH="ssh -i $K -o BatchMode=yes -o StrictHostKeyChecking=no -o ConnectTimeout=8"
[ -f "$LOG" ] || echo "ts_epoch,device_id,action,outcome" > "$LOG"
log(){ echo "$(date +%s),$1,$2,$3" >> "$LOG"; }
jitter(){ local b=$1; echo $(( b - b/4 + RANDOM % (b/2 + 1) )); }   # +/-25%

typo_login(){ # one benign wrong-password attempt -> 'Failed password for pi'
  local ip=$1 f="/tmp/ap_$$_$RANDOM.sh"
  printf '#!/bin/sh\necho benign_typo_%s\n' "$RANDOM" > "$f"; chmod +x "$f"
  SSH_ASKPASS="$f" SSH_ASKPASS_REQUIRE=force setsid -w ssh -o PreferredAuthentications=password \
    -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o ConnectTimeout=6 "pi@$ip" exit >/dev/null 2>&1
  rm -f "$f"
}
admin_session(){ local vn=$1 ip=$2
  if [ $((RANDOM % P_TYPO_DENOM)) -eq 0 ]; then typo_login "$ip"; log "$vn" admin_ssh typo_failed; fi
  $SSH "pi@$ip" 'uptime >/dev/null; df -h / >/dev/null; journalctl -n 20 >/dev/null 2>&1; ls -l /var/log >/dev/null' \
    >/dev/null 2>&1 && log "$vn" admin_ssh ok || log "$vn" admin_ssh err
}
cron_maint(){ local vn=$1 ip=$2
  $SSH "pi@$ip" 'logger -t benign-cron "scheduled maintenance: health report"; sudo logrotate -d /etc/logrotate.conf >/dev/null 2>&1; find /var/log/testbed -name "*.pcap" -mmin +720 >/dev/null 2>&1' \
    >/dev/null 2>&1 && log "$vn" cron_maint ok || log "$vn" cron_maint err
}
backup(){ local vn=$1 ip=$2
  scp -i "$K" -o BatchMode=yes -o ConnectTimeout=8 "pi@$ip:/var/log/testbed/coap_tactic.log" "/tmp/bk_${vn}.log" \
    >/dev/null 2>&1 && log "$vn" backup ok || log "$vn" backup err
}
loop_admin(){  while :; do for v in $VICTIMS; do admin_session "${v%%:*}" "${v##*:}"; done; sleep "$(jitter 210)"; done; }
loop_cron(){   while :; do for v in $VICTIMS; do cron_maint   "${v%%:*}" "${v##*:}"; done; sleep "$(jitter 300)"; done; }
loop_backup(){ while :; do for v in $VICTIMS; do backup       "${v%%:*}" "${v##*:}"; done; sleep "$(jitter 900)"; done; }
trap 'kill 0' TERM INT
loop_admin & loop_cron & loop_backup &
echo "[benign-host] started: admin~210s cron~300s backup~900s, typo 1/${P_TYPO_DENOM}"
wait
