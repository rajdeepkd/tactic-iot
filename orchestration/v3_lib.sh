#!/bin/bash
# v3_lib.sh -- shared helpers for the v3 collection + top-up drivers. Sourced only;
# defines NO top-level actions. Provides V() (run a command on a victim via the hub)
# and health_check() (per-run clock + 4-modality freshness repair + benign liveness).
: "${K:=$HOME/.ssh/obj3_testbed}"; : "${HUB:=cnc@192.168.0.50}"
: "${SSH:=ssh -i $K -o BatchMode=yes -o ServerAliveInterval=15 -o ConnectTimeout=15}"

V(){ $SSH "$HUB" "ssh -i ~/.ssh/hub_to_victim -o BatchMode=yes -o ConnectTimeout=10 pi@$1 \"$2\""; }

health_check(){ # $1=victim-ip $2=victim-name ; repairs clock/collectors/benign, best-effort
  local ip=$1 vn=$2 hub_t vic_t d report
  # kill any ORPHANED campaign/attack procs lingering from a prior run: a leftover
  # hub_campaign.sh makes run_campaign ABORT the next run ("concurrent campaign"), and
  # a detached ettercap/hping3 would bleed attack traffic into the benign baseline.
  # Safe here because the driver is sequential (no legit campaign is active at this point).
  $SSH "$HUB" 'sudo pkill -9 -f hub_campaign.sh 2>/dev/null; sudo pkill -9 -f run_action.sh 2>/dev/null; sudo pkill -9 -f ettercap 2>/dev/null; sudo pkill -9 -f hping3 2>/dev/null; true' >/dev/null 2>&1
  hub_t=$($SSH "$HUB" 'date +%s' 2>/dev/null); vic_t=$(V "$ip" 'date +%s' 2>/dev/null)
  if [ -n "$hub_t" ] && [ -n "$vic_t" ]; then d=$((hub_t-vic_t)); d=${d#-}
    if [ "$d" -gt 3 ]; then echo "[health] $vn CLOCK off ${d}s -> resync"
      V "$ip" 'sudo chronyc makestep >/dev/null 2>&1'; sleep 2
      vic_t=$(V "$ip" 'date +%s'); d=$((hub_t-vic_t)); d=${d#-}
      if [ "$d" -gt 3 ]; then echo "[health] $vn still off -> redeploy chrony cfg from .32"
        $SSH "$HUB" "ssh -i ~/.ssh/hub_to_victim pi@192.168.0.32 'sudo cat /etc/chrony/chrony.conf'" | \
          V "$ip" 'sudo tee /etc/chrony/chrony.conf >/dev/null; sudo systemctl restart chronyd; sleep 2; sudo chronyc makestep >/dev/null 2>&1'
      fi
    fi
  fi
  report=$(V "$ip" 'bash /opt/testbed/tb_health.sh')
  echo "[health] $vn $report"
  echo "$report" | grep -qE "net:(NONE|[2-9][0-9][0-9]|[0-9]{4})" && { echo "[health] $vn restart tb-capture"; V "$ip" 'sudo systemctl restart tb-capture'; }
  echo "$report" | grep -qE "tel:(NONE|[2-9][0-9][0-9]|[0-9]{4})" && { echo "[health] $vn restart tb-telemetry"; V "$ip" 'sudo systemctl restart tb-telemetry'; }
  $SSH "$HUB" 'pgrep -f benign_host_v3.sh >/dev/null 2>&1' || { echo "[health] start benign_host"; $SSH "$HUB" 'nohup bash ~/benign_host_v3.sh >/tmp/benign_host.log 2>&1 & disown' >/dev/null 2>&1; }
}
