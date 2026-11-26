#!/usr/bin/env python3
"""
Phase-1 deterministic, STAGE-AWARE orchestrator.

Runs on the WINDOWS control machine. Owns the synced clock (via rpi5-hub chrony,
the time_master), drives each lifecycle STAGE of each scenario in a timed window
over key-based SSH, and writes machine-readable ground-truth STAGE labels.
Collectors AND benign background (benignd.service) are ALWAYS ON; this script
NEVER starts/stops them (anti-sessionization principle #1). Determinism (not an
LLM) guarantees reproducible timing/labels.

Canonical stage vocabulary = stages.yaml (S0..S12), referenced by scenarios.yaml
(taxonomy_file). This script loads it for each stage's MITRE tactic + expected
primary source.

Ground-truth timeline: at each window boundary the orchestrator captures the
TARGET board's chrony-disciplined CLOCK_REALTIME on-device (`date +%s.%N`) plus
CLOCK_MONOTONIC, and appends an on-device marker. Those on-device synced times
ARE the label boundaries, so labels live on the exact clock the board's
collectors stamp — cross-machine skew never enters the label.

Two label files are written per run (INTEROP — do not break):
  labels.ndjson  rich provenance, one JSON object per stage execution
                 (conforms to schemas/label_record.schema.json)
  labels.csv     the projection consumed by pipeline/align_windows.py and
                 pipeline/validate_alignment.py:
                 scenario_id,run_idx,attack_type,target,stage,start_iso,end_iso,
                 start_ns,end_ns,guard_pre_s,guard_post_s

SAFETY: this script only LAUNCHES attacker actions referenced by action_ref in
scenarios.yaml (methodology-level tool references / operator-supplied, authorized
programs). It authors no offensive code. requires_airgap stages are BLOCKED
unless the air-gap preflight passes and a real ethics_ref is set.

Usage:
  python orchestrator.py --manifest scenarios.yaml --nodes nodes.yaml --out ./captures --dry-run
  python orchestrator.py --manifest scenarios.yaml --nodes nodes.yaml --out ./captures
"""
import argparse, csv, hashlib, json, os, platform, shlex, subprocess, sys, time, uuid
from datetime import datetime, timezone


# ----------------------------------------------------------------------------- utils
def load_yaml(path):
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML required: pip install pyyaml")
    with open(path) as f:
        return yaml.safe_load(f)


def utc_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def epoch_to_iso(ep):
    """Board-synced epoch seconds -> UTC ISO-8601 (same clock the collectors stamp)."""
    if ep is None:
        return ""
    return datetime.fromtimestamp(float(ep), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z"


def sha256_str(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def short_stage(stage_id):
    """S2_bruteforce_credential_access -> bruteforce_credential_access (coarse attack_type)."""
    p = stage_id.split("_", 1)
    return p[1] if len(p) == 2 and p[0][:1] == "S" and p[0][1:].isdigit() else stage_id


def log(msg):
    print(f"[{datetime.now(timezone.utc).isoformat()}] {msg}", flush=True)


# ----------------------------------------------------------------------------- SSH
class SSH:
    """Key-based SSH transport to the boards. No passwords; fails instead of
    prompting (BatchMode). Every call has a timeout and returns (rc, out, err)."""

    def __init__(self, ssh_defaults, dry):
        self.d = ssh_defaults or {}
        self.dry = dry

    def _base(self, node):
        opts = ["ssh",
                "-o", "BatchMode=yes",
                "-o", f"ConnectTimeout={self.d.get('connect_timeout_s', 8)}",
                "-o", f"StrictHostKeyChecking={self.d.get('strict_host_key_checking', 'accept-new')}"]
        if self.d.get("key_file"):
            opts += ["-i", self.d["key_file"]]
        if self.d.get("known_hosts"):
            opts += ["-o", f"UserKnownHostsFile={self.d['known_hosts']}"]
        opts.append(f"{node['ssh_user']}@{node['ip']}")
        return opts

    def run(self, node, remote_cmd, timeout=30):
        argv = self._base(node) + [remote_cmd]
        if self.dry:
            log(f"    [dry-run ssh] {node['ip']}: {remote_cmd}")
            return 0, "", ""
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
            return p.returncode, p.stdout.strip(), p.stderr.strip()
        except subprocess.TimeoutExpired:
            return 124, "", "timeout"

    def launch(self, node, remote_cmd, logfile="/tmp/obj3_action.log"):
        """Start a remote action in the background; return its remote PID (or None).
        setsid+nohup so it survives the SSH channel; killed by PID at window close
        for a crisp, deterministic boundary."""
        wrapped = f"nohup setsid sh -c {shlex.quote(remote_cmd)} > {logfile} 2>&1 & echo $!"
        rc, out, err = self.run(node, wrapped, timeout=self.d.get("connect_timeout_s", 8) + 5)
        if self.dry:
            return -1
        try:
            return int(out.splitlines()[-1].strip())
        except Exception:
            log(f"    [warn] could not read remote PID (rc={rc} err={err})")
            return None

    def kill(self, node, pid):
        if self.dry or pid is None:
            return
        self.run(node, f"kill -TERM {pid} 2>/dev/null; sleep 1; kill -KILL {pid} 2>/dev/null; true", timeout=20)

    def alive(self, node, pid):
        if self.dry or pid is None:
            return False
        rc, out, _ = self.run(node, f"kill -0 {pid} 2>/dev/null && echo up || echo down", timeout=15)
        return out.strip().endswith("up")

    def remote_now(self, node):
        """(t_synced_epoch_float, t_mono_float) read ON the board — the authoritative
        synced CLOCK_REALTIME the collectors also use."""
        rc, out, err = self.run(node, "date +%s.%N; awk '{print $1}' /proc/uptime", timeout=15)
        if self.dry:
            return time.time(), time.monotonic()
        try:
            a, b = out.splitlines()[:2]
            return float(a), float(b)
        except Exception:
            log(f"    [warn] remote_now parse failed on {node['ip']} (rc={rc}): {out!r} {err!r}")
            return time.time(), None


# ----------------------------------------------------------------------------- taxonomy
def load_taxonomy(manifest_path, man):
    """Load stages.yaml (canonical) -> {stage_id: {mitre_tactic, mitre_technique, primary}}."""
    tf = man.get("taxonomy_file", "stages.yaml")
    path = tf if os.path.isabs(tf) else os.path.join(os.path.dirname(os.path.abspath(manifest_path)), tf)
    tax = {}
    try:
        sy = load_yaml(path)
        for s in sy.get("stages", []):
            techs = s.get("mitre_techniques") or []
            tax[s["id"]] = {"mitre_tactic": s.get("mitre_tactic"),
                            "mitre_technique": (techs[0] if techs else None),
                            "primary": s.get("expected_primary_source")}
    except Exception as e:
        log(f"    [warn] could not load taxonomy {path}: {e} (mitre/primary will be null)")
    return tax


# ----------------------------------------------------------------------------- preflight
def collect_fingerprint(ssh, node):
    """Device config metadata (P5 obligation: RAM, kernel, governor, process set,
    nvpmodel) — recorded, controlled by design, NEVER used as a feature."""
    fp = {}
    for k, cmd in [
        ("kernel", "uname -r"),
        ("cpu_model", "grep -m1 'model name\\|Model' /proc/cpuinfo | cut -d: -f2"),
        ("ram_mb", "awk '/MemTotal/{print int($2/1024)}' /proc/meminfo"),
        ("governor", "cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null"),
        ("nproc", "nproc"),
        ("proc_count", "ls -1 /proc | grep -c '^[0-9]'"),
        ("btf_present", "test -e /sys/kernel/btf/vmlinux && echo yes || echo no"),
        ("os_release", "sed -n 's/^PRETTY_NAME=//p' /etc/os-release | tr -d '\"'"),
        ("nvpmodel", "nvpmodel -q 2>/dev/null | sed -n 's/.*NV Power Mode: //p' | head -1"),
    ]:
        rc, out, _ = ssh.run(node, cmd, timeout=15)
        fp[k] = out if rc == 0 and out else None
    return fp


def chrony_offset_ms(ssh, node):
    """|Last offset| in ms from `chronyc tracking`. None if unavailable."""
    rc, out, _ = ssh.run(node, "chronyc tracking 2>/dev/null | sed -n 's/^Last offset *: *//p'", timeout=15)
    if rc != 0 or not out:
        return None
    try:
        return abs(float(out.split()[0])) * 1000.0
    except Exception:
        return None


def preflight(ssh, nodes, man, skew_ms_max=1.0):
    """Assert chrony skew < threshold on every board; collectors + benignd active;
    disk ok. Air-gap is checked per requires_airgap stage, not globally."""
    report = {"skew_ms": {}, "collectors": {}, "benign": {}, "disk_free_mb": {}, "problems": []}
    victims = set(man.get("benign", {}).get("victims", []))

    for dev_id, node in nodes["nodes"].items():
        if node.get("board") == "laptop_vm":
            continue
        skew = chrony_offset_ms(ssh, node)
        report["skew_ms"][dev_id] = skew
        if skew is None:
            report["problems"].append(f"{dev_id}: chrony offset unreadable")
        elif skew > skew_ms_max:
            report["problems"].append(f"{dev_id}: chrony skew {skew:.3f}ms > {skew_ms_max}ms")

        for unit in ["obj3-telemetry.service"]:
            rc, out, _ = ssh.run(node, f"systemctl is-active {unit}", timeout=15)
            report["collectors"].setdefault(dev_id, {})[unit] = out or "unknown"
            if out != "active":
                report["problems"].append(f"{dev_id}: collector {unit} not active ({out})")

        rc, out, _ = ssh.run(node, "df -Pm /var/log 2>/dev/null | awk 'NR==2{print $4}'", timeout=15)
        try:
            report["disk_free_mb"][dev_id] = int(out)
        except Exception:
            report["disk_free_mb"][dev_id] = None

    # benignd.service must be ALWAYS ON on each victim (never started by us)
    bunit = man.get("benign", {}).get("daemon_unit", "benignd.service")
    for dev_id in victims:
        node = nodes["nodes"].get(dev_id)
        if not node:
            report["problems"].append(f"benign victim {dev_id} not in nodes.yaml")
            continue
        rc, out, _ = ssh.run(node, f"systemctl is-active {bunit}", timeout=15)
        report["benign"][dev_id] = out or "unknown"
        if out != "active":
            report["problems"].append(f"{dev_id}: {bunit} not active ({out}) — benign background REQUIRED (principle #1)")

    ok = len(report["problems"]) == 0
    return ok, report


def assert_airgap(ssh, nodes, target_node):
    """MANDATORY containment check before any requires_airgap stage: egress and
    external DNS MUST fail (non-zero exit == good). Returns (ok, detail)."""
    probe = nodes.get("airgap_probe", {})
    detail, ok = {}, True
    for key, cmd in [("egress", probe.get("cmd")), ("dns", probe.get("dns_cmd"))]:
        if not cmd:
            continue
        rc, _, _ = ssh.run(target_node, cmd, timeout=20)
        detail[key] = {"rc": rc, "blocked": rc != 0}
        ok = ok and (rc != 0)
    return ok, detail


# ----------------------------------------------------------------------------- reaction / validity gate
def reaction_probe(modality):
    """Tiny counter command per modality — used to check that expected sources
    actually reacted (Charter principle #2). Deltas over the window, not features."""
    return {
        "network":   "cat /sys/class/net/eth0/statistics/rx_packets 2>/dev/null || cat /sys/class/net/wlan0/statistics/rx_packets 2>/dev/null || echo 0",
        "host":      "grep -c '' /var/log/auth.log 2>/dev/null || ls -1 /proc | grep -c '^[0-9]'",
        "telemetry": "awk '{print $1}' /proc/loadavg",
    }.get(modality, "echo 0")


def snapshot_counters(ssh, node, modalities):
    snap = {}
    for m in set(modalities):
        rc, out, _ = ssh.run(node, reaction_probe(m), timeout=15)
        try:
            snap[m] = float(out.splitlines()[-1])
        except Exception:
            snap[m] = None
    return snap


def evaluate_gate(open_snap, close_snap, expected):
    """>=2 expected modalities must show a positive delta (or load rise). Provisional;
    validate_alignment.py + the finalize step re-check against aligned window data."""
    thr = {"network": 50.0, "host": 1.0, "telemetry": 0.05}
    reacted, detail = 0, {}
    for m in set(expected):
        a, b = open_snap.get(m), close_snap.get(m)
        if a is None or b is None:
            detail[m] = None
            continue
        delta = b - a
        r = delta >= thr.get(m, 1.0)
        detail[m] = {"delta": round(delta, 3), "reacted": bool(r)}
        reacted += int(r)
    return reacted >= 2, detail


# ----------------------------------------------------------------------------- markers
def append_marker(ssh, node, obj):
    ml = node.get("marker_log", "/var/log/testbed/markers/m.ndjson")
    line = json.dumps(obj, separators=(",", ":"))
    ssh.run(node, f"mkdir -p $(dirname {ml}); printf '%s\\n' {shlex.quote(line)} >> {ml}", timeout=15)


# ----------------------------------------------------------------------------- one stage
def run_stage(ssh, nodes, man, tax, run_id, scenario, repeat_idx, stage_index, stage_spec,
              defaults, nd_fh, csv_w, dry):
    sid = stage_spec["stage"]
    t = tax.get(sid, {"mitre_tactic": None, "mitre_technique": None, "primary": None})
    action = man["actions"][stage_spec["action_ref"]]
    target_id = scenario["target"]
    attacker_id = scenario.get("attacker", nodes["roles"]["attacker"])
    target = nodes["nodes"][target_id]
    attacker = nodes["nodes"][attacker_id]

    roles = nodes["roles"]
    subs = {
        "target_ip":   target["ip"],
        "gateway_ip":  nodes["nodes"].get(roles.get("gateway", ""), {}).get("ip", ""),
        "sinkhole_ip": nodes["nodes"].get(roles.get("sinkhole", ""), {}).get("ip", ""),
        "sample_id":   scenario.get("sample_id") or "",
    }
    action_cmd = action["invocation"].format(**subs)

    if action.get("requires_airgap"):
        ok, detail = assert_airgap(ssh, nodes, target)
        if not ok and not dry:
            log(f"    [ABORT] air-gap NOT verified for {sid} ({detail}); skipping")
            return None

    duration = stage_spec["duration_s"]
    gpre = stage_spec.get("guard_pre_s", defaults.get("guard_pre_s", 2))
    gpost = stage_spec.get("guard_post_s", defaults.get("guard_post_s", 3))
    expected = stage_spec["expected_modalities"]

    log(f"[stage] {scenario['id']} r{repeat_idx} s{stage_index} {sid} "
        f"target={target_id} action={stage_spec['action_ref']} dur={duration}s")

    open_snap = snapshot_counters(ssh, target, expected)
    t_open_synced, t_open_mono = ssh.remote_now(target)
    orch_open = time.time()
    pid = ssh.launch(attacker, action_cmd)

    if dry:
        t_close_synced = t_open_synced + duration
        t_close_mono = (t_open_mono + duration) if t_open_mono else None
        orch_close = orch_open + duration
        exit_code, terminated, gate_ok, gate_detail = None, True, True, {"dry": True}
    else:
        t_end = time.monotonic() + duration
        while time.monotonic() < t_end:
            if pid is not None and not ssh.alive(attacker, pid):
                log("    attacker action finished early")
                break
            time.sleep(min(5, max(0, t_end - time.monotonic())))
        terminated = ssh.alive(attacker, pid) if pid else False
        ssh.kill(attacker, pid)
        exit_code = None
        t_close_synced, t_close_mono = ssh.remote_now(target)
        orch_close = time.time()
        close_snap = snapshot_counters(ssh, target, expected)
        gate_ok, gate_detail = evaluate_gate(open_snap, close_snap, expected)

    for node in (target, attacker):
        for ev, ts, tm in [("open", t_open_synced, t_open_mono), ("close", t_close_synced, t_close_mono)]:
            append_marker(ssh, node, {"ev": ev, "run_id": run_id, "scenario": scenario["id"],
                                      "repeat": repeat_idx, "stage": sid, "stage_index": stage_index,
                                      "t_synced": ts, "t_mono": tm})

    # rich provenance record (labels.ndjson)
    rec = {
        "schema_version": 2, "run_id": run_id, "campaign_id_prefix": man["campaign"]["id_prefix"],
        "scenario_id": scenario["id"], "repeat_idx": repeat_idx, "stage_index": stage_index,
        "stage": sid, "mitre_tactic": t["mitre_tactic"], "mitre_technique": t["mitre_technique"],
        "target_device_id": target_id, "attacker_device_id": attacker_id,
        "action_ref": stage_spec["action_ref"], "action_cmd_sha256": sha256_str(action_cmd),
        "sample_id": scenario.get("sample_id"), "sample_sha256": None,
        "t_open_synced": t_open_synced, "t_close_synced": t_close_synced,
        "t_open_mono": t_open_mono, "t_close_mono": t_close_mono,
        "orch_t_open": orch_open, "orch_t_close": orch_close, "clock_skew_ms": None,
        "guard_pre_s": gpre, "guard_post_s": gpost,
        "primary_modality": t["primary"], "expected_modalities": expected,
        "validity_gate_passed": bool(gate_ok), "validity_gate_detail": gate_detail,
        "remote_pid": pid if pid and pid > 0 else None, "remote_exit_code": exit_code,
        "terminated_on_close": bool(terminated), "notes": None,
    }
    nd_fh.write(json.dumps(rec) + "\n")
    nd_fh.flush()

    # pipeline-facing projection (labels.csv) — align_windows.py / validate_alignment.py
    NS = 1_000_000_000
    csv_w.writerow([scenario["id"], repeat_idx, short_stage(sid), target_id, sid,
                    epoch_to_iso(t_open_synced), epoch_to_iso(t_close_synced),
                    int(t_open_synced * NS), int(t_close_synced * NS), gpre, gpost])

    if not gate_ok:
        log(f"    [validity] WARNING gate FAILED (expected {expected}); kept for audit, excluded from headline")
    return rec


# ----------------------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--nodes", required=True)
    ap.add_argument("--out", default="./captures")
    ap.add_argument("--skew-ms-max", type=float, default=1.0)
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    man = load_yaml(a.manifest)
    nodes = load_yaml(a.nodes)
    tax = load_taxonomy(a.manifest, man)
    ssh = SSH(nodes.get("ssh_defaults", {}), a.dry_run)

    run_id = f"{man['campaign']['id_prefix']}-{utc_stamp()}-{uuid.uuid4().hex[:8]}"
    run_dir = os.path.join(a.out, run_id)
    os.makedirs(run_dir, exist_ok=True)
    nd_path = os.path.join(run_dir, "labels.ndjson")
    csv_path = os.path.join(run_dir, "labels.csv")
    manifest_path = os.path.join(run_dir, "run_manifest.json")
    log(f"[orchestrator] run_id={run_id} out={run_dir} dry={a.dry_run}")

    # ethics gate: any requires_airgap action => real ethics_ref mandatory
    needs_airgap = any(man["actions"][st["action_ref"]].get("requires_airgap")
                       for sc in man["scenarios"] for st in sc["stages"])
    ethics = man["campaign"].get("ethics_ref", "")
    if needs_airgap and (not ethics or ethics == "PENDING") and not a.dry_run:
        sys.exit("[ABORT] scenarios include contained-malware stages but campaign.ethics_ref is PENDING. "
                 "Set a written ethics-approval reference before live capture (Charter S11).")

    ok, pf_report = preflight(ssh, nodes, man, a.skew_ms_max)
    if not ok and not a.dry_run:
        json.dump(pf_report, open(os.path.join(run_dir, "preflight_FAILED.json"), "w"), indent=2)
        sys.exit(f"[ABORT] preflight failed: {pf_report['problems']}")

    # provenance / run manifest
    fingerprints = {}
    for dev_id, node in nodes["nodes"].items():
        if node.get("board") != "laptop_vm":
            fingerprints[dev_id] = {**collect_fingerprint(ssh, node),
                                    "board": node.get("board"), "arch": node.get("arch"),
                                    "declared_governor": node.get("pin_governor"),
                                    "declared_nvpmodel": node.get("nvpmodel_mode"),
                                    "host_syscall_source": node.get("host_syscall_source")}
    manifest = {
        "run_id": run_id, "schema_version": 2,
        "started_utc": datetime.now(timezone.utc).isoformat(),
        "orchestrator_host": platform.node(), "orchestrator_platform": platform.platform(),
        "time_master": man["campaign"].get("time_master"),
        "manifest_file": os.path.abspath(a.manifest), "nodes_file": os.path.abspath(a.nodes),
        "manifest_sha256": sha256_str(open(a.manifest, encoding="utf-8").read()),
        "nodes_sha256": sha256_str(open(a.nodes, encoding="utf-8").read()),
        "taxonomy_file": man.get("taxonomy_file"),
        "ethics_ref": ethics, "operator": man["campaign"].get("operator"),
        "defaults": man.get("defaults", {}),
        "benign": man.get("benign", {}),
        "preflight": pf_report, "device_fingerprints": fingerprints,
        "scenarios": [sc["id"] for sc in man["scenarios"]],
        "dry_run": a.dry_run,
    }
    json.dump(manifest, open(manifest_path, "w"), indent=2)
    log(f"[provenance] wrote {manifest_path}")

    defaults = man.get("defaults", {})
    n_stages = 0
    nd_fh = open(nd_path, "a", newline="")
    cf = open(csv_path, "a", newline="")
    csv_w = csv.writer(cf)
    if os.stat(csv_path).st_size == 0:
        csv_w.writerow(["scenario_id", "run_idx", "attack_type", "target", "stage",
                        "start_iso", "end_iso", "start_ns", "end_ns", "guard_pre_s", "guard_post_s"])
    try:
        for sc in man["scenarios"]:
            reps = sc.get("repeats", defaults.get("repeats", 1))
            for r in range(1, reps + 1):
                for si, stage_spec in enumerate(sc["stages"]):
                    rec = run_stage(ssh, nodes, man, tax, run_id, sc, r, si, stage_spec,
                                    defaults, nd_fh, csv_w, a.dry_run)
                    cf.flush()
                    n_stages += 1 if rec else 0
                    if not a.dry_run and si < len(sc["stages"]) - 1:
                        time.sleep(defaults.get("inter_stage_gap_s", 30))
                if not a.dry_run:
                    time.sleep(defaults.get("cooldown_s", 120))
    finally:
        nd_fh.close()
        cf.close()

    manifest["finished_utc"] = datetime.now(timezone.utc).isoformat()
    manifest["stages_executed"] = n_stages
    json.dump(manifest, open(manifest_path, "w"), indent=2)
    log(f"[orchestrator] done. stages={n_stages}  ndjson->{nd_path}  csv->{csv_path}")


if __name__ == "__main__":
    main()
