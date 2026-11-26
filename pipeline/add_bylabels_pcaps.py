#!/usr/bin/env python3
r"""add_bylabels_pcaps.py -- ADDITIVE, per-run, checkpointed pcap slicer.

Unlike `build_dual_layout relabel` (which rmtrees and rebuilds all of By_labels in one
long shot -- fatal on a flaky external drive), this ONLY writes <stub>.pcap files into the
EXISTING By_labels/<stage>/<sub>/raw/network/ dirs, run by run, skipping slices that already
exist. Safe to re-run after a drive drop: completed runs are checkpointed and skipped.

Reads each By_device node's labels.csv + raw/network/cap_*.pcap. Replicates relabel's action
and benign-gap interval logic and stub naming so the .pcap sits beside the Zeek/CSV slices.

Env: DV (dataset root), SEC_LO, SEC_HI (run range), CKPT (checkpoint file).
"""
import os, sys, csv, glob, time, argparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import build_dual_layout as B   # slice_pcap, iso2epoch, utc_stamp, ensure

GAP_MIN = 3
PAD_IV  = 60

def drive_root(dv):
    # /f/... -> /f ; F:/... -> F:/
    p = dv.replace("\\", "/")
    return p[:2] if p[1:2] == ":" else "/" + p.strip("/").split("/")[0]

def drive_ok(root):
    try:
        t = os.path.join(root, ".wtest_pcap")
        with open(t, "w") as f: f.write("x")
        os.remove(t); return True
    except Exception:
        return False

def wait_drive(root, lim=180):
    n = 0
    while not drive_ok(root):
        if n >= lim: return False
        time.sleep(5); n += 5
    return True

def actions_of(lab):
    with open(lab, newline="") as fh:
        return list(csv.DictReader(fh))

def benign_intervals(acts_se):
    iv = []
    if acts_se:
        iv.append((acts_se[0][0] - PAD_IV, acts_se[0][0] - 1))
        for (ps, pe), (ns, ne) in zip(acts_se, acts_se[1:]):
            if ns - pe >= GAP_MIN:
                iv.append((pe + 1, ns - 1))
        iv.append((acts_se[-1][1] + 1, acts_se[-1][1] + PAD_IV))
    return iv

def main():
    dv   = os.environ.get("DV", "/f/Experiment/Objective_3/testbed/dataset_v5")
    lo   = int(os.environ.get("SEC_LO", "0"))
    hi   = int(os.environ.get("SEC_HI", "31"))
    ckpt = os.environ.get("CKPT", "/d/Experiment/Objective_3/testbed/dataset/v5_slice_checkpoint.txt")
    out  = os.path.join(dv, "By_labels")
    base = os.path.join(dv, "By_device_and_campaigns")
    root = drive_root(dv)

    done = set()
    if os.path.exists(ckpt):
        done = {l.split()[0] for l in open(ckpt) if l.strip()}

    if not wait_drive(root):
        print(f"[slice] ABORT: drive {root} not writable"); sys.exit(9)

    nodes = sorted(glob.glob(os.path.join(base, "*", "run*_V5")))
    processed = 0; failed = 0; need = []
    for node in nodes:
        run_name = os.path.basename(node)
        dev = os.path.basename(os.path.dirname(node))
        run_idx = run_name.split("_")[0].replace("run", "").lstrip("0") or "0"
        ri = int(run_idx)
        if ri < lo or ri > hi: continue
        key = f"{ri}:{dev}"
        if key in done:
            continue
        lab = os.path.join(node, "labels.csv")
        net = os.path.join(node, "raw", "network")
        pcaps = glob.glob(os.path.join(net, "cap_*.pcap"))
        if not os.path.exists(lab) or not pcaps:
            print(f"[slice] run {ri} ({dev}): no labels/pcap, skip"); continue
        if not wait_drive(root):
            print(f"[slice] run {ri}: DRIVE GONE >180s -- stop; re-run to resume"); need.append(ri); failed += 1; break
        try:
            acts = actions_of(lab)
            nslice = 0
            acts_se = []
            # attack action slices
            for act in acts:
                stg = (act.get("stage") or "").strip() or "unknown"
                sub = (act.get("attack_type") or "").strip() or stg
                try:
                    s, e = B.iso2epoch(act["start_iso"]), B.iso2epoch(act["end_iso"])
                except Exception:
                    continue
                acts_se.append((s, e))
                stub = f"{dev}_run{ri:02d}_{B.utc_stamp(s)}"
                rn = B.ensure(out, stg, sub, "raw", "network")
                op = os.path.join(rn, stub + ".pcap")
                if os.path.exists(op) and os.path.getsize(op) > 0:
                    continue
                B.slice_pcap(pcaps, s, e, op); nslice += 1
            # benign gap slices
            acts_se.sort()
            for (bs, be) in benign_intervals(acts_se):
                if be <= bs: continue
                stub = f"{dev}_run{ri:02d}_{B.utc_stamp(bs)}"
                rn = B.ensure(out, "benign", "benign", "raw", "network")
                op = os.path.join(rn, stub + ".pcap")
                if os.path.exists(op) and os.path.getsize(op) > 0:
                    continue
                B.slice_pcap(pcaps, bs, be, op); nslice += 1
            try:
                os.sync()
            except Exception:
                pass
            with open(ckpt, "a") as f: f.write(f"{key} {nslice}\n")
            processed += 1
            print(f"[slice] run {ri} ({dev}): {nslice} pcap slices [ckpt]")
        except OSError as ex:
            failed += 1; need.append(ri)
            print(f"[slice] run {ri} ({dev}): OSError {ex} -- drive drop? re-run to resume")
            break
        except Exception as ex:
            failed += 1; need.append(ri)
            print(f"[slice] run {ri} ({dev}): ERROR {ex}")
            break

    total = len(open(ckpt).readlines()) if os.path.exists(ckpt) else 0
    print(f"[slice] section done: processed={processed} failed={failed} ; checkpointed runs={total}/32")
    if failed:
        print(f"[slice] INCOMPLETE. still needed: {need}. Re-run to resume."); sys.exit(2)
    print("[slice] section OK")

if __name__ == "__main__":
    main()
