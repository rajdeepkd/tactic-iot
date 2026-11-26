#!/usr/bin/env python3
"""
build_dual_layout.py -- file one harvested+aligned run into the v2 dual store, and
project the label view from it. Two structures over ONE collection (never a second
capture), per docs/TACTIC-IoT_v2_collection_plan.md:

  By_device_and_campaigns/<device>/run<NN>_<scenario>/   PRIMARY, whole-run context
      raw/{network,host,telemetry}/ + preprocessed/windows_w{1,5}.csv + labels.csv
  By_labels/<stage>/<sub_label>/                         DERIVED projection
      raw/{network,host,telemetry}/<device>_run<NN>_<startUTC>.* (per-action slices)
      preprocessed/windows_w{1,5}.csv                    windows with that sub-label

The device tree is the source of truth. The label tree is rebuilt wholesale from it
(idempotent), so re-running never double-counts and group integrity is preserved
(one run = one group = one directory, no cross-run straddle, no benign/attack mix).

Subcommands:
  ingest   one run -> device tree (copies raw, filters preprocessed, writes manifest)
  relabel  rebuild By_labels/ from the whole device tree (slices raw, pools windows)

Usage:
  python build_dual_layout.py ingest --run-idx 4 --device rpi3b1 --scenario PROD \
      --work _work/p4 --aligned _work/p4_al --labels dataset/PROD_labels.csv \
      --pcaps-dir dataset/raw_pcaps/rpi3b1 --root dataset_v2
  python build_dual_layout.py relabel --root dataset_v2
"""
import argparse, csv, glob, hashlib, json, os, re, shutil, struct
from datetime import datetime, timezone

WINDOWS = (1,)   # V4: store W1 only (W5/W8/W10 are derivable by aggregating W1)
BENIGN_STAGES = {"", "normal", "benign", "S0_baseline_benign", "nan"}

# V4 per-modality preprocessed split: each fused windows_wN.csv is also written as four
# per-modality CSVs (key/label columns + that modality's feature columns only).
KEY_COLS = ["device_id", "window_idx", "window_start_iso", "group_id",
            "attack_type", "stage", "label_overlap", "modality_mask"]
MOD_PREFIXES = {"network": "net__", "host": "host__", "telemetry": "tel__", "applog": "applog__"}


# ---------------------------------------------------------------- helpers
def iso2epoch(s):
    return datetime.fromisoformat(str(s).replace("Z", "+00:00")).timestamp()


def utc_stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def ensure(*parts):
    d = os.path.join(*parts)
    os.makedirs(d, exist_ok=True)
    return d


def copy_if(src, dst):
    if src and os.path.exists(src):
        shutil.copy2(src, dst)
        return True
    return False


def first(paths):
    for p in paths:
        if os.path.exists(p):
            return p
    return None


# ---------------------------------------------------------------- pcap slicing (pure struct)
def pcap_meta(path):
    with open(path, "rb") as f:
        gh = f.read(24)
    m = gh[:4]
    if m == b"\xd4\xc3\xb2\xa1": return gh, "<", 1e6
    if m == b"\x4d\x3c\xb2\xa1": return gh, "<", 1e9
    if m == b"\xa1\xb2\xc3\xd4": return gh, ">", 1e6
    if m == b"\xa1\xb2\x3c\x4d": return gh, ">", 1e9
    raise ValueError("not a pcap: " + path)


def slice_pcap(src_files, s, e, out_path):
    """Write every packet in [s,e] from the (time-ordered) src pcaps to out_path.
    Returns (packets, bytes). Writes nothing and returns (0,0) if no packet matches."""
    writer = None
    pkts = nbytes = 0
    gh = en = div = None
    for p in sorted(src_files, key=lambda x: x):
        try:
            gh, en, div = pcap_meta(p)
        except ValueError:
            continue
        with open(p, "rb") as f:
            f.read(24)
            while True:
                rh = f.read(16)
                if len(rh) < 16:
                    break
                ts_s, ts_f, incl, orig = struct.unpack(en + "IIII", rh)
                data = f.read(incl)
                ts = ts_s + ts_f / div
                if s <= ts <= e:
                    if writer is None:
                        writer = open(out_path, "wb")
                        writer.write(gh)
                    writer.write(rh)
                    writer.write(data)
                    pkts += 1
                    nbytes += incl
    if writer:
        writer.close()
    return pkts, nbytes


# ---------------------------------------------------------------- host/telemetry slicing
def slice_auditd(src, s, e, out_path):
    """auditd lines carry audit(<epoch>.<ms>:<serial>). Keep those in [s,e]."""
    if not (src and os.path.exists(src)):
        return 0
    import re
    rx = re.compile(r"audit\((\d+)\.")
    n = 0
    with open(src, errors="replace") as fin, open(out_path, "w", newline="\n") as fout:
        for line in fin:
            m = rx.search(line)
            if m and s <= int(m.group(1)) <= e:
                fout.write(line)
                n += 1
    if n == 0:
        os.remove(out_path)
    return n


def slice_journald(src, s, e, out_path):
    """journald -o json: one object per line with __REALTIME_TIMESTAMP (us)."""
    if not (src and os.path.exists(src)):
        return 0
    n = 0
    with open(src, errors="replace") as fin, open(out_path, "w", newline="\n") as fout:
        for line in fin:
            try:
                ts = int(json.loads(line).get("__REALTIME_TIMESTAMP", 0)) / 1e6
            except Exception:
                continue
            if s <= ts <= e:
                fout.write(line)
                n += 1
    if n == 0:
        os.remove(out_path)
    return n


def slice_telemetry(src, s, e, out_path):
    """2 Hz telemetry csv with ts_realtime_ns. Keep header + samples in [s,e]."""
    if not (src and os.path.exists(src)):
        return 0
    with open(src, newline="") as fin:
        rdr = csv.reader(fin)
        try:
            header = next(rdr)
        except StopIteration:
            return 0
        if "ts_realtime_ns" not in header:
            return 0
        ci = header.index("ts_realtime_ns")
        rows = [r for r in rdr if r and len(r) > ci and r[ci].isdigit()
                and s <= int(r[ci]) / 1e9 <= e]
    if not rows:
        return 0
    with open(out_path, "w", newline="\n") as fout:
        w = csv.writer(fout)
        w.writerow(header)
        w.writerows(rows)
    return len(rows)


def slice_applog(src, s, e, out_path):
    """v3 app-log: lines 'epoch: message'. Keep those whose leading epoch is in [s,e]."""
    if not src or not os.path.exists(src):
        return 0
    n = 0
    with open(src, encoding="utf-8", errors="replace") as f, \
            open(out_path, "w", encoding="utf-8") as o:
        for line in f:
            m = re.match(r"^(\d+):", line)
            if m and s <= int(m.group(1)) <= e:
                o.write(line); n += 1
    return n


# ---------------------------------------------------------------- network csv / zeek slicing (v3: no pcap kept)
def load_tscsv(path):
    """Load a ts-first CSV (pkts/arp/coap) once as (header, [(ts, row), ...])."""
    if not path or not os.path.exists(path):
        return None
    with open(path, newline="") as f:
        rdr = csv.reader(f)
        try:
            header = next(rdr)
        except StopIteration:
            return None
        if "ts" not in header:
            return None
        ti = header.index("ts")
        data = []
        for r in rdr:
            if len(r) <= ti:
                continue
            try:
                t = float(r[ti])
            except ValueError:
                continue
            data.append((t, r))
    return header, data


def write_tscsv_slice(loaded, s, e, out_path):
    """Write the rows of a loaded ts-first CSV whose ts lies in [s,e]. Skip if none."""
    if not loaded:
        return 0
    header, data = loaded
    rows = [r for (t, r) in data if s <= t <= e]
    if not rows:
        return 0
    with open(out_path, "w", newline="\n") as f:
        w = csv.writer(f)
        w.writerow(header)
        w.writerows(rows)
    return len(rows)


def load_zeek(path):
    """Load a Zeek TSV log once as (comment_header_lines, [(ts, line), ...])."""
    head, data = [], []
    with open(path, errors="replace") as f:
        for line in f:
            if line.startswith("#"):
                head.append(line)
                continue
            p = line.split("\t", 1)
            try:
                t = float(p[0])
            except (ValueError, IndexError):
                continue
            data.append((t, line))
    return head, data


def write_zeek_slice(loaded, s, e, out_path):
    """Write a Zeek log keeping its #header, the data lines in [s,e], then #close. Skip if none."""
    head, data = loaded
    rows = [ln for (t, ln) in data if s <= t <= e]
    if not rows:
        return 0
    with open(out_path, "w", newline="") as f:
        for ln in head:
            if not ln.startswith("#close"):
                f.write(ln)
        for ln in rows:
            f.write(ln)
        for ln in head:
            if ln.startswith("#close"):
                f.write(ln)
    return len(rows)


# ---------------------------------------------------------------- preprocessed filtering
def read_csv_rows(path):
    with open(path, newline="") as f:
        rdr = csv.DictReader(f)
        return rdr.fieldnames, list(rdr)


def write_csv_rows(path, fieldnames, rows):
    ensure(os.path.dirname(path))
    with open(path, "w", newline="\n") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames, restval="", extrasaction="ignore")
        w.writeheader()
        w.writerows(rows)


def write_modality_splits(windows_path):
    """V4: from a fused windows_wN.csv, write the four per-modality split CSVs beside it
    (windows_wN_{network,host,telemetry,applog}.csv), each = the key/label columns plus
    that modality's prefixed feature columns. Pure column projection of the fused file."""
    if not os.path.exists(windows_path):
        return
    fn, rows = read_csv_rows(windows_path)
    keys = [c for c in KEY_COLS if c in fn]
    base = windows_path[:-4] if windows_path.endswith(".csv") else windows_path
    for modname, pfx in MOD_PREFIXES.items():
        modcols = [c for c in fn if c.startswith(pfx)]
        write_csv_rows(f"{base}_{modname}.csv", keys + modcols, rows)


def stage_sub(row):
    """(coarse_stage, sub_label) for a window row, folding benign to benign/benign."""
    stg = str(row.get("stage", "")).strip()
    at = str(row.get("attack_type", "")).strip()
    if stg.lower() in BENIGN_STAGES or at.lower() in BENIGN_STAGES:
        return "benign", "benign"
    return stg or "unknown", at or stg or "unknown"


# ---------------------------------------------------------------- ingest
def ingest(a):
    VN = a.device
    run_dir = ensure(a.root, "By_device_and_campaigns", VN, f"run{a.run_idx:02d}_{a.scenario}")
    net_d = ensure(run_dir, "raw", "network")
    zeek_d = ensure(net_d, "zeek")
    host_d = ensure(run_dir, "raw", "host")
    tel_d = ensure(run_dir, "raw", "telemetry")
    app_d = ensure(run_dir, "raw", "applog")   # v3: 4th modality (broker/coap/modbus logs)
    prep_d = ensure(run_dir, "preprocessed")

    # --- raw network: zeek logs (strip .<VN>), arp/coap/pkts csv, pcaps ---
    zeek_names = ("conn", "ssh", "dns", "http", "weird", "mqtt_connect",
                  "mqtt_publish", "mqtt_subscribe", "modbus", "snmp")
    for name in zeek_names:
        copy_if(first([os.path.join(a.work, f"{name}.log.{VN}")]),
                os.path.join(zeek_d, f"{name}.log"))
    for base in ("arp", "coap", "pkts"):
        copy_if(first([os.path.join(a.work, f"{base}.{VN}.csv")]),
                os.path.join(net_d, f"{base}.csv"))
    npcap = 0
    if a.pcaps_dir and os.path.isdir(a.pcaps_dir):
        for p in glob.glob(os.path.join(a.pcaps_dir, f"cap_{VN}_*.pcap")):
            copy_if(p, os.path.join(net_d, os.path.basename(p)))
            npcap += 1

    # --- raw host + telemetry ---
    copy_if(first([os.path.join(a.work, f"audit_{VN}.log")]), os.path.join(host_d, "audit.log"))
    copy_if(first([os.path.join(a.work, f"journald_{VN}.json")]), os.path.join(host_d, "journald.json"))
    copy_if(first([os.path.join(a.work, f"telemetry_{VN}_win.csv")]),
            os.path.join(tel_d, "telemetry_2hz.csv"))
    copy_if(first([os.path.join(a.work, f"collector_cpu_{VN}.csv"),
                   os.path.join(a.work, f"collector_cpu.{VN}.csv")]),
            os.path.join(tel_d, "collector_cpu.csv"))

    # --- raw applog (v3 4th modality): per-protocol daemon logs, sliced to the window ---
    for proto in ("mqtt", "coap", "modbus"):
        copy_if(first([os.path.join(a.work, f"applog_{proto}_{VN}.log")]),
                os.path.join(app_d, f"{proto}.log"))

    # --- preprocessed windows (filter to this device) ---
    nwin = {}
    for w in WINDOWS:
        src = first([os.path.join(a.aligned, f"fused_windows_W{w}.csv")])
        if not src:
            continue
        fn, rows = read_csv_rows(src)
        rows = [r for r in rows if str(r.get("device_id", VN)) in (VN, "", "unknown")] or rows
        wp = os.path.join(prep_d, f"windows_w{w}.csv")
        write_csv_rows(wp, fn, rows)
        write_modality_splits(wp)
        nwin[w] = len(rows)

    # --- labels slice (this run + device) ---
    lab_rows = []
    if a.labels and os.path.exists(a.labels):
        fn, rows = read_csv_rows(a.labels)
        lab_rows = [r for r in rows if str(r.get("run_idx")) == str(a.run_idx)
                    and str(r.get("target")) == VN]
        write_csv_rows(os.path.join(run_dir, "labels.csv"), fn, lab_rows)

    # --- run manifest ---
    man = {
        "run_idx": a.run_idx, "device": VN, "scenario": a.scenario,
        "stage_order_seed": a.order_seed, "single_shot": bool(a.single_shot),
        "n_pcaps": npcap, "n_actions": len(lab_rows),
        "windows": nwin, "ingested_utc": datetime.now(timezone.utc).isoformat(),
    }
    json.dump(man, open(os.path.join(run_dir, "run_manifest.json"), "w"), indent=2)
    print(f"[ingest] {VN} run{a.run_idx:02d}_{a.scenario}: "
          f"pcaps={npcap} actions={len(lab_rows)} windows={nwin} -> {run_dir}")


# ---------------------------------------------------------------- relabel (projection)
def relabel(a):
    base = os.path.join(a.root, "By_device_and_campaigns")
    out = os.path.join(a.root, "By_labels")
    if os.path.isdir(out):
        shutil.rmtree(out)
    ensure(out)

    pooled = {}        # (stage, sub, w) -> (fieldnames, [rows])
    map_rows = []

    for dev in sorted(os.listdir(base)) if os.path.isdir(base) else []:
        dev_dir = os.path.join(base, dev)
        if not os.path.isdir(dev_dir):
            continue
        for run_name in sorted(os.listdir(dev_dir)):
            run_dir = os.path.join(dev_dir, run_name)
            if not os.path.isdir(run_dir):
                continue
            run_idx = run_name.split("_")[0].replace("run", "").lstrip("0") or "0"

            # --- pool preprocessed windows by (stage, sub) ---
            for w in WINDOWS:
                src = os.path.join(run_dir, "preprocessed", f"windows_w{w}.csv")
                if not os.path.exists(src):
                    continue
                fn, rows = read_csv_rows(src)
                for r in rows:
                    stg, sub = stage_sub(r)
                    key = (stg, sub, w)
                    if key not in pooled:
                        pooled[key] = (list(fn), [])
                    else:
                        # union columns across runs: a run that saw HTTP adds
                        # net__http_* columns that quiet runs lack, so the pooled
                        # header must be their superset or the writer rejects the
                        # extra fields (restval="" fills the gaps for quiet runs).
                        existing = pooled[key][0]
                        for c in fn:
                            if c not in existing:
                                existing.append(c)
                    pooled[key][1].append(r)

            # --- slice raw per attack action into the label tree ---
            lab = os.path.join(run_dir, "labels.csv")
            if not os.path.exists(lab):
                continue
            _, actions = read_csv_rows(lab)
            net_dir = os.path.join(run_dir, "raw", "network")
            pcaps = glob.glob(os.path.join(net_dir, "cap_*.pcap"))
            # v3 keeps network as ts-first CSVs + Zeek logs (no raw pcap). Load once per run.
            net_csv = {b: load_tscsv(os.path.join(net_dir, f"{b}.csv")) for b in ("pkts", "arp", "coap")}
            zeek_src = {}
            zeek_dir = os.path.join(net_dir, "zeek")
            if os.path.isdir(zeek_dir):
                for zl in sorted(glob.glob(os.path.join(zeek_dir, "*.log"))):
                    zeek_src[os.path.splitext(os.path.basename(zl))[0]] = load_zeek(zl)
            audit = os.path.join(run_dir, "raw", "host", "audit.log")
            jrnl = os.path.join(run_dir, "raw", "host", "journald.json")
            tel = os.path.join(run_dir, "raw", "telemetry", "telemetry_2hz.csv")
            applogs = {p: os.path.join(run_dir, "raw", "applog", f"{p}.log") for p in ("mqtt", "coap", "modbus")}
            for act in actions:
                stg = str(act.get("stage", "")).strip() or "unknown"
                sub = str(act.get("attack_type", "")).strip() or stg
                try:
                    s, e = iso2epoch(act["start_iso"]), iso2epoch(act["end_iso"])
                except Exception:
                    continue
                stamp = utc_stamp(s)
                stub = f"{dev}_run{int(run_idx):02d}_{stamp}"
                rn = ensure(out, stg, sub, "raw", "network")
                rh = ensure(out, stg, sub, "raw", "host")
                rt = ensure(out, stg, sub, "raw", "telemetry")
                ra = ensure(out, stg, sub, "raw", "applog")
                pk, nb = (0, 0)
                if pcaps:
                    pk, nb = slice_pcap(pcaps, s, e, os.path.join(rn, stub + ".pcap"))
                # network (v3): slice the ts-first CSVs and the Zeek logs into the label tree
                npk = write_tscsv_slice(net_csv["pkts"], s, e, os.path.join(rn, f"{stub}.pkts.csv"))
                write_tscsv_slice(net_csv["arp"], s, e, os.path.join(rn, f"{stub}.arp.csv"))
                write_tscsv_slice(net_csv["coap"], s, e, os.path.join(rn, f"{stub}.coap.csv"))
                for zname, zloaded in zeek_src.items():
                    write_zeek_slice(zloaded, s, e, os.path.join(rn, f"{stub}.{zname}.zeek.log"))
                na = slice_auditd(audit, s, e, os.path.join(rh, stub + ".audit.log"))
                nj = slice_journald(jrnl, s, e, os.path.join(rh, stub + ".journald.json"))
                nt = slice_telemetry(tel, s, e, os.path.join(rt, stub + ".telemetry.csv"))
                for proto, ap in applogs.items():
                    slice_applog(ap, s, e, os.path.join(ra, f"{stub}.{proto}.log"))
                net_pkts = pk or npk
                map_rows.append(dict(device=dev, run=int(run_idx), stage=stg, sub_label=sub,
                                     start_iso=act["start_iso"], end_iso=act["end_iso"],
                                     packets=net_pkts, bytes=nb, audit_lines=na,
                                     journald_lines=nj, telemetry_rows=nt,
                                     slice=f"{stg}/{sub}/raw/network/{stub}.pkts.csv" if net_pkts else ""))

            # --- slice BENIGN baseline (the gaps BETWEEN attack actions, plus a lead-in
            # before the first action and a tail after the last) into benign/benign/raw.
            # Benign is not an action in labels.csv, so without this the benign label gets
            # pooled preprocessed windows but ZERO raw (V4 pilot gap). These gaps are the
            # pure-baseline periods that align labels "normal"; multiple benign slices per
            # run is expected and fine. Reuses this run's already-loaded raw sources.
            GAP_MIN = 3    # s: skip sub-3s slivers between back-to-back actions
            PAD_IV = 60    # s: benign lead-in before first action / tail after last
            acts_se = []
            for act in actions:
                try:
                    acts_se.append((iso2epoch(act["start_iso"]), iso2epoch(act["end_iso"])))
                except Exception:
                    continue
            acts_se.sort()
            benign_iv = []
            if acts_se:
                benign_iv.append((acts_se[0][0] - PAD_IV, acts_se[0][0] - 1))
                for (ps, pe), (ns, ne) in zip(acts_se, acts_se[1:]):
                    if ns - pe >= GAP_MIN:
                        benign_iv.append((pe + 1, ns - 1))
                benign_iv.append((acts_se[-1][1] + 1, acts_se[-1][1] + PAD_IV))
            for (bs, be) in benign_iv:
                if be <= bs:
                    continue
                stamp = utc_stamp(bs)
                stub = f"{dev}_run{int(run_idx):02d}_{stamp}"
                rn = ensure(out, "benign", "benign", "raw", "network")
                rh = ensure(out, "benign", "benign", "raw", "host")
                rt = ensure(out, "benign", "benign", "raw", "telemetry")
                ra = ensure(out, "benign", "benign", "raw", "applog")
                pk, nb = (0, 0)
                if pcaps:
                    pk, nb = slice_pcap(pcaps, bs, be, os.path.join(rn, stub + ".pcap"))
                npk = write_tscsv_slice(net_csv["pkts"], bs, be, os.path.join(rn, f"{stub}.pkts.csv"))
                write_tscsv_slice(net_csv["arp"], bs, be, os.path.join(rn, f"{stub}.arp.csv"))
                write_tscsv_slice(net_csv["coap"], bs, be, os.path.join(rn, f"{stub}.coap.csv"))
                for zname, zloaded in zeek_src.items():
                    write_zeek_slice(zloaded, bs, be, os.path.join(rn, f"{stub}.{zname}.zeek.log"))
                na = slice_auditd(audit, bs, be, os.path.join(rh, stub + ".audit.log"))
                nj = slice_journald(jrnl, bs, be, os.path.join(rh, stub + ".journald.json"))
                nt = slice_telemetry(tel, bs, be, os.path.join(rt, stub + ".telemetry.csv"))
                for proto, ap in applogs.items():
                    slice_applog(ap, bs, be, os.path.join(ra, f"{stub}.{proto}.log"))
                net_pkts = pk or npk
                map_rows.append(dict(device=dev, run=int(run_idx), stage="benign", sub_label="benign",
                                     start_iso=datetime.fromtimestamp(bs, timezone.utc).isoformat(),
                                     end_iso=datetime.fromtimestamp(be, timezone.utc).isoformat(),
                                     packets=net_pkts, bytes=nb, audit_lines=na,
                                     journald_lines=nj, telemetry_rows=nt,
                                     slice=f"benign/benign/raw/network/{stub}.pkts.csv" if net_pkts else ""))

    # --- write pooled preprocessed windows (+ per-modality splits) ---
    for (stg, sub, w), (fn, rows) in sorted(pooled.items()):
        wp = os.path.join(out, stg, sub, "preprocessed", f"windows_w{w}.csv")
        write_csv_rows(wp, fn, rows)
        write_modality_splits(wp)

    # --- label_map.csv ---
    if map_rows:
        write_csv_rows(os.path.join(out, "label_map.csv"),
                       ["device", "run", "stage", "sub_label", "start_iso", "end_iso",
                        "packets", "bytes", "audit_lines", "journald_lines",
                        "telemetry_rows", "slice"], map_rows)

    # --- summary ---
    agg = {}
    for (stg, sub, w), (_, rows) in pooled.items():
        if w == 1:
            agg[(stg, sub)] = len(rows)
    print(f"{'stage':20}{'sub_label':28}{'windows_w1':>12}")
    for (stg, sub), n in sorted(agg.items()):
        print(f"{stg:20}{sub:28}{n:>12}")
    print(f"[relabel] {len(agg)} sub-labels, {len(map_rows)} action slices -> {out}")


# ---------------------------------------------------------------- manifest
def write_manifest(root):
    for tree in ("By_device_and_campaigns", "By_labels"):
        d = os.path.join(root, tree)
        if not os.path.isdir(d):
            continue
        man = os.path.join(d, "_MANIFEST.md5")
        with open(man, "w", newline="\n") as mf:
            for p in sorted(glob.glob(os.path.join(d, "**", "*"), recursive=True)):
                if os.path.isfile(p) and os.path.basename(p) != "_MANIFEST.md5":
                    h = hashlib.md5(open(p, "rb").read()).hexdigest()
                    mf.write(f"{h}  {os.path.relpath(p, d).replace(os.sep, '/')}\n")
        print(f"[manifest] {tree}/_MANIFEST.md5")


# ---------------------------------------------------------------- cli
def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    ig = sub.add_parser("ingest", help="file one run into the device tree")
    ig.add_argument("--run-idx", type=int, required=True)
    ig.add_argument("--device", required=True)
    ig.add_argument("--scenario", default="PROD")
    ig.add_argument("--work", required=True, help="harvest output dir (audit_/journald_/*.log.<VN>)")
    ig.add_argument("--aligned", required=True, help="align_windows out dir (fused_windows_W*.csv)")
    ig.add_argument("--labels", default=None, help="master labels.csv")
    ig.add_argument("--pcaps-dir", default=None, help="dir with cap_<device>_*.pcap for this run")
    ig.add_argument("--order-seed", type=int, default=None, help="stage-order seed, for the manifest")
    ig.add_argument("--single-shot", action="store_true", help="record run as single-shot (B3)")
    ig.add_argument("--root", default="dataset_v2")
    ig.add_argument("--manifest", action="store_true", help="also regenerate md5 manifests")

    rl = sub.add_parser("relabel", help="rebuild By_labels/ from the device tree")
    rl.add_argument("--root", default="dataset_v2")
    rl.add_argument("--manifest", action="store_true", help="also regenerate md5 manifests")

    a = ap.parse_args()
    if a.cmd == "ingest":
        ingest(a)
    elif a.cmd == "relabel":
        relabel(a)
    if getattr(a, "manifest", False):
        write_manifest(a.root)


if __name__ == "__main__":
    main()
