#!/usr/bin/env python3
"""
organize_raw_pcaps.py -- turn the archived rolling captures into STAGE-LABELLED pcaps.

Each 600 s rolling capture contains a full kill-chain run (recon -> ... ->
defense_evasion) plus benign background, so a whole file cannot carry a single
stage label. Instead we SLICE every action interval from PROD_labels.csv out of the
captures (pure struct, no pcap library) into clean per-action pcaps, filed under a
stage-named directory. Benign-only captures are kept whole. Originals that contain
attacks are preserved intact under _source_with_attacks/ so slicing is reproducible.

Timestamps: labels are UTC; packet times are read from the pcap record headers
(epoch, TZ-independent). Supports us (0xa1b2c3d4) and ns (0xa1b23c4d) pcap, either endian.

Layout produced under raw_pcaps/:
  by_stage/<stage>/<device>/run<NN>_<attack_type>_<startUTC>.pcap   clean action slices
  benign/<device>/<original>.pcap                                   benign-only captures
  _source_with_attacks/<device>/<original>.pcap                     intact sources of slices
  pcap_label_map.csv    one row per action: slice path, packets, bytes, source files
  PCAP_MANIFEST.md5     regenerated over the new tree
"""
import os, struct, csv, glob, shutil, hashlib, collections
from datetime import datetime, timezone

DS = r"D:\Experiment\Objective_3\testbed\dataset"
RP = os.path.join(DS, "raw_pcaps")
LABELS = os.path.join(DS, "PROD_labels.csv")
CAP_SECONDS = 600

def iso2epoch(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()

def pcap_meta(path):
    """Return (global_header_bytes, endian, frac_divisor)."""
    with open(path, "rb") as f:
        gh = f.read(24)
    m = gh[:4]
    if m == b"\xd4\xc3\xb2\xa1": return gh, "<", 1e6      # us LE
    if m == b"\x4d\x3c\xb2\xa1": return gh, "<", 1e9      # ns LE
    if m == b"\xa1\xb2\xc3\xd4": return gh, ">", 1e6      # us BE
    if m == b"\xa1\xb2\x3c\x4d": return gh, ">", 1e9      # ns BE
    raise ValueError("not a pcap: " + path)

def first_pkt_epoch(path):
    gh, en, _ = pcap_meta(path)
    with open(path, "rb") as f:
        f.seek(24); rh = f.read(16)
    if len(rh) < 16: return None
    return float(struct.unpack(en + "IIII", rh)[0])

# ---- actions (one slice each) ----
acts = collections.defaultdict(list)           # device -> list of action dicts
for r in csv.DictReader(open(LABELS)):
    acts[r["target"]].append(dict(run=int(r["run_idx"]), attack=r["attack_type"], stage=r["stage"],
                                   s=iso2epoch(r["start_iso"]), e=iso2epoch(r["end_iso"])))

rows = []                                       # mapping-csv rows
for dev in ("rpi3b1", "rpi3b2"):
    files = sorted(glob.glob(os.path.join(RP, dev, "*.pcap")), key=first_pkt_epoch)
    if not files:
        continue
    gh, en, div = pcap_meta(files[0])
    A = sorted(acts[dev], key=lambda a: a["s"])
    for a in A:
        a.update(writer=None, path=None, pkts=0, bytes=0, srcs=set())
    file_cov = {}                               # file -> [fp, fp+CAP] span
    for p in files:
        fp = first_pkt_epoch(p); file_cov[p] = (fp, fp + CAP_SECONDS)
    # single time-ordered pass over all packets; pointer into sorted actions
    ai = 0
    for p in files:
        with open(p, "rb") as f:
            f.read(24)
            while True:
                rh = f.read(16)
                if len(rh) < 16: break
                ts_s, ts_f, incl, orig = struct.unpack(en + "IIII", rh)
                data = f.read(incl)
                ts = ts_s + ts_f / div
                while ai < len(A) and ts > A[ai]["e"]:
                    ai += 1
                if ai < len(A) and A[ai]["s"] <= ts <= A[ai]["e"]:
                    a = A[ai]
                    if a["writer"] is None:
                        d = os.path.join(RP, "by_stage", a["stage"], dev)
                        os.makedirs(d, exist_ok=True)
                        tstamp = datetime.fromtimestamp(a["s"], timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                        a["path"] = os.path.join(d, f"run{a['run']:02d}_{a['attack']}_{tstamp}.pcap")
                        a["writer"] = open(a["path"], "wb"); a["writer"].write(gh)
                    a["writer"].write(rh); a["writer"].write(data)
                    a["pkts"] += 1; a["bytes"] += incl; a["srcs"].add(os.path.basename(p))
    for a in A:
        if a["writer"]:
            a["writer"].close()
        rows.append(dict(device=dev, run=a["run"], stage=a["stage"], attack=a["attack"],
                         start_iso=datetime.fromtimestamp(a["s"], timezone.utc).isoformat(),
                         end_iso=datetime.fromtimestamp(a["e"], timezone.utc).isoformat(),
                         packets=a["pkts"], bytes=a["bytes"],
                         slice=os.path.relpath(a["path"], RP).replace("\\", "/") if a["path"] else "",
                         source_files="|".join(sorted(a["srcs"]))))
    # bucket whole source files: benign-only vs contains-attacks
    attack_spans = [(a["s"], a["e"]) for a in A]
    for p in files:
        c0, c1 = file_cov[p]
        has_attack = any(c0 <= e and s <= c1 for s, e in attack_spans)
        sub = "_source_with_attacks" if has_attack else "benign"
        d = os.path.join(RP, sub, dev); os.makedirs(d, exist_ok=True)
        shutil.move(p, os.path.join(d, os.path.basename(p)))

# ---- mapping CSV ----
with open(os.path.join(RP, "pcap_label_map.csv"), "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["device", "run", "stage", "attack", "start_iso", "end_iso",
                                      "packets", "bytes", "slice", "source_files"])
    w.writeheader(); w.writerows(rows)

# ---- summary ----
st = collections.defaultdict(lambda: [0, 0, 0])      # stage -> [slices, packets, empty]
for r in rows:
    st[r["stage"]][0] += 1; st[r["stage"]][1] += r["packets"]
    if r["packets"] == 0: st[r["stage"]][2] += 1
print(f"{'stage':18}{'slices':>8}{'packets':>12}{'empty':>8}")
for s in sorted(st):
    v = st[s]; print(f"{s:18}{v[0]:>8}{v[1]:>12}{v[2]:>8}")
tot_b = sum(len(glob.glob(os.path.join(RP, 'benign', d, '*.pcap'))) for d in ('rpi3b1', 'rpi3b2'))
tot_src = sum(len(glob.glob(os.path.join(RP, '_source_with_attacks', d, '*.pcap'))) for d in ('rpi3b1', 'rpi3b2'))
print(f"benign whole captures: {tot_b} | source(attack) captures: {tot_src} | action slices: {len(rows)}")

# ---- regenerate md5 manifest ----
man = os.path.join(RP, "PCAP_MANIFEST.md5")
with open(man, "w", newline="\n") as mf:
    for p in sorted(glob.glob(os.path.join(RP, "**", "*.pcap"), recursive=True)):
        h = hashlib.md5(open(p, "rb").read()).hexdigest()
        mf.write(f"{h}  {os.path.relpath(p, RP).replace(os.sep, '/')}\n")
print("PCAP_MANIFEST.md5 regenerated")
