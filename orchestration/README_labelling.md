# Ground-truth labelling — Objective 3 testbed

**Claim we must be able to defend to a Transactions reviewer:** every record's label
is *caused and timestamped at capture time*, never guessed from the data afterward.
This document is the construction.

## 1. Why not post-hoc labelling

Inspecting pcaps/logs after the fact to decide "this looks like a scan" is circular:
the label would encode the same features the classifier learns, and any labelling
error correlates with the signal. We instead make the label a **property of the
experiment design**, independent of the captured features.

## 2. The mechanism

```
shared clock          all boards chrony-slaved to RPi5 (stratum master), µs offset
   │
orchestrator          every attack action launched ONLY via run_action.sh, which
   │                  brackets it with MASTER-clock start/end timestamps
   ▼
labels.csv            one row per action: an INTERVAL on the reference clock
   │                  scenario_id,run_idx,attack_type,target,stage,start_iso,end_iso
   ▼
align_windows.py      each victim window [w_start,w_end) is interval-joined to the
   label_window()     overlapping labels.csv row FOR THAT target device; greatest-
                      overlap wins; benign = overlaps nothing.
```

- **`target` = the victim hostname** (`rpi3b1`/`rpi3b2`). The label attaches to the
  victim's windows, where the footprint lands — not to the attacker.
- **`stage`** is the kill-chain label (`recon,bruteforce,delivery,execution,
  persistence,privesc,c2,exfil,ddos`) → gives the *stage-dependence* labels for free.
- **group_id** downstream = `scenario_id#run_idx` → per-execution pooling (prevents
  window-split leakage across the train/test boundary: split by group, never by row).

## 3. Accuracy safeguards (what makes it *accurate*, not just automatic)

1. **Master-clock timestamps.** Timestamps are taken on the stratum master (the
   attacker node = RPi5). Victim silos are slaved to it at µs, far tighter than the
   window width `W` (seconds). Boundary error ≪ W.
2. **Guard bands.** Windows within ±Δ of an interval edge are marked ambiguous /
   dropped (`label_overlap` < threshold), so a window straddling benign→attack is
   never confidently mislabelled. `label_overlap` (overlap fraction) is emitted per
   window; filter on it.
3. **Quiescent baselines.** Each campaign brackets its actions with baseline
   stretches that call *no* `run_action` → a real benign distribution, not merely
   "gaps between attacks."
4. **Benign-overlap shortcut audit (P7 lesson).** Before trusting the split, verify
   benign windows never contain the attack's tell (e.g. *benign must never scan*).
   If benign and attack share a trivially-separating artifact, the result is a
   shortcut, not detection — this audit is a release gate, not optional.
5. **Evidence log.** `run_action.sh` also appends `actions.jsonl` (rc, argv, wall
   time, output tail) per action → the campaign is reproducible and auditable, but
   the `.csv` interval, not the tool's own output, is the ground truth.

## 4. Files

| File | Runs on | Role |
|---|---|---|
| `run_action.sh` | attacker (RPi5 master) | wrap+timestamp one action → `labels.csv` row |
| `campaign_example.sh` | attacker | TEMPLATE campaign (dry-run until `EXECUTE=1`) |
| `../pipeline/align_windows.py` | control PC | interval-join `labels.csv` → per-window labels |

## 5. labels.csv schema (verbatim contract with align_windows.load_labels)

```
scenario_id,run_idx,attack_type,target,stage,start_iso,end_iso
C07,0,recon,rpi3b2,recon,2026-09-28T18:00:00.123456Z,2026-09-28T18:00:12.400011Z
```
`run_idx` and `stage` are optional to the reader (stage falls back to attack_type,
run_idx to 0) but **always emitted** by `run_action.sh`. Timestamps are UTC ISO-8601,
µs precision, master clock.

## 6. Gate before any campaign runs (still no attacks)

`campaign_example.sh` stays dry-run (`EXECUTE=0`) until **all** of:
- `stages.yaml` revised to the no-malware, silo-balanced scope;
- `nodes.yaml` reconciled from placeholder `10.0.0.x` to real `192.168.0.x`;
- always-on collectors (systemd) capturing so windows aren't sessionized;
- benign-overlap shortcut audit wired and passing on a benign-only capture.
