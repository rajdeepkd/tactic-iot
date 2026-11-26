# pipeline/

Harvest, clean, preprocess, align, and validate. This turns the raw per-board
captures into the final, labelled, four-modality windowed dataset, and gates it
for integrity.

## Flow

```
harvest.sh ─▶ anonymize_logs.py ─▶ align_windows.py ─▶ build_dual_layout.py ─▶ verify_* (gates)
                                        ▲
             zeek_tactic.zeek, pcap_to_connlog.py, organize_raw_pcaps.py feed the network modality
```

## Files

| File | Stage |
|------|-------|
| `harvest.sh` | Harvester. Pulls each run's raw artefacts from the boards to the hub. |
| `anonymize_logs.py` | Pseudonymises identifiers in logs with a salted, non-reversible HMAC-SHA256 tag (same token → same tag), so hostnames/users are consistent but not revealing. |
| `zeek_tactic.zeek` | Zeek script producing the network connection-log features. |
| `pcap_to_connlog.py`, `organize_raw_pcaps.py`, `add_bylabels_pcaps.py` | Packet-capture organisation and conn-log derivation; place full-snaplen pcaps into the by-label layout. |
| `derive_windows.py` | Derives the one-second (and longer) windows per modality from the harvested artefacts. |
| `align_windows.py` | **Window aligner.** Aligns the four modalities onto a common one-second grid and assembles the per-window feature vectors and modality mask. |
| `build_dual_layout.py` | Builds the dual on-disk layout (by-label and by-device/campaign views of the same windows). |
| `validate_alignment.py` | Checks that the aligned windows reproduce the exact readers'/timestamps' values. |
| `verify_run.py` | Per-run validation gate (a run must pass before it joins the corpus). |
| `verify_dataset.py` | Whole-dataset validation gate (schema, class floors, integrity). |
| `benign_overlap_audit.py` | Audits benign/attack window overlap. |
| `feature_manifest.yaml` | The feature dictionary: every per-modality feature and its definition. |

## Notes

- Window sizes are configurable; the dataset ships W1/W5/W8/W10 (1/5/8/10 s).
- The validation gates are strict by design: a run or corpus that fails a gate is
  rejected rather than silently included.
- `anonymize_logs.py` generates a fresh random salt per run unless one is
  supplied; keep the salt out of the repository.
