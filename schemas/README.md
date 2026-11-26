# schemas/

JSON Schemas that define the data contracts the pipeline enforces.

| File | Contract |
|------|----------|
| `label_record.schema.json` | A single ground-truth label record: campaign/run identity, attack stage and sub-label, and the time interval it covers. Produced by the orchestrator/labeller and consumed by `pipeline/align_windows.py`. |
| `window_record.schema.json` | A single one-second window record: per-modality feature fields, the modality-presence mask, and the assigned coarse/fine label. This is the unit the analysis operates on. |

The validation gates (`pipeline/verify_run.py`, `pipeline/verify_dataset.py`)
check records against these schemas before a run or the whole corpus is accepted.
