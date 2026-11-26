# orchestration/

Attack orchestration and labelling — the control plane of the testbed.

The orchestrator reads a declarative **attack catalogue** and drives time-boxed,
labelled campaigns against the victim boards. Because every action is scheduled
against one master clock, the exact start/stop of each attack stage is known and
is later used to label the collected windows.

## Files

| File | Role |
|------|------|
| `orchestrator.py` | Main orchestrator. Reads the catalogue, emits the hub-side action scripts, schedules stages, and records the ground-truth timeline. Key-based SSH to the boards only (no passwords). |
| `scenarios.yaml` | Attack catalogue: per-scenario actions, targets, containment flags, and whether a stage is operator-supplied or air-gapped. |
| `stages.yaml` | Canonical attack-stage taxonomy (the single source of truth for coarse/fine labels). |
| `nodes.yaml` | Testbed node inventory: roles, lab IP addresses, and privilege notes. |
| `campaigns.yaml` | Campaign definitions that compose scenarios into labelled runs. |
| `run_campaign.py` | Driver for a single campaign run. |
| `run_action.sh` | Executes one attack action on the hub side. |
| `campaign_example.sh` | A worked, minimal campaign example. |
| `labeller.py` | Assigns coarse/fine labels to windows from the recorded campaign timeline. |
| `finalize_dataset.py` | Assembles and finalises the labelled dataset from labelled runs. |
| `prod_batch.sh`, `prod_harvest.sh` | Production batch-run and harvest wrappers. |
| `v5_collect.sh`, `v5_topup.sh`, `v5_preflight.sh`, `v5_finalize.sh`, `v5_add_pcaps.sh` | The v5 collection sequence: preflight checks, collect, top-up under-represented classes, add full-snaplen pcaps, and finalise. |
| `v3_lib.sh` | Shared shell helpers (`V()` logging, `health_check()`) sourced by the collection scripts. |
| `README_labelling.md` | Notes on the labelling convention. |

## Notes

- The shell scripts assume the testbed deployment layout (a `$TB` testbed root
  with a hub and victim boards reachable over key-based SSH on an isolated
  network). They are provided to document the exact collection procedure.
- `scenarios.yaml` requires a real ethics reference and an air-gapped network
  before any attack stage will run. Keep it that way.
