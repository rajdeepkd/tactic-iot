# TACTIC-IoT

**T**estbed for **A**ttack **C**ampaigns with **T**ime-synchronised **I**oT **C**ollection.

This repository holds the complete code used to build and analyse **TACTIC-IoT**, a
multi-modal IoT intrusion dataset. It covers the entire pipeline: attack
orchestration, four-modality data collection, harvesting and cleaning, window
alignment and preprocessing, dataset validation, and the analysis that produces
every table and figure in the accompanying Data Descriptor.

## About the dataset

TACTIC-IoT records **four synchronised observation planes** on real IoT hardware:

1. **Network traffic** — packet capture plus Zeek connection logs,
2. **Host logs** — audit events, authentication logs, and syscall activity,
3. **Resource telemetry** — CPU, memory, and process statistics, and
4. **Application-service logs** — from the MQTT, CoAP, and Modbus daemons.

Collection used **32 labelled campaigns** on **two Raspberry Pi victims** under a
single master clock, yielding **167,145 one-second windows** (48,007 benign +
119,138 attack) with per-modality features and a modality mask. The dataset
covers **12 coarse attack labels** and **29 fine sub-labels**, with benign
activity that exercises authenticated IoT services. Features are computed at four
window lengths (1 s, 5 s, 8 s, 10 s).

The central finding the code supports: *no modality is redundant*. Every modality
carries label information, and removing any one of the four lowers multiclass
macro-F1.

> **Dataset download.** The dataset itself is deposited separately and is not in
> this repository. See the Data Descriptor's *Data availability* statement for the
> repository and persistent identifier.

## Repository layout

| Directory | Stage | What it contains |
|-----------|-------|------------------|
| [`orchestration/`](orchestration/) | Attack orchestration | The orchestrator, attack catalogue (`scenarios.yaml`, `stages.yaml`), node inventory, per-campaign runners, and labelling. |
| [`collectors/`](collectors/) | Data collection (sensors) | Network capture, host audit/auth/syscall collectors, resource telemetry, log shipping, and the systemd units that run them on each board. |
| [`services/`](services/) | Data collection (victim services) | The MQTT / CoAP / Modbus / RTSP / SNMP daemons and the command handler that make the victims behave like real IoT devices. |
| [`benign/`](benign/) | Data collection (background) | Benign-traffic and benign-workload generators that produce the normal-activity baseline. |
| [`pipeline/`](pipeline/) | Harvest, clean, preprocess, validate | Harvesting, log pseudonymisation, window alignment, dual-layout build, pcap organisation, and the per-run / whole-dataset validation gates. |
| [`analysis/`](analysis/) | Analysis experiments | The complete v5 analysis that produces every Technical-Validation table and figure, plus the manuscript statistics. |
| [`schemas/`](schemas/) | Contracts | JSON schemas for the label and window records. |
| [`timesync/`](timesync/) | Infrastructure | chrony and high-precision rsyslog configuration for the one-master-clock design. |

Each directory has its own `README.md` describing its files and how they fit the pipeline.

## End-to-end flow

```
            orchestration/                collectors/ + services/ + benign/
         ┌──────────────────┐          ┌──────────────────────────────────┐
 catalogue -> orchestrator  ──drives──▶  victim boards emit 4 modalities   │
         └──────────────────┘          └──────────────────────────────────┘
                                                     │ raw captures
                                                     ▼
                                           pipeline/ harvest.sh
                                                     │
                      pseudonymise ──▶ align windows ──▶ build dual layout
                                                     │
                                            validate (verify_run /
                                             verify_dataset gates)
                                                     │  final dataset
                                                     ▼
                                           analysis/ exp_v5_analysis.py
                                        ──▶ CSVs ──▶ make_v5_figures / tables
```

## Quick start

```bash
# 1. Install Python dependencies (analysis needs only the first group)
python -m pip install -r requirements.txt

# 2. Reproduce the analysis from the deposited dataset
#    (point --data at the dataset's By_labels root; see analysis/README.md)
python analysis/exp_v5_analysis.py --data /path/to/TACTIC-IoT/By_labels --out results/
python analysis/make_v5_tables.py  --in results/ --out tables/
python analysis/make_v5_figures.py --in results/ --out figs/

# A fast end-to-end smoke test (subsampled, tiny models):
python analysis/exp_v5_analysis.py --data /path/to/TACTIC-IoT/By_labels --smoke --out results_smoke/
```

Re-running the **live collection** requires the physical testbed (two Raspberry
Pi victims, a hub/orchestrator, and an isolated network). The collection code is
provided for transparency and reproducibility of method; the `orchestration/`,
`collectors/`, `services/`, and `benign/` READMEs describe the deployment.

## Reproducibility notes

- All modelling is deterministic (`random_state = 42`) and uses a strict
  **grouped-by-run** train/test split, so no window from a test run is ever seen
  in training.
- RandomForest is the fixed detector in the per-class and ablation experiments so
  that those comparisons isolate the *modality*, not the model. A five-model grid
  (RandomForest, HistGradientBoosting, MLP, LSTM, GRU) then shows the dataset is
  learnable by diverse model families.
- Figures are emitted as `pgfplots` LaTeX sources; compile them with any modern
  LaTeX toolchain.

## Scope of this repository

This repository contains the **final (v5) pipeline** that produced the deposited
dataset and the Data Descriptor. Superseded collection iterations, one-off
operational scripts, intermediate data, and separate downstream modelling work
are intentionally excluded to keep the release focused and reproducible.

## Ethics and safety

All attacks run inside an **isolated, air-gapped laboratory** against hardware the
operators own. Credentials, SNMP communities, and other weak configurations in
this code are **synthetic, documented lab settings** created to generate the
labelled attack signal — they are placeholders, not real secrets, and must be
replaced for any deployment. Do not run the attack orchestration against systems
you do not own or are not explicitly authorised to test.

## License

Code is released under the [MIT License](LICENSE). The dataset is distributed
separately under its own license (see the Data Descriptor).

## Citation

If you use this code or the TACTIC-IoT dataset, please cite the accompanying Data
Descriptor. A `CITATION` entry will be added here on publication.
