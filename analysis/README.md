# analysis/

The complete analysis of the final TACTIC-IoT dataset. This produces every table
and figure in the Technical Validation of the Data Descriptor.

## Files

| File | Output |
|------|--------|
| `exp_v5_analysis.py` | The full analysis. From the four-modality fused windows it computes: dataset summary and modality presence; per-sublabel / per-stage one-vs-rest detection with single-modality, fused, dominant-modality, **fusion gain**, and every leave-one-modality-out ablation; multiclass fused classification with per-class P/R/F1, confusion, and bootstrap CIs; the modality ablation on multiclass macro-F1; the window-size effect (1/5/8/10 s); per-feature mutual information aggregated by modality; K-means class-overlap (ARI/NMI/homogeneity/completeness/silhouette); and a five-model grid (RandomForest, HistGradientBoosting, MLP, LSTM, GRU) on both the binary and multiclass tasks. Writes a set of CSVs. |
| `make_v5_figures.py` | Camera-ready PGFPlots `.tex` figure sources from those CSVs. |
| `make_v5_tables.py` | Exact LaTeX table bodies from the dataset and the CSVs. |
| `v5_manuscript_stats.py` | The specific summary statistics quoted in the manuscript text. |

## Usage

Run from this directory. Point `--work` at the deposited dataset root (the folder
that holds `By_device_and_campaigns/` and `By_labels/`).

```bash
# Full analysis -> ./v5_results/*.csv
python exp_v5_analysis.py --work /path/to/TACTIC-IoT --outdir v5_results

# Camera-ready figure sources -> ./v5_figures/tex/*.tex  (compile with pdflatex)
python make_v5_figures.py

# LaTeX table bodies -> ./tables/
python make_v5_tables.py

# Fast end-to-end smoke test (subsampled windows, tiny models, separate outdir)
python exp_v5_analysis.py --work /path/to/TACTIC-IoT --smoke --outdir v5_results_smoke
```

### Key options for `exp_v5_analysis.py`

| Flag | Default | Meaning |
|------|---------|---------|
| `--work` | `./dataset_v5` | Dataset root. |
| `--outdir` | `./v5_results` | Where the CSVs are written. |
| `--windows` | `1,5,8,10` | Window lengths (seconds) to evaluate. |
| `--models` | `rf,gb,mlp,lstm,gru` | Model grid. |
| `--trees` | `200` | Trees for the RandomForest / HistGB. |
| `--boot` | `300` | Group-bootstrap resamples for the confidence intervals. |
| `--ctx` | `8` | Temporal-context length (windows) for the LSTM/GRU. |
| `--smoke` | off | Subsample + shrink every model for a fast correctness check. |

## Reproducibility

- Deterministic (`random_state = 42`).
- **Grouped-by-run** splitting throughout: no window from a test run appears in
  training.
- RandomForest is the fixed detector in the detection/ablation experiments so the
  comparison isolates the modality rather than the model; the model grid then
  shows the dataset is learnable across model families.
- LSTM/GRU classify each window from its causal predecessors in the same capture
  segment, and are scored on exactly the same test windows as the tabular models.
