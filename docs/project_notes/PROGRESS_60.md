# Progress Snapshot (Target: 60%+)

Date: 2026-02-15

## Current Completion Estimate: 65%

## What is completed now
1. Implemented adaptive PoW runtime path (risk + reputation aware challenge profile).
2. Added reputation engine integration in request flow and PoW verification flow.
3. Built windowed dataset pipeline for more credible evaluation samples.
4. Trained supervised detector on windowed dataset and generated evaluation reports.
5. Implemented static baseline vs adaptive PoW comparison script.
6. Generated presentation-ready result artifacts (CSV + JSON + Markdown).
7. Upgraded supervised training with advanced candidates (ExtraTrees, RBF-SVM, MLP, optional XGBoost/LightGBM).

## What remains (next milestone)
1. Add cloud auditing module (`/audit/challenge`, `/audit/verify`).
2. Add explicit ownership event lifecycle (grant/revoke/transfer).
3. Add file recipe versioning and delete/update data dynamics.
4. Run larger-scale experiments and statistical significance tests.

## Visible Results (Generated Today)

### A) Dataset generation
- Source logs: `request_logs.csv` (1,026,034 events, 72 clients)
- Windowed dataset: `demo_detection_results.csv` (103 samples)
- Label mix: ownership_fraud=60, hash_probing=18, dedup_dos=8, normal=17

### B) Detection model results
From `demo_artifacts/training_metrics.json` (holdout split: 77 train / 26 test):
- Best model: `random_forest`
- Best CV macro F1: `0.9484`
- Test accuracy: `0.9615`
- Test weighted F1: `0.9573`
- Test macro F1: `0.8889`

From `extra_trees_artifacts/training_metrics.json` (forced advanced model demo):
- Forced model: `extra_trees`
- CV macro F1: `0.7508`
- Test accuracy: `0.9231`
- Test weighted F1: `0.9203`

From `demo_artifacts/evaluation_report.md` (full dataset scoring):
- Binary F1: `0.9942`
- Binary macro F1: `0.9828`
- PR-AUC: `1.0000`
- Confusion matrix (normal vs anomaly): TN=17, FP=0, FN=1, TP=85
- Multiclass macro F1: `0.9762`

### C) Static baseline vs adaptive PoW
From `pow_comparison_summary.json`:
- Baseline proof length (static): `32`
- Adaptive mean proof length (all): `94.83`
- Adaptive mean proof length (normal): `50.59`
- Adaptive mean proof length (anomaly): `103.58`
- Estimated attacker success on anomaly rows:
  - Static baseline: `1.0000`
  - Adaptive: `0.4735`
  - Relative reduction: `52.65%`
- Adaptive difficulty distribution:
  - hardened: 68
  - elevated: 18
  - normal: 17

## Interpretation
1. Baseline replication path is operational (dedup + ownership proof workflow with static PoW baseline still available).
2. Improvement layer is operational (adaptive PoW with risk/reputation input).
3. Measurable security gain is visible in controlled comparison.
4. Overhead is currently high for benign traffic, and policy tuning is the next optimization step.

## Reproducibility Commands

```bash
.venv/bin/python build_windowed_feature_dataset.py \
  --input request_logs.csv \
  --feature-output demo_feature_dataset.csv \
  --detection-output demo_detection_results.csv \
  --window-sec 120 \
  --step-sec 30 \
  --min-events 10 \
  --max-windows-per-client 200
```

```bash
mkdir -p demo_artifacts
.venv/bin/python train_model.py \
  --dataset demo_detection_results.csv \
  --model-dir demo_artifacts \
  --cv-folds 3 \
  --test-size 0.25 \
  --scoring f1_macro
```

```bash
.venv/bin/python compare_static_vs_adaptive_pow.py \
  --input demo_detection_results.csv \
  --output-details pow_comparison_details.csv \
  --output-summary pow_comparison_summary.json \
  --output-md pow_comparison_report.md \
  --attacker-budget 48 \
  --chunk-length 4096
```

## Artifact List
1. `build_windowed_feature_dataset.py`
2. `compare_static_vs_adaptive_pow.py`
3. `demo_feature_dataset.csv`
4. `demo_detection_results.csv`
5. `demo_artifacts/evaluation_report.md`
6. `demo_artifacts/evaluation_report.json`
7. `advanced_artifacts/training_metrics.json`
8. `extra_trees_artifacts/training_metrics.json`
9. `pow_comparison_report.md`
10. `pow_comparison_summary.json`
11. `pow_comparison_details.csv`
