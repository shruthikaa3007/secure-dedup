# Model Evaluation Report

- Generated At (UTC): `2026-02-15T12:20:46.817096+00:00`
- Dataset: `demo_detection_results.csv`
- Model Dir: `unsupervised_artifacts`
- Training Metadata Mode: `unsupervised`
- Evaluated Mode: `unsupervised`
- Rows Evaluated: `103`

## Binary Metrics (normal vs anomaly)
- PR-AUC: `0.855618`
- F1 (binary): `0.130435`
- F1 (macro): `0.214340`
- Precision: `1.000000`
- Recall: `0.069767`

| Truth \ Pred | normal | anomaly |
|---|---:|---:|
| normal | 17 | 0 |
| anomaly | 80 | 6 |

## Multiclass Metrics
- Available: `False`
- Reason: Multiclass metrics are only computed for supervised classifier outputs. Use binary metrics (normal vs anomaly) for unsupervised evaluation.

## Prediction Summary
- Predicted Normal: `97`
- Predicted Anomaly: `6`
- Predicted Anomaly Rate: `0.058252`
- Mean Risk Score: `0.079827`
- Unsupervised Threshold: `0.500000`

## Notes
- Unsupervised evaluation uses weighted votes from IsolationForest and OneClassSVM.
