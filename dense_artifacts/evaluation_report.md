# Model Evaluation Report

- Generated At (UTC): `2026-03-22T12:36:25.825642+00:00`
- Dataset: `multisource_dense_detection_results.csv`
- Model Dir: `dense_artifacts`
- Training Metadata Mode: `supervised`
- Evaluated Mode: `supervised`
- Rows Evaluated: `221`

## Binary Metrics (normal vs anomaly)
- PR-AUC: `1.000000`
- F1 (binary): `1.000000`
- F1 (macro): `1.000000`
- Precision: `1.000000`
- Recall: `1.000000`

| Truth \ Pred | normal | anomaly |
|---|---:|---:|
| normal | 32 | 0 |
| anomaly | 0 | 189 |

## Multiclass Metrics
- Labels: `dedup_dos, hash_probing, normal, ownership_fraud`
- F1 (macro): `1.000000`
- PR-AUC (OvR macro): `1.0`

Confusion matrix (JSON):
```json
[
  [
    16,
    0,
    0,
    0
  ],
  [
    0,
    53,
    0,
    0
  ],
  [
    0,
    0,
    32,
    0
  ],
  [
    0,
    0,
    0,
    120
  ]
]
```

## Prediction Summary
- Predicted Normal: `32`
- Predicted Anomaly: `189`
- Predicted Anomaly Rate: `0.855204`
- Mean Risk Score: `0.851733`
