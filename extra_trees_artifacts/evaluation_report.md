# Model Evaluation Report

- Generated At (UTC): `2026-02-15T08:31:53.200740+00:00`
- Dataset: `demo_detection_results.csv`
- Model Dir: `extra_trees_artifacts`
- Training Metadata Mode: `supervised`
- Evaluated Mode: `supervised`
- Rows Evaluated: `103`

## Binary Metrics (normal vs anomaly)
- PR-AUC: `0.999594`
- F1 (binary): `0.994220`
- F1 (macro): `0.981958`
- Precision: `0.988506`
- Recall: `1.000000`

| Truth \ Pred | normal | anomaly |
|---|---:|---:|
| normal | 16 | 1 |
| anomaly | 0 | 86 |

## Multiclass Metrics
- Labels: `dedup_dos, hash_probing, normal, ownership_fraud`
- F1 (macro): `0.962600`
- PR-AUC (OvR macro): `0.9977941176470588`

Confusion matrix (JSON):
```json
[
  [
    7,
    1,
    0,
    0
  ],
  [
    0,
    18,
    0,
    0
  ],
  [
    0,
    1,
    16,
    0
  ],
  [
    0,
    0,
    0,
    60
  ]
]
```

## Prediction Summary
- Predicted Normal: `16`
- Predicted Anomaly: `87`
- Predicted Anomaly Rate: `0.844660`
- Mean Risk Score: `0.833916`
