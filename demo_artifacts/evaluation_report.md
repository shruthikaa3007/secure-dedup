# Model Evaluation Report

- Generated At (UTC): `2026-02-15T08:15:03.586336+00:00`
- Dataset: `demo_detection_results.csv`
- Model Dir: `demo_artifacts`
- Training Metadata Mode: `supervised`
- Evaluated Mode: `supervised`
- Rows Evaluated: `103`

## Binary Metrics (normal vs anomaly)
- PR-AUC: `1.000000`
- F1 (binary): `0.994152`
- F1 (macro): `0.982790`
- Precision: `1.000000`
- Recall: `0.988372`

| Truth \ Pred | normal | anomaly |
|---|---:|---:|
| normal | 17 | 0 |
| anomaly | 1 | 85 |

## Multiclass Metrics
- Labels: `dedup_dos, hash_probing, normal, ownership_fraud`
- F1 (macro): `0.976190`
- PR-AUC (OvR macro): `1.0`

Confusion matrix (JSON):
```json
[
  [
    7,
    0,
    1,
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
    0,
    17,
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
- Predicted Normal: `18`
- Predicted Anomaly: `85`
- Predicted Anomaly Rate: `0.825243`
- Mean Risk Score: `0.831165`
