# Static vs Adaptive PoW Comparison

- Generated At (UTC): `2026-02-15T08:15:11.289317+00:00`
- Input Dataset: `demo_detection_results.csv`
- Rows: `103`
- Labels: `{'ownership_fraud': 60, 'normal': 17, 'hash_probing': 18, 'dedup_dos': 8}`

## Proof Length (Mean)

| Segment | Static Baseline | Adaptive PoW |
|---|---:|---:|
| All rows | 32.00 | 94.83 |
| Normal rows | 32.00 | 50.59 |
| Anomaly rows | 32.00 | 103.58 |

## Estimated Attacker Success (Anomaly Rows)

- Baseline mean success: `1.0000`
- Adaptive mean success: `0.4735`
- Relative reduction: `52.65%`

## Adaptive Difficulty Distribution

- {'hardened': 68, 'normal': 17, 'elevated': 18}

## Benign Overhead

- Normal-row proof length change vs baseline: `58.09%`
