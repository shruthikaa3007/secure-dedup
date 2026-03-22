# Dataset Defense Note

## Short Answer

Do not anchor the viva answer on the small legacy `training_data.csv` file alone.
The stronger and more accurate dataset story is the multi-source trace pipeline.

## What The Repo Has Now

- Raw standardized request logs:
  - `request_logs_fiu.csv`
  - `request_logs_msrc.csv`
- Combined raw event volume: `1,026,034`
- Combined processed clients: `72`

## Larger Trace-Derived Dataset

Generated on `2026-03-22` with:

```powershell
.\.venv\Scripts\python.exe build_windowed_feature_dataset.py `
  --input request_logs_fiu.csv `
  --input request_logs_msrc.csv `
  --feature-output multisource_dense_feature_dataset.csv `
  --detection-output multisource_dense_detection_results.csv `
  --window-sec 120 `
  --step-sec 10 `
  --min-events 5 `
  --max-windows-per-client 400
```

Result:

- dense window rows: `221`
- label distribution:
  - `ownership_fraud`: `120`
  - `hash_probing`: `53`
  - `normal`: `32`
  - `dedup_dos`: `16`

Artifacts:

- `multisource_dense_feature_dataset.csv`
- `multisource_dense_detection_results.csv`

## Larger-Dataset Model Artifact

Trained on the 221-row dense dataset:

- model dir: `dense_artifacts`
- best model: `random_forest`
- best CV macro F1: `0.9652`
- train rows: `165`
- test rows: `56`

Key files:

- `dense_artifacts/training_metrics.json`
- `dense_artifacts/evaluation_report.md`

## Thesis-Safe Framing

Use this wording:

`The project has a small legacy CSV snapshot, but the actual evaluation pipeline is built on over one million standardized request events adapted from multiple trace sources. I generated a denser multi-source windowed dataset with 221 labelled samples and retrained the detector on that larger trace-derived set. I still present the result as prototype-scale because the labels are trace-derived and the data is not collected from a production deployment.`

## What Not To Overclaim

Do not say:

- the dataset is production-scale,
- the labels are ground-truth from real attackers,
- the model is deployment-ready.

Do say:

- the raw telemetry base is large,
- the feature-window dataset is reproducible,
- the current evaluation is trace-derived and suitable for a final-year prototype.
