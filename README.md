# secure-dedup

Secure deduplication prototype with:
- chunk-level dedup + proof-of-ownership checks,
- behavioral feature extraction,
- attack/anomaly detection from client behavior.

For setup on a new machine, see `NEW_LAPTOP_SETUP.md`.
For quick local demo startup, use `./run_demo.sh start`.

## Training workflow (optimized)

`train_model.py` now supports two modes:
- `supervised` (preferred): trains a label-aware classifier with model selection (HistGradientBoosting / RandomForest / LogisticRegression + CV),
- `unsupervised` (fallback): Isolation Forest + One-Class SVM + optional Dense Autoencoder + optional LSTM autoencoder.

The script automatically chooses supervised mode when a usable label column exists.
If some attack classes are too rare, it automatically collapses labels to `normal` vs `anomaly` and trains supervised mode.
If labels are still not trainable, it falls back to unsupervised mode.

### 1) Install dependencies

```bash
pip install -r requirements.txt
```

Optional for LSTM training/inference:

```bash
pip install tensorflow
```

### 2) Build clean training data

Create a clean labeled dataset from `detection_results.csv`:

```bash
python prepare_training_data.py \
  --input detection_results.csv \
  --output training_data.csv \
  --relabel auto
```

`--relabel auto` fixes degenerate labels (for example, all `normal`) using `attack_labeler.py`.

### 3) Train model artifacts

```bash
python train_model.py --dataset training_data.csv --model-dir .
```

Each training run now auto-generates:
- `evaluation_report.json`
- `evaluation_report.md`
These include PR-AUC, F1, confusion matrix, and prediction summary.

Useful options:

```bash
python train_model.py \
  --dataset training_data.csv \
  --model-dir . \
  --cv-folds 3 \
  --scoring f1_macro
```

Enable advanced supervised candidates (default behavior):

- `extra_trees`
- `svc_rbf`
- `mlp_classifier`
- optional `xgboost` / `lightgbm` if installed

To restrict to baseline supervised candidates only:

```bash
python train_model.py --dataset training_data.csv --disable-advanced-models
```

To force a specific supervised model candidate:

```bash
python train_model.py \
  --dataset training_data.csv \
  --preferred-supervised-model extra_trees
```

Force unsupervised mode:

```bash
python train_model.py --dataset training_data.csv --force-unsupervised
```

Disable LSTM in unsupervised mode:

```bash
python train_model.py --dataset training_data.csv --force-unsupervised --disable-lstm
```

Disable dense autoencoder in unsupervised mode:

```bash
python train_model.py --dataset training_data.csv --force-unsupervised --disable-autoencoder
```

Skip auto-evaluation report generation:

```bash
python train_model.py --dataset training_data.csv --skip-evaluation
```

Run evaluation manually:

```bash
python evaluate_model.py --dataset training_data.csv --model-dir .
```

## Artifacts produced

Supervised mode:
- `attack_classifier.pkl`
- `attack_label_encoder.pkl`
- `training_metrics.json`
- `model_metadata.json`
- `evaluation_report.json`
- `evaluation_report.md`

Unsupervised mode:
- `isolation_forest.pkl`
- `one_class_svm.pkl`
- `scaler.pkl`
- `model_metadata.json`
- `evaluation_report.json`
- `evaluation_report.md`
- `dense_autoencoder.keras` *(optional)*
- `dense_ae_threshold.npy` *(optional)*
- `lstm_autoencoder.keras` *(optional)*
- `lstm_threshold.npy` *(optional)*

## Runtime detection behavior

`detector.py` loads models in this order:
1. Supervised classifier (`attack_classifier.pkl`) when available,
2. Otherwise unsupervised weighted ensemble (`isolation_forest.pkl` + `one_class_svm.pkl`, and optional dense/LSTM autoencoders).

`app.py` supports policy actions (`ALLOW`, `RATE_LIMIT`, `BLOCK`) via `policy_engine.py`.
Use headers `X-API-Key` and `X-Client-ID` for authenticated runtime identity.
`app.py` computes `attack_label` before persisting rows to `detection_results.csv`, so newly collected data is immediately usable for supervised training.

PoW is challenge-based:
- `POST /pow/challenge` to request nonce/offset/length for a duplicate chunk,
- `POST /pow/verify` to submit client proof,
- `POST /upload` supports `pow_proofs_json` (form field) to include proof payloads inline.

Adaptive PoW and reputation are enabled at runtime:
- challenge responses now include `adaptive_profile` (`difficulty_level`, `difficulty_score`, length/window metadata),
- difficulty selection uses detector-derived risk and client reputation,
- reputation is updated from PoW verification outcomes and policy actions.

## Runtime configuration

Storage backend can be configured with:
- `STORAGE_BACKEND` (`auto`/`localstack`/`minio`/`filesystem`, default `auto`)
- `S3_BUCKET` (default `chunks`)

LocalStack S3 settings:
- `LOCALSTACK_ENDPOINT` (default `http://127.0.0.1:4566`)
- `AWS_ACCESS_KEY_ID` (default `test`)
- `AWS_SECRET_ACCESS_KEY` (default `test`)
- `AWS_REGION` (default `us-east-1`)

MinIO settings (legacy/optional):
- `MINIO_ENDPOINT` (default `localhost:9000`)
- `MINIO_ACCESS_KEY` (default `minioadmin`)
- `MINIO_SECRET_KEY` (default `minioadmin`)
- `MINIO_SECURE` (`true`/`false`, default `false`)
- `MINIO_BUCKET` (default `chunks`)

Policy thresholds can be configured with:
- `RATE_LIMIT_THRESHOLD` (default `0.55`)
- `BLOCK_THRESHOLD` (default `0.80`)
- `RATE_LIMIT_COOLDOWN_SEC` (default `30`)
- `BLOCK_COOLDOWN_SEC` (default `180`)

Auth and PoW configuration:
- `REQUIRE_API_KEY` (`true`/`false`, default `true`)
- `API_KEYS` (comma-separated, default `dev-api-key`)
- `POW_CHALLENGE_TTL_SEC` (default `120`)
- `POW_VERIFIED_TTL_SEC` (default `300`)
- `ADAPTIVE_POW_ENABLED` (`true`/`false`, default `true`)
- `POW_BASE_PROOF_LENGTH` (default `32`)
- `POW_MIN_PROOF_LENGTH` (default `16`)
- `POW_MAX_EXTRA_PROOF_LENGTH` (default `96`)
- `POW_RISK_WEIGHT` (default `0.65`)
- `POW_REPUTATION_WEIGHT` (default `0.25`)
- `POW_DUPLICATE_WEIGHT` (default `0.10`)

Reputation tuning:
- `REPUTATION_INITIAL_SCORE` (default `0.60`)
- `REPUTATION_MIN_SCORE` (default `0.05`)
- `REPUTATION_MAX_SCORE` (default `0.95`)
- `REPUTATION_HALF_LIFE_SEC` (default `21600`)
- `REPUTATION_POW_SUCCESS_DELTA` (default `0.04`)
- `REPUTATION_POW_FAILURE_DELTA` (default `-0.12`)
- `REPUTATION_RATE_LIMIT_DELTA` (default `-0.05`)
- `REPUTATION_BLOCK_DELTA` (default `-0.10`)
- `REPUTATION_BENIGN_DELTA` (default `0.01`)

Durable telemetry:
- `TELEMETRY_DB` (default `telemetry.db`)
- `MAX_EVENTS_PER_CLIENT` (default `5000`)
- `HYDRATE_EVENT_LIMIT` (default `50000`)

Model artifact path:
- `MODEL_DIR` (default `.`). Set this to use alternate trained artifacts (for example `advanced_artifacts`).

## Dataset adapters

Use `dataset_adapters.py` to convert external datasets into project request logs.

Azure Functions Invocation trace:
```bash
python dataset_adapters.py azure-invocations --input AzureFunctionsInvocationTrace2021.csv --output request_logs.csv
```

Block trace CSV (FIU/MSRC-like exports):
```bash
python dataset_adapters.py block-trace \
  --input fiu_export.csv \
  --output request_logs.csv \
  --timestamp-col timestamp \
  --client-col host \
  --block-col block \
  --op-col op \
  --size-col size
```

CIC flow CSV:
```bash
python dataset_adapters.py cic-flow --input CIC-DDoS2019.csv --output request_logs.csv
```

FIU/MSRC revised tar traces:
```bash
python dataset_adapters.py revised-tar \
  --input FIU-trace.tar \
  --output request_logs.csv \
  --max-events-per-file 20000 \
  --max-files 0 \
  --max-events 0
```

Fast multi-client sample (recommended while iterating):
```bash
python dataset_adapters.py revised-tar \
  --input FIU-trace.tar \
  --output request_logs.csv \
  --max-files 40 \
  --max-events-per-file 15000
```

Build features directly from generated request logs:
```bash
python build_feature_dataset_from_logs.py \
  --input request_logs.csv \
  --feature-output feature_dataset.csv \
  --detection-output detection_results.csv \
  --min-events 50
```
