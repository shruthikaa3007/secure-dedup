# secure-dedup

Secure deduplication prototype with:
- chunk-level dedup + proof-of-ownership checks,
- behavioral feature extraction,
- attack/anomaly detection from client behavior.

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

Useful options:

```bash
python train_model.py \
  --dataset training_data.csv \
  --model-dir . \
  --cv-folds 3 \
  --scoring f1_macro
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

## Artifacts produced

Supervised mode:
- `attack_classifier.pkl`
- `attack_label_encoder.pkl`
- `training_metrics.json`
- `model_metadata.json`

Unsupervised mode:
- `isolation_forest.pkl`
- `one_class_svm.pkl`
- `scaler.pkl`
- `model_metadata.json`
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

## Runtime configuration

Storage backend (MinIO) can be configured with environment variables:
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

Durable telemetry:
- `TELEMETRY_DB` (default `telemetry.db`)
- `MAX_EVENTS_PER_CLIENT` (default `5000`)
- `HYDRATE_EVENT_LIMIT` (default `50000`)

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
