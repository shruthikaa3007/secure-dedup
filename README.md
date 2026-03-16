# secure-dedup

Secure deduplication prototype with:
- chunk-level dedup + proof-of-ownership checks,
- behavioral feature extraction,
- attack/anomaly detection from client behavior.

For setup on a new machine, see `docs/project_notes/NEW_LAPTOP_SETUP.md`.
For quick local demo startup, use `./run_demo.sh start`.


## Repository organization

- **Core service code**: repository root (`app.py`, `storage.py`, `detector.py`, etc.).
- **Deployment config**: `Dockerfile`, `.dockerignore`, `docker-compose.local.yml`, `railway.json`.
- **Model artifacts**: `advanced_artifacts/`, `demo_artifacts/`, `extra_trees_artifacts/`, `unsupervised_artifacts/`.
- **Project notes & reports**: `docs/project_notes/`.
- **Generated datasets/logs**: root CSV outputs (can be relocated per your workflow).

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


## Deploy in a UI cloud (Railway)

If you want a web-UI cloud deploy, use Railway.

### Steps (UI based)

1. Push this repo to GitHub.
2. In Railway dashboard: **New Project** -> **Deploy from GitHub Repo**.
3. Select this repository.
4. Railway will use `Dockerfile` (and `railway.json`) automatically.
5. Set environment variables in Railway UI:
   - `API_KEYS=dev-api-key`
   - `MODEL_DIR=advanced_artifacts`
   - `STORAGE_BACKEND=filesystem`
   - `TELEMETRY_DB=/tmp/telemetry.db`
   - `LOCAL_CHUNK_DIR=/tmp/local_chunks`
   - `ADAPTIVE_POW_ENABLED=true`
   - optional: `CHUNK_ENCRYPTION_KEY=<base64 key>`
6. Deploy and open the generated public URL.

### Verify deployment

```bash
curl -fsS "https://<your-railway-domain>/health"
```

Adaptive PoW is visible through duplicate uploads and `/pow/challenge` response `adaptive_profile`.

## Run with Docker locally

### Prerequisites

- Docker + Docker Compose
- Python virtualenv with project dependencies installed

### Start everything

```bash
./run_demo.sh start
```

This starts Redis + LocalStack (if Docker is available) and then runs the API with adaptive PoW enabled by default.

### Show adaptive PoW locally

```bash
BASE_URL="http://127.0.0.1:8000"
API_KEY="dev-api-key"
CLIENT_ID="demo-client"

# 1) Upload once
curl -fsS -X POST "$BASE_URL/upload"   -H "X-API-Key: $API_KEY"   -H "X-Client-ID: $CLIENT_ID"   -F "file=@sample.bin"

# 2) Upload same file again (duplicate path)
curl -sS -X POST "$BASE_URL/upload"   -H "X-API-Key: $API_KEY"   -H "X-Client-ID: $CLIENT_ID"   -F "file=@sample.bin"

# 3) Request challenge directly for one duplicate chunk hash
CHUNK_HASH="<chunk-hash-from-file_recipe>"
curl -fsS -X POST "$BASE_URL/pow/challenge"   -H "Content-Type: application/json"   -H "X-API-Key: $API_KEY"   -H "X-Client-ID: $CLIENT_ID"   -d "{"chunk_hash":"$CHUNK_HASH"}"
```

Inspect `challenge.adaptive_profile` to confirm adaptive PoW difficulty is active.

### Smoke test

```bash
./run_demo.sh test
```


## Base-paper alignment upgrades

This implementation now aligns more closely with the selected base paper by adding:

- **Dynamic ownership management**
  - persistent per-chunk owner sets and ownership events (`grant` / `revoke` / `transfer`)
  - endpoints: `GET /ownership/{chunk_hash}`, `POST /ownership/transfer`

- **Data dynamics (versioned file recipes)**
  - each upload creates a versioned file record (`file_id`, `version`, `status`)
  - upload with `file_id` updates that file with a new recipe version
  - delete endpoint creates a tombstone version and decrements chunk ref-counts
  - endpoints: `GET /files`, `GET /files/{file_id}`, `DELETE /files/{file_id}`

- **Cloud auditing protocol**
  - challenge/verify audit flow for chunk integrity checks
  - quick audit endpoint for on-demand hash evidence
  - endpoints: `POST /audit/challenge`, `POST /audit/verify`, `GET /audit/quick/{chunk_hash}`

Upload endpoint update:
- `POST /upload` now accepts optional form field `file_id` to create a new version for an existing file.


## Encryption at rest for stored chunks

Chunk payload encryption is now supported via AES-GCM before writing to the storage backend (filesystem / LocalStack S3 / MinIO / S3).

- Set `CHUNK_ENCRYPTION_KEY` to a base64-encoded AES key (16/24/32 bytes).
- Encryption is **content-bound**: a per-chunk key is derived from the master key + `chunk_hash` context (HMAC-SHA256 based derivation).
- Encryption is **segment-based (not chunk all-or-nothing)**: each chunk is split into independently encrypted segments.
- AES-GCM AAD includes `chunk_hash` plus segment index, cryptographically binding each encrypted segment to chunk identity and position.
- If the key is not set, storage behaves as plaintext (backward-compatible default).
- Encrypted payloads are stored with an internal envelope prefix and authenticated tags per segment.
- Optional strict mode (`CHUNK_ENCRYPTION_STRICT=true`) rejects plaintext legacy chunks when encryption is enabled.

Generate a key:

```bash
python generate_encryption_key.py
```

Example runtime config:

```bash
export CHUNK_ENCRYPTION_KEY="<base64-32-byte-key>"
```


## What happens if two files are similar but slightly different?

The system deduplicates at chunk level (content-defined chunking), not whole-file level.

- Shared chunk bytes across the two files produce identical chunk hashes and are **reused** (deduplicated).
- Modified regions tend to create different chunk boundaries/hashes locally and are stored as **new chunks**.
- Result: partial deduplication. Highly similar files share most chunks; only changed segments consume extra storage.

File records keep separate versioned recipes per file, so both files can coexist while still sharing duplicate chunks safely.

## Final project implementation: what to expect

This project now implements an end-to-end secure dedup pipeline that is close to the selected base paper while preserving your adaptive defense extension:

1. **Secure dedup core**
   - content-defined chunking + hash-based dedup index + chunk reference counting
   - proof-of-ownership challenge/verify flow on duplicate chunks

2. **Dynamic ownership management**
   - persistent owner sets per chunk
   - ownership events (`grant`, `revoke`, `transfer`) and transfer API

3. **Data dynamics (file lifecycle)**
   - versioned file recipes (`file_id`, `version`, `status`)
   - create/update/delete semantics with chunk ref-count reconciliation

4. **Cloud auditing protocol**
   - challenge/verify integrity audits for stored chunks
   - quick integrity probe endpoint for on-demand evidence

5. **Adaptive security extension (your novelty)**
   - behavioral anomaly/risk scoring and policy actions
   - reputation-aware adaptive PoW difficulty

6. **Cloud deployment path**
   - Dockerfile + local Docker Compose stack (`run_demo.sh`)

In practice, users should expect:
- first upload stores new encrypted chunks (if encryption key configured),
- duplicate uploads require ownership proof,
- file updates create a new version and retire unreferenced old chunks,
- owners can audit chunk integrity and transfer ownership,
- suspicious clients are automatically rate-limited/blocked by policy.


## Runtime metrics and test graphs

### Runtime metrics endpoint

The API now exposes:

- `GET /metrics`

It returns a lightweight snapshot including request volume, feature snapshot count, file-version count, ownership links/events, and audit challenge/event counts.

### Generate benchmark metrics + graphs

Run:

```bash
python generate_test_metrics_graphs.py --output-dir metrics_artifacts
```

Artifacts generated:
- `metrics_artifacts/test_metrics.csv`
- `metrics_artifacts/summary.json`
- `metrics_artifacts/dedup_ratio_by_case.png` **or** `.svg`
- `metrics_artifacts/shared_vs_new_chunks.png` **or** `.svg`
- `metrics_artifacts/processing_time_ms.png` **or** `.svg`

These are based on synthetic similarity/mutation test cases and are useful to show dedup efficiency and processing behavior.

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

Encryption:
- `CHUNK_ENCRYPTION_KEY` (optional; base64 AES key with 16/24/32 decoded bytes).
- `CHUNK_ENCRYPTION_STRICT` (`true`/`false`, default `false`) fail reads when encryption is enabled but payload is plaintext/legacy format.
- `CHUNK_ENCRYPTION_SEGMENT_SIZE` (default `4096`) segment size in bytes for segment-based encryption (must be >= 256).

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
