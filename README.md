# secure-dedup

Secure deduplication prototype with:
- chunk-level dedup + proof-of-ownership checks,
- behavioral feature extraction,
- attack/anomaly detection from client behavior.

For setup on a new machine, see `docs/project_notes/NEW_LAPTOP_SETUP.md`.
For quick local demo startup, use `./run_demo.sh start`.

## Table of contents

- [Project objective](#project-objective)
- [System architecture](#system-architecture)
- [Methodology](#methodology)
- [Key results](#key-results)
- [Repository organization](#repository-organization)
- [Training workflow (optimized)](#training-workflow-optimized)
- [Runtime detection behavior](#runtime-detection-behavior)
- [End-to-end demo playbook (UI and API)](#end-to-end-demo-playbook-ui-and-api)
- [Scenario playbooks](#scenario-playbooks)
- [Deploy in a UI cloud (Railway)](#deploy-in-a-ui-cloud-railway)
- [Run with Docker locally](#run-with-docker-locally)
- [Runtime metrics and test graphs](#runtime-metrics-and-test-graphs)
- [Runtime configuration](#runtime-configuration)

## Project objective

Build and validate a secure chunk-level deduplication system that keeps storage efficiency while reducing abuse risk.

Primary goals:
- Preserve dedup benefits for benign users.
- Require proof-of-ownership for duplicate chunk claims.
- Detect suspicious behavior from request patterns.
- Enforce adaptive policy (`ALLOW`, `RATE_LIMIT`, `BLOCK`) and adaptive PoW difficulty.
- Provide auditability, ownership lifecycle, and reproducible demo/test workflows.

## System architecture

The implementation follows a layered architecture that maps to `architecture.drawio` and is explained in `docs/project_notes/ARCHITECTURE_EXPLANATION.md`.

Runtime path (online):
- API ingress (`app.py`) with authenticated client identity (`X-API-Key`, `X-Client-ID`).
- Chunking + fingerprinting (`chunking.py`, `hashing.py`) and dedup index (`dedup_index.py`).
- Storage backends (`storage.py`) with optional encryption-at-rest (`encryption.py`).
- Duplicate-claim verification via challenge-based PoW (`pow_session.py`, `pow.py`, `/pow/*`, `/upload`).
- Adaptive policy loop using behavior features (`features.py`), detector (`detector.py`), policy engine (`policy_engine.py`), and reputation (`reputation.py`).
- Durable telemetry + metrics (`logger.py`, `feature_store.py`, `metrics_tools.py`).

Data/control stores:
- Chunk object storage (filesystem / LocalStack S3 / MinIO / S3).
- Fingerprint/ref-count index.
- SQLite telemetry (`TELEMETRY_DB`) for events, feature snapshots, file versions, and ownership events.

Lifecycle controls:
- File versioning and updates (`file_catalog.py`, `/files*`).
- Ownership transfer (`ownership_store.py`, `/ownership/*`).
- Integrity audit challenge/verify (`audit_store.py`, `/audit/*`).

## Methodology

1. Data and feature engineering
- Convert/prepare request logs and derive behavioral features (`prepare_training_data.py`, `features.py`).
- Label attack patterns using rules (`attack_labeler.py`) to bootstrap supervised learning.

2. Model training and selection
- Train supervised models when labels are trainable; fallback to unsupervised ensemble otherwise (`train_model.py`).
- Compare candidate classifiers with CV and select best by macro-F1.
- Persist artifacts and evaluation reports (`training_metrics.json`, `evaluation_report.json/.md`).

3. Adaptive control design
- Map detector risk + client reputation into policy decisions and PoW difficulty.
- Keep a challenge-based duplicate flow so legitimate clients can still proceed.

4. System validation
- API smoke validation and scenario tests (upload, duplicate challenge, solve, retry, metrics, UI hooks).
- Reproducible report generation through `tests/run_smoke_tests.py`.

## Key results

Modeling results (from `advanced_artifacts/training_metrics.json`):
- Dataset rows: `103` (train `77`, test `26`), 4 classes.
- Best model: `random_forest` with CV macro-F1 `0.9484`.
- Test accuracy: `0.9615`.
- Macro-F1: `0.8889`, weighted-F1: `0.9573`.

Adaptive PoW comparison (from `pow_comparison_summary.json`):
- Mean estimated attacker success on anomaly rows reduced from `1.0000` to `0.4735`.
- Relative reduction: `52.65%`.
- Benign proof-length overhead (normal rows): `58.09%`.
- Adaptive difficulty distribution: `hardened=68`, `elevated=18`, `normal=17`.

Current smoke validation (from `test_reports/smoke_test_report_20260318_120635.md`):
- `7/7` smoke test cases passed (health, config, upload, duplicate PoW, solve+retry, status/metrics, UI hooks).


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

## End-to-end demo playbook (UI and API)

### A) Guided UI demo (recommended)

1. Open `https://<your-railway-domain>/ui/`.
2. Set:
   - API key: `dev-api-key` (or your configured key),
   - Client ID: use a fresh value per demo (for example `demo-<timestamp>`),
   - Policy Client ID: same as Client ID.
3. Click `Refresh Overview`.
4. Click `Run Full Demo Story`.
5. Narrate the flow:
   - baseline upload success,
   - duplicate upload triggers PoW challenge,
   - PoW solved and retry succeeds,
   - optional bad-proof attack path.
6. In parallel tabs, show:
   - `/health`
   - `/demo/status?limit=20`
   - `/metrics`

If duplicate upload returns `429` instead of `409`:
1. Click `Clear Policy`.
2. Re-run duplicate step.
3. Continue with solve+retry.

### B) API demo flow (curl)

```bash
BASE_URL="https://<your-railway-domain>"
API_KEY="dev-api-key"
CLIENT_ID="demo-$(date +%s)"
echo "secure dedup demo payload" > demo.txt

# 1) Baseline upload
curl -fsS -X POST "$BASE_URL/upload" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Client-ID: $CLIENT_ID" \
  -F "file=@demo.txt"

# 2) Duplicate upload (expect 409 + required_challenges)
curl -sS -X POST "$BASE_URL/upload" \
  -H "X-API-Key: $API_KEY" \
  -H "X-Client-ID: $CLIENT_ID" \
  -F "file=@demo.txt"
```

Then either:
- Solve via `/demo/solve_pow` and retry `/upload` with `pow_proofs_json`, or
- Use `/pow/challenge` + `/pow/verify` endpoint pair for explicit challenge verification.

## Scenario playbooks

### Scenario 1: Duplicate ownership verification

Goal:
- Show that duplicate claims require proof, not just matching hash requests.

Steps:
1. Upload file once (`/upload`) -> success.
2. Upload same file again -> `409` with `required_challenges`.
3. Solve/verify challenge and retry -> success.

Expected demo message:
- Dedup remains efficient, but duplicate path is protected by PoW.

### Scenario 2: Policy enforcement (rate-limit/block)

Goal:
- Show adaptive defense actions.

Steps:
1. Use `/demo/force-policy` with `RATE_LIMIT` and same client ID.
2. Upload again -> expect `429`.
3. Use `/demo/force-policy` with `BLOCK`.
4. Upload again -> expect `403`.
5. Use `/demo/clear-policy` and verify normal flow resumes.

### Scenario 3: File lifecycle and versioning

Goal:
- Show update/delete semantics with chunk ref-count reconciliation.

Steps:
1. Upload new file -> capture `file.file_id`.
2. Upload updated content with `file_id=<captured_id>` form field.
3. Query `/files` and `/files/{file_id}` to show version increments.
4. Delete via `/files/{file_id}` and verify status transitions.

### Scenario 4: Ownership transfer

Goal:
- Demonstrate secure owner tracking and transfer events.

Steps:
1. Identify a chunk hash from upload response.
2. Call `/ownership/{chunk_hash}` as current owner.
3. Transfer with `/ownership/transfer`.
4. Re-check ownership summary.

### Scenario 5: Cloud integrity audit

Goal:
- Prove auditable integrity of stored chunks.

Steps:
1. Create challenge via `/audit/challenge`.
2. Verify with `/audit/verify`.
3. Optionally show `/audit/quick/{chunk_hash}`.

### Scenario 6: Encryption-at-rest proof

Goal:
- Show stored payloads are envelope-encrypted when key is configured.

Steps:
1. Set `CHUNK_ENCRYPTION_KEY` in runtime env.
2. Upload sample file.
3. Call `/demo/encryption`.
4. Call `/demo/encryption?chunk_hash=<hash>` and verify `encrypted_envelope: true`.


## Deploy in a UI cloud (Railway)

If you want a web-UI cloud deploy, use Railway.

### Steps (UI based)

1. Push this repo to GitHub.
2. In Railway dashboard: **New Project** -> **Deploy from GitHub Repo**.
3. Select this repository.
4. Railway will use `Dockerfile` for build/run; `railway.json` starts `python start_server.py` explicitly.
5. Set environment variables in Railway UI:
   - `API_KEYS=dev-api-key`
   - `MODEL_DIR=advanced_artifacts`
   - `STORAGE_BACKEND=filesystem`
   - `TELEMETRY_DB=/tmp/telemetry.db`
   - `LOCAL_CHUNK_DIR=/tmp/local_chunks`
   - `ADAPTIVE_POW_ENABLED=true`
   - optional: `CHUNK_ENCRYPTION_KEY=<base64 key>`
6. Deploy and open the generated public URL.

Defaults baked into Docker image:
- `STORAGE_BACKEND=filesystem`
- `TELEMETRY_DB=/tmp/telemetry.db`
- `LOCAL_CHUNK_DIR=/tmp/local_chunks`

### Verify deployment

```bash
curl -fsS "https://<your-railway-domain>/"
```

For a demo-friendly runtime snapshot (recent events, active client policies, and reputation):

```bash
curl -fsS "https://<your-railway-domain>/demo/status?limit=20" | python -m json.tool
```

Adaptive PoW is visible through duplicate uploads and `/pow/challenge` response `adaptive_profile`.

Swagger UI tip: open `https://<your-railway-domain>/docs`, click **Authorize**, and enter your `X-API-Key` (for example `dev-api-key`) before trying protected routes like `/upload`.

For a guided UI automation flow (baseline upload, duplicate+PoW success, and PoW attack simulation), open `https://<your-railway-domain>/ui/`.

Upload demo flow in UI (to avoid PoW form errors):
1. First upload: leave `pow_proofs_json` empty (or set `{}`), then execute `/upload`.
   - If Swagger shows `file_id=string`, clear it before execute (or leave it empty for new uploads).
2. Upload same file again: you will get `409` with `required_challenges` for duplicate chunks.
3. Call `/pow/verify` (or provide valid `pow_proofs_json`) and retry `/upload`.
4. Use `/demo/status` to show recent upload + PoW events live.


### If Railway shows healthcheck failure (concrete fix)


### If Railway says `Failed to parse JSON file railway.json`

Use this exact validation command before pushing:

```bash
python -m json.tool railway.json
```

If it fails, replace `railway.json` with the current repository version (strict JSON with double-quoted keys).


Use this exact setup:

1. In Railway **Settings -> Healthcheck Path**, set it to `/` (root).

2. Keep `/health` for automated probes, and use `/demo/status` during demos to show what the service is doing in near real time.
3. In Railway **Settings -> Start Command**, set `python start_server.py` (or keep repo `railway.json` command).
4. Ensure these env vars exist:
   - `API_KEYS=dev-api-key`
   - `MODEL_DIR=advanced_artifacts`
   - `STORAGE_BACKEND=filesystem`
   - `TELEMETRY_DB=/tmp/telemetry.db`
   - `LOCAL_CHUNK_DIR=/tmp/local_chunks`
5. Redeploy from latest commit.
6. In Railway **Deployments -> Logs**, confirm process starts and binds to a port.
7. Check logs for a line like: `Uvicorn running on http://0.0.0.0:<port>`.
8. Verify both endpoints:

```bash
curl -fsS "https://<your-railway-domain>/"
curl -fsS "https://<your-railway-domain>/health"
```

If your logs include `PermissionError: [Errno 13]` for `/var/data/local_chunks`, set `LOCAL_CHUNK_DIR=/tmp/local_chunks` and redeploy.

If your logs include `sqlite3.OperationalError: unable to open database file`, set `TELEMETRY_DB=/tmp/telemetry.db` and redeploy.

If this still fails in your Railway workspace, use Render UI flow below (same Docker image).

## Alternative easy UI cloud: Render Web Service

If Railway health checks still fail in your account/project, use Render (Web Service) directly from UI:

1. Push repo to GitHub.
2. In Render: **New +** -> **Web Service** -> select repo.
3. Runtime: Docker (Render auto-detects `Dockerfile`).
4. Set health check path to `/health` (or `/`, both are supported).
5. Add env vars:
   - `API_KEYS=dev-api-key`
   - `MODEL_DIR=advanced_artifacts`
   - `STORAGE_BACKEND=filesystem`
   - `TELEMETRY_DB=/tmp/telemetry.db`
   - `LOCAL_CHUNK_DIR=/tmp/local_chunks`
   - `ADAPTIVE_POW_ENABLED=true`
6. Deploy, then verify:

```bash
curl -fsS "https://<your-render-service>.onrender.com/health"
```

## Concrete deployment checklist (works path)

Use this exact order:

1. Confirm `Dockerfile` exists and unchanged.
2. Push latest commit to GitHub.
3. Connect repo in Railway UI.
4. Set env vars exactly as documented.
5. Set Start Command to `python start_server.py` (or keep repo `railway.json`).
6. Set Healthcheck path to `/health` (or `/` if required by platform behavior).
7. Deploy and verify `/` and `/health`.

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

Generate an isolated smoke-test report (Markdown + JSON):

```bash
.venv/bin/python tests/run_smoke_tests.py
```

Reports are written to `test_reports/`.


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

Demo proof in UI/API:

1. Upload a file once (`POST /upload`) with API key + client ID.
2. Call `GET /demo/encryption` to show runtime encryption flags.
3. Copy one `chunk_hash` from upload response and call `GET /demo/encryption?chunk_hash=<hash>` to show `encrypted_envelope: true` for stored chunk payloads.


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


## Is the project complete?

For a thesis/demo prototype: **yes, functionally complete**.

Implemented end-to-end:
- secure dedup + PoW duplicate ownership verification
- adaptive PoW (risk + reputation aware)
- file versioning and lifecycle
- ownership and transfer tracking
- chunk audit challenge/verify
- encryption-at-rest for chunks
- runtime metrics and benchmark graph generation

For production-hardening, still recommended:
- migration/versioning for DB schema,
- API rate limiting at gateway level,
- stronger auth/tenant isolation and secret management,
- automated integration tests in CI/CD.

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
