# secure-dedup

Secure cloud deduplication prototype aligned to Wu et al. (JISA 2024), with four demo-ready outcomes:

1. Upload a file once and store only new chunks.
2. Reuse matching chunks across similar files.
3. Protect duplicate reuse with proof-of-ownership (PoW).
4. Show encryption, chunk reuse, and attack throttling clearly in Swagger UI.

Base paper direction:

- Wu et al., *Journal of Information Security and Applications* (2024), on randomized deduplication encryption against frequency attack.

Final-year-project scope note:

- The core claim is the Wu-et-al improvement path only: stronger dedup-aware encryption, visible PoW, and lightweight throttling.
- Auditing, ownership transfer, and broader data-dynamics code may remain in the repo, but they are not part of the main thesis claim or demo.

## What This Repo Demonstrates

- Secret-assisted dedup tokens using `HMAC-SHA256` instead of plain public `SHA-256`.
- Fingerprint-bound segmented `AES-GCM` encryption with `HKDF-SHA256` key derivation.
- PoW challenges before duplicate chunks can be reused.
- Runtime policy actions such as `RATE_LIMIT` and `BLOCK`.
- Demo-facing endpoints for:
  - encryption comparison,
  - shared chunk comparison between files,
  - per-client PoW and rate-limit highlights.

## Main Demo Surface

The most reliable demo entry point is Swagger UI:

```text
http://127.0.0.1:8000/
```

The custom frontend still exists under `/ui/`, but the recommended presentation path is now Swagger because it exposes the important responses directly.

## Repo Map

- `app.py`: FastAPI service and demo endpoints.
- `hashing.py`: dedup token generation (`sha256` or `secret_hmac`).
- `encryption.py`: fingerprint-bound segmented AES-GCM envelope.
- `pow.py`, `pow_session.py`, `adaptive_pow.py`: PoW challenge creation and verification.
- `storage.py`, `dedup_index.py`: chunk storage and ref counting.
- `file_catalog.py`, `ownership_store.py`: optional lifecycle support kept outside the core demo story.
- `compare_dedup_encryption_schemes.py`: baseline vs proposed encryption benchmark.
- `tests/run_smoke_tests.py`: end-to-end smoke flow.
- `tests/test_encryption.py`: encryption unit tests.
- `tests/test_frequency_attack_resistance.py`: REFA-aligned proof that HMAC blocks the public-token vulnerability while preserving dedup.
- `tests/test_attack_detection_demo.py`: self-contained behavioural attack demos for hash probing, dedup DoS, and ownership fraud.
- `notebooks/encryption_demo_colab.ipynb`: Colab notebook for the encryption + PoW demo story.
- `docs/project_notes/BASE_PAPER_ALIGNMENT.md`: direct explanation of how this project improves on Wu et al.

## 1. Clone The Repo

```bash
git clone <your-repo-url>
cd secure-dedup
```

## 2. Create And Activate A Virtual Environment

### Windows PowerShell

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### macOS / Linux

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 3. Run The API

### Recommended Local Demo Mode

This mode uses:

- `advanced_artifacts` as the model set,
- demo-safe thresholds,
- filesystem storage fallback,
- encryption enabled,
- secret-HMAC dedup tokens enabled.

### Windows PowerShell

```powershell
$env:API_KEYS="dev-api-key"
$env:REQUIRE_API_KEY="true"
$env:MODEL_DIR="advanced_artifacts"
$env:RATE_LIMIT_THRESHOLD="0.70"
$env:BLOCK_THRESHOLD="0.90"
$env:DEMO_MODE="true"
$env:CHUNK_ENCRYPTION_DEFAULT_ON="true"
$env:DEDUP_FINGERPRINT_MODE="secret_hmac"
$env:DEDUP_FINGERPRINT_DEFAULT_ON="true"
$env:STORAGE_BACKEND="filesystem"

.\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 8000
```

### macOS / Linux

```bash
export API_KEYS=dev-api-key
export REQUIRE_API_KEY=true
export MODEL_DIR=advanced_artifacts
export RATE_LIMIT_THRESHOLD=0.70
export BLOCK_THRESHOLD=0.90
export DEMO_MODE=true
export CHUNK_ENCRYPTION_DEFAULT_ON=true
export DEDUP_FINGERPRINT_MODE=secret_hmac
export DEDUP_FINGERPRINT_DEFAULT_ON=true
export STORAGE_BACKEND=filesystem

./.venv/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/
```

## 4. Optional LocalStack / Redis Run

If you want object-storage-style demo infrastructure locally:

```bash
./run_demo.sh cloud-start
```

Stop it with:

```bash
./run_demo.sh stop
```

## 5. Tests

### Encryption Unit Tests

```bash
./.venv/bin/python -m pytest tests/test_encryption.py -q
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_encryption.py -q
```

### Frequency-Attack Resistance Demo Tests

```bash
./.venv/bin/python -m pytest tests/test_frequency_attack_resistance.py -v -s
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_frequency_attack_resistance.py -v -s
```

### Behavioural Attack Demo Tests

```bash
./.venv/bin/python -m pytest tests/test_attack_detection_demo.py -v -s
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_attack_detection_demo.py -v -s
```

### Smoke Test

```bash
./.venv/bin/python tests/run_smoke_tests.py
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe tests\run_smoke_tests.py
```

## 6. Encryption Comparison

Run the checked-in benchmark locally:

```bash
./.venv/bin/python compare_dedup_encryption_schemes.py
```

On Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe compare_dedup_encryption_schemes.py
```

For a presentation-friendly terminal table:

```powershell
.\.venv\Scripts\python.exe compare_dedup_encryption_schemes.py --print-table
```

Generated outputs:

- `docs/project_notes/encryption_scheme_comparison.json`
- `docs/project_notes/encryption_scheme_comparison.md`

Live API view:

```text
GET /demo/encryption/comparison
```

This is the fastest way to show:

- baseline public-hash-bound encryption,
- proposed secret-HMAC-bound encryption,
- dedup saved percent,
- token time delta,
- encrypt/decrypt time deltas,
- storage overhead delta.

## 7. Demo Flow In Swagger

Use header values:

- `X-API-Key: dev-api-key`
- `X-Client-ID: demo-client-1`

### A. Show The Encryption Story

1. Open `GET /demo/encryption/comparison`
2. Click `Execute`
3. Show:
   - `baseline_scheme`
   - `proposed_scheme`
   - `dedup_saved_percent_baseline`
   - `dedup_saved_percent_proposed`
   - `token_time_delta_pct`
   - `storage_overhead_delta_bytes`

### B. Show Chunk Reuse Across Similar Files

Use two controlled files with large shared regions. This is important: naturally edited tiny files do not always share visible chunks depending on chunk boundaries.

Best options:

- use the Colab notebook in `notebooks/encryption_demo_colab.ipynb`, or
- create two files where the start and end blocks are identical and the middle block differs.

Demo sequence:

1. `POST /upload` with file A
2. `POST /upload` with file B
3. If the response is `409`, show:
   - `detail.chunk_summary`
   - `detail.chunk_details`
   - `detail.required_challenges`
4. `POST /demo/solve_pow`
5. Retry `POST /upload` with `pow_proofs_json`
6. `GET /demo/compare-files`

What to point out:

- `shared_chunk_count`
- `shared_chunk_positions`
- `chunk_summary.shared_with_existing_count`
- `chunk_summary.reused_existing_count`
- `chunk_summary.pow_required_count`
- `chunk_summary.pow_verified_count`

### C. Show Duplicate Protection

1. Upload the same file again with the same client
2. Show the `409` response

Call out:

- `detail.error = "PoW verification required for duplicate chunks"`
- `detail.required_challenges`
- `detail.chunk_summary.shared_with_existing_count`

### D. Show Rate Limiting During Attack Scenarios

1. `POST /demo/force-policy` with:

```json
{
  "client_id": "demo-client-1",
  "action": "RATE_LIMIT"
}
```

2. Attempt another `POST /upload`
3. Show the `429` response
4. Open `GET /demo/highlights/{client_id}`

What to point out:

- `detail.policy.action`
- `detail.policy.remaining_sec`
- `highlights.rate_limit_events`
- `highlights.pow_challenges_issued`
- `highlights.duplicate_reuse_successes`
- `recent_events`

## 8. Colab Demo Option

If you want a notebook-driven presentation instead of manual Swagger clicking, use:

- `notebooks/encryption_demo_colab.ipynb`

It demonstrates:

- encryption comparison,
- controlled similar-file chunk overlap,
- PoW solve-and-retry,
- rate-limit evidence.

## 9. Larger Dataset Option

If an examiner pushes on dataset size, do not anchor your answer on the small legacy `training_data.csv` snapshot alone. The stronger story is the trace-to-window pipeline:

```bash
./.venv/bin/python build_windowed_feature_dataset.py \
  --input request_logs_fiu.csv \
  --input request_logs_msrc.csv \
  --feature-output multisource_feature_dataset.csv \
  --detection-output multisource_detection_results.csv \
  --window-sec 120 \
  --step-sec 30 \
  --min-events 10 \
  --max-windows-per-client 200
```

This builds a larger trace-derived dataset from multiple standardized request-log sources while automatically tagging client ids per source to avoid collisions.

Already generated in this repo:

- `multisource_dense_feature_dataset.csv`
- `multisource_dense_detection_results.csv`
- `dense_artifacts/training_metrics.json`
- `dense_artifacts/evaluation_report.md`

Current dense-run snapshot:

- raw events loaded: `1,026,034`
- processed clients: `72`
- dense window rows: `221`
- best supervised model: `random_forest`
- best CV macro F1: `0.9652`

## 10. Scope Note

The current project story is intentionally centered on:

- dedup-aware encryption,
- chunk reuse visibility,
- PoW protection on duplicate reuse,
- behavioural throttling during suspicious activity.

Audit endpoints and related lifecycle code remain in the repo as secondary modules, but they are not part of the main demo or thesis claim.

## 11. Notes For Similar Files

If two files are only "slightly similar" in a casual sense, they may still fail to show chunk overlap clearly.

That is not necessarily a bug.

Why:

- chunking depends on content boundaries,
- small edits can shift chunk boundaries,
- short files may collapse into very few chunks.

For a reliable presentation, use files with:

- a large identical prefix,
- a different middle region,
- a large identical suffix.

That is exactly why the Colab notebook uses controlled payloads.

## 12. Cleanup

Generated runtime output is intentionally ignored:

- `test_reports/`
- `uploads/`
- `local_chunks/`
- `request_logs.csv`

This keeps the repo focused on implementation and demo artifacts instead of runtime noise.
