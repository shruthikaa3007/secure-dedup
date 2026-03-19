# secure-dedup

Secure deduplication prototype focused on one clear story:

1. Upload a file and store its chunks once.
2. Encrypt stored chunks with a chunk-hash-bound segmented AES-GCM envelope.
3. When the same chunk is claimed again, require proof-of-ownership before dedup reuse.
4. Keep behavioural monitoring available as runtime telemetry rather than an overloaded operator UI.

The project definition lives in [docs/project_notes/PROJECT_DEFINITION.md](/Users/shruthikaa.s/untitled%20folder/Project/secure-dedup/docs/project_notes/PROJECT_DEFINITION.md).

## Final Project Scope

- Core problem: preserve deduplication benefits without allowing fake duplicate claims.
- Base paper anchor: Peng et al., IEEE TNSM 2025 on secure deduplication, auditing, and ownership management.
- Final novelty for this repo:
  - chunk-hash-bound segmented AES-GCM encryption at rest,
  - proof-of-ownership challenge flow for duplicate uploads,
  - step-by-step demo UI with clear dedup, PoW, and behavioural monitoring metrics.

Secondary research modules remain in the repo, but the primary runtime path and UI now focus on encrypted dedup plus PoW verification.

## Repository Map

- `app.py`: FastAPI service and upload/PoW endpoints.
- `encryption.py`: segmented AES-GCM envelope bound to chunk hash context.
- `pow.py`, `pow_session.py`, `adaptive_pow.py`: duplicate challenge generation and verification.
- `storage.py`, `dedup_index.py`, `ownership_store.py`, `file_catalog.py`: chunk storage, dedup references, ownership, and file versions.
- `ui/`: simplified step-by-step web UI.
- `tests/run_smoke_tests.py`: local isolated smoke validation.
- `tests/run_deployment_smoke.py`: deployment-facing smoke tests for Render/Railway/other hosted URLs.
- `notebooks/deployment_smoke_colab.ipynb`: Colab notebook that runs the deployment smoke test and shows results.

## Local Run

Install dependencies:

```bash
pip install -r requirements.txt
```

Optional encryption key:

```bash
python generate_encryption_key.py
```

Run the service:

```bash
uvicorn app:app --reload
```

Open the guided UI:

```text
http://127.0.0.1:8000/ui/
```

## Guided Demo Flow

The UI is intentionally small now. It walks through three steps:

1. `Step 1: Upload Original File`
2. `Step 2: Upload Duplicate and Request PoW`
3. `Step 3: Solve Challenge and Retry`

The dashboard surfaces only the metrics needed for the thesis/demo story:

- active files
- unique chunks
- dedup saved chunks
- PoW challenges issued
- PoW proofs verified/rejected
- encryption state
- monitored clients and request volume

## Local Tests

Run the isolated smoke suite:

```bash
python tests/run_smoke_tests.py
```

Run the broader local scenario suite:

```bash
python tests/run_scenario_suite.py
```

## Deployment Smoke Test

Set deployment values:

```bash
export SECURE_DEDUP_BASE_URL="https://your-deployment.example.com"
export SECURE_DEDUP_API_KEY="dev-api-key"
export SECURE_DEDUP_CLIENT_ID="deployment-smoke-client"
```

Run:

```bash
python tests/run_deployment_smoke.py
```

This test verifies:

1. `/health`
2. `/demo/config`
3. first upload success
4. duplicate upload returns PoW challenge
5. valid proof retry succeeds
6. `/metrics` and `/demo/metrics/summary` show clear dedup/PoW numbers

## Colab Notebook

Use [notebooks/deployment_smoke_colab.ipynb](/Users/shruthikaa.s/untitled%20folder/Project/secure-dedup/notebooks/deployment_smoke_colab.ipynb) to run the deployment smoke flow from Google Colab and display the latest JSON/Markdown report.

## Cleanup Notes

Generated runtime output is intentionally ignored:

- `test_reports/`
- `uploads/`
- `local_chunks/`
- `request_logs.csv`
- generated demo comparison files

This keeps the repo centered on the implementation instead of checked-in runtime noise.
