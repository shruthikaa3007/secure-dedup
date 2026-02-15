# Run on Another Machine (Local Stack Demo)

This is the fastest way to show the project on a new laptop with a local stack.

## 1) Prerequisites

- Python `3.10+`
- Docker Desktop (or Docker Engine + Compose)
- `git`

## 2) Get Project + Env

```bash
git clone <your-repo-url>
cd secure-dedup

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## 3) Copy Demo Artifacts From Current Machine

Copy these into the same paths on the new machine:

- `advanced_artifacts/` (recommended model set)
- `demo_detection_results.csv`
- `pow_comparison_summary.json`
- `pow_comparison_report.md`
- `architecture.drawio`
- `PROGRESS_60.md`
- `TMRW_TALK_TRACK.md`

If you cannot copy artifacts, you can retrain later; for tomorrow demo, copying is fastest.

## 4) Start Local Stack (Redis + MinIO)

```bash
docker compose -f docker-compose.local.yml up -d
docker compose -f docker-compose.local.yml ps
```

MinIO console: `http://127.0.0.1:9001`  
Username/password: `minioadmin` / `minioadmin`

## 5) Start API with Advanced Model Artifacts

```bash
source .venv/bin/activate

export API_KEYS=dev-api-key
export MODEL_DIR=advanced_artifacts

export MINIO_ENDPOINT=127.0.0.1:9000
export MINIO_ACCESS_KEY=minioadmin
export MINIO_SECRET_KEY=minioadmin
export MINIO_SECURE=false
export MINIO_BUCKET=chunks

uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Or use the one-command runner:

```bash
./run_demo.sh start
```

## 6) Smoke Test

Health:

```bash
curl http://127.0.0.1:8000/health
```

First upload:

```bash
echo "hello dedup demo" > sample.txt
curl -X POST "http://127.0.0.1:8000/upload" \
  -H "X-API-Key: dev-api-key" \
  -H "X-Client-ID: demo-client-1" \
  -F "file=@sample.txt"
```

Second upload (same file) should trigger duplicate PoW path and return challenge/requirements:

```bash
curl -X POST "http://127.0.0.1:8000/upload" \
  -H "X-API-Key: dev-api-key" \
  -H "X-Client-ID: demo-client-1" \
  -F "file=@sample.txt"
```

## 7) What to Show in the Demo

1. Runtime architecture (`architecture.drawio`)
2. Progress + results (`PROGRESS_60.md`)
3. Talk script (`TMRW_TALK_TRACK.md`)
4. Comparison result (`pow_comparison_summary.json`, `pow_comparison_report.md`)
5. Live API flow (`/health`, `/upload`, duplicate-trigger behavior)

## 8) Optional: Run Without Docker Services

The app has fallbacks:

- No Redis -> in-memory dedup/reputation state
- No MinIO -> local filesystem chunks (`local_chunks/`)

So you can still run:

```bash
source .venv/bin/activate
export API_KEYS=dev-api-key
export MODEL_DIR=advanced_artifacts
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

## 9) Stop Local Stack

```bash
docker compose -f docker-compose.local.yml down
```

Or:

```bash
./run_demo.sh stop
```
