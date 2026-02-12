# Run This Project on Another Laptop

This guide gives you a repeatable setup path on a fresh machine.

## 1) Prerequisites

- OS: macOS/Linux (Windows works with WSL2).
- Python: `3.10+` (recommended `3.10`).
- Tools: `git`, `pip`, `venv`.
- Free disk space:
  - Code + venv + outputs: at least `5 GB`.
  - If using FIU/MSRC raw traces: at least `40 GB` free.

## 2) Get the Project

```bash
git clone <your-repo-url>
cd secure-dedup
```

If you are copying the folder directly (USB/Drive), open terminal inside the copied `secure-dedup` folder and continue.

## 3) Create Python Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Optional (only if you want dense/LSTM autoencoders):

```bash
pip install tensorflow
```

## 4) Choose Your Path

Use one of these two paths.

### Path A: Reuse Existing Prepared Data / Models (Fastest)

Copy these files from your old laptop into this repo root:

- `request_logs.csv` (optional)
- `feature_dataset.csv` (optional)
- `detection_results.csv` (optional)
- `training_data.csv` (optional)
- `isolation_forest.pkl`
- `one_class_svm.pkl`
- `scaler.pkl`
- `model_metadata.json`

Then run API directly (see step 8).

### Path B: Full Rebuild From Raw Datasets (Recommended for fresh training)

Place raw dataset archives in repo root:

- `FIU-trace.tar`
- `MSRC-trace-003.tar`

Run ingestion (balanced multi-client sampling):

```bash
python dataset_adapters.py revised-tar \
  --input FIU-trace.tar \
  --output request_logs_fiu.csv \
  --max-files 40 \
  --max-events-per-file 15000

python dataset_adapters.py revised-tar \
  --input MSRC-trace-003.tar \
  --output request_logs_msrc.csv \
  --max-files 40 \
  --max-events-per-file 15000
```

Merge both logs:

```bash
{ head -n 1 request_logs_fiu.csv; tail -n +2 request_logs_fiu.csv; tail -n +2 request_logs_msrc.csv; } > request_logs.csv
```

Build features + labeled detection dataset:

```bash
python build_feature_dataset_from_logs.py \
  --input request_logs.csv \
  --feature-output feature_dataset.csv \
  --detection-output detection_results.csv \
  --min-events 50
```

Prepare training data:

```bash
python prepare_training_data.py \
  --input detection_results.csv \
  --output training_data.csv \
  --relabel auto
```

Train models:

```bash
python train_model.py \
  --dataset training_data.csv \
  --model-dir . \
  --disable-autoencoder \
  --disable-lstm
```

Note: if the label set has no `normal` class, the code now automatically falls back to unsupervised training.
Each training run auto-generates `evaluation_report.json` and `evaluation_report.md`.

## 5) Validate Outputs

Check that key files exist:

```bash
ls -1 model_metadata.json isolation_forest.pkl one_class_svm.pkl scaler.pkl
```

Inspect model mode:

```bash
cat model_metadata.json
```

## 6) Run the API Locally

```bash
export API_KEYS=dev-api-key
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

Health check:

```bash
curl http://127.0.0.1:8000/health
```

Simple upload test:

```bash
echo "hello dedup" > sample.txt
curl -X POST "http://127.0.0.1:8000/upload" \
  -H "X-API-Key: dev-api-key" \
  -H "X-Client-ID: laptop-test-client" \
  -F "file=@sample.txt"
```

## 7) Optional Services (Not Mandatory)

This project works without Redis/MinIO due in-memory and local-file fallbacks.

- Redis unavailable: `dedup_index.py` uses in-memory map.
- MinIO unavailable: `storage.py` writes chunks to `local_chunks/`.

If you want production-like behavior, run Redis + MinIO separately and set env vars from `README.md`.

## 8) Troubleshooting

- `ModuleNotFoundError`: activate venv first (`source .venv/bin/activate`).
- `PermissionError ... SC_SEM_NSEMS_MAX`: use latest code in this repo (training now uses single-process CV).
- Training is too slow:
  - lower `--max-files` (example: `20`)
  - lower `--max-events-per-file` (example: `8000`)
- `rar` extraction issues for Azure file: skip it for now, FIU/MSRC `.tar` path is already supported.
- API rejects requests with `403`:
  - ensure `X-API-Key` matches `API_KEYS`
  - check anomaly policy cooldown if client was previously blocked

## 9) Recommended Repeatable Command Block

If you want one standard sequence after cloning:

```bash
source .venv/bin/activate
python dataset_adapters.py revised-tar --input FIU-trace.tar --output request_logs_fiu.csv --max-files 40 --max-events-per-file 15000
python dataset_adapters.py revised-tar --input MSRC-trace-003.tar --output request_logs_msrc.csv --max-files 40 --max-events-per-file 15000
{ head -n 1 request_logs_fiu.csv; tail -n +2 request_logs_fiu.csv; tail -n +2 request_logs_msrc.csv; } > request_logs.csv
python build_feature_dataset_from_logs.py --input request_logs.csv --feature-output feature_dataset.csv --detection-output detection_results.csv --min-events 50
python prepare_training_data.py --input detection_results.csv --output training_data.csv --relabel auto
python train_model.py --dataset training_data.csv --model-dir . --disable-autoencoder --disable-lstm
```
