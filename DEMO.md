# 10-Minute Demo Runbook

This runbook is optimized for the current repo state: Wu et al. as the base
paper, Swagger as the live demo surface, and the new self-contained tests as
the fastest way to show the security story clearly.

## 1. Start The API

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

Open `http://127.0.0.1:8000/`.

Headers to use in Swagger:

- `X-API-Key: dev-api-key`
- `X-Client-ID: demo-client-1`

## 2. Step 1 - Frequency Attack Resistance

Run this first.

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_frequency_attack_resistance.py -v -s
```

What to say:

`Wu et al. show why deterministic deduplication encryption is dangerous. These tests show the exact vulnerability under public SHA-256, and then show that our HMAC token blocks it while preserving cross-user deduplication.`

The key lines to point at are:

- SHA-256 token is reproducible
- HMAC token is not reproducible
- ten users still dedup correctly
- the adversary recovers zero matches under HMAC

## 3. Step 2 - Encryption Benchmark Table

```powershell
.\.venv\Scripts\python.exe compare_dedup_encryption_schemes.py --print-table
```

What to say:

`The important point is not just runtime. The proposed scheme keeps the same dedup savings, but the token is no longer reproducible by an external attacker, and it does not need an external key server.`

The three key rows are:

- `Token reproducible?`
- `Frequency attack resistant?`
- `External key server?`

## 4. Step 3 - Live Swagger Demo

Open Swagger and use this order:

1. `GET /demo/encryption/comparison`
2. `POST /upload` with file A
3. `POST /upload` with file B
4. If file B returns `409`, inspect `detail.chunk_summary` and `detail.chunk_details`
5. `POST /demo/solve_pow`
6. Retry `POST /upload` with `pow_proofs_json`
7. `GET /demo/compare-files`
8. `POST /demo/force-policy` with `RATE_LIMIT`
9. `POST /upload` again to show `429`
10. `GET /demo/highlights/{client_id}`

What to say:

`This is the live system view: dedup-aware encrypted storage, visible PoW before duplicate reuse, and lightweight runtime throttling when the client behaves suspiciously.`

## 5. Step 4 - Behavioural Attack Detection Demo

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_attack_detection_demo.py -v -s
```

The sentence to say out loud:

`REFA would: ALLOW | Our framework would: RATE_LIMIT.`

That line comes from:

```powershell
.\.venv\Scripts\python.exe -m pytest tests\test_attack_detection_demo.py::TestREFAGapDemonstration::test_gap2_refa_has_no_behaviour_detection -v -s
```

Why it matters:

- the attacker stays below a static requests-per-minute threshold,
- but the upload-to-query ratio is still abnormal,
- so the behavioural layer catches what crypto-only dedup schemes do not.

## 6. Examiner Questions

### Q: How is this different from Wu et al.?

`Wu et al. motivate reducing leakage from deterministic deduplication encryption. My project improves that direction with a lighter server-side design: HMAC chunk identities, HKDF-bound AES-GCM, visible proof-of-ownership, and behavioural throttling.`

### Q: Why no external key server?

`REFA uses a trusted key-server-style path. My prototype keeps the secret server-side instead, so it avoids the extra external service and stays easier to demo. The trade-off is a stronger trust assumption in the storage server.`

### Q: Is the dataset large enough?

Use this answer:

`The small legacy training_data.csv snapshot is not the full data story. The repo also contains large standardized request-log sources, including request_logs_fiu.csv and request_logs_msrc.csv, together covering 1,026,034 raw events. I generated a denser multi-source windowed dataset with 221 labelled windows across 72 clients, and trained a fresh supervised model on that larger trace-derived set. I still present the result as prototype-scale rather than deployment-scale, because the labels are rule-derived from traces rather than collected from a production system.`

Files you can point at:

- `multisource_dense_detection_results.csv`
- `dense_artifacts/training_metrics.json`
- `dense_artifacts/evaluation_report.md`

Command to show the larger dataset path:

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

### Q: What is the main limitation?

`The current evaluation is still trace-derived and prototype-scale. The strongest claim is not production readiness; it is that the security properties are visible, testable, and stronger than a deterministic public-hash baseline.`

## 7. Cleanup

```powershell
Get-Process | Where-Object { $_.ProcessName -eq 'python' -and $_.Path -eq 'E:\secure-dedup\.venv\Scripts\python.exe' } | ForEach-Object { Stop-Process -Id $_.Id -Force }
```
