# Secure Dedup Smoke Test Report

- Generated (UTC): `2026-03-18T06:36:35.232274+00:00`
- Python: `3.10.6`
- Platform: `macOS-15.7.4-arm64-arm-64bit`
- Repo: `/Users/shruthikaa.s/untitled folder/Project/secure-dedup`
- Isolated Runtime Dir: `/var/folders/w0/_q_88bx510l_bkzq33bv22xw0000gp/T/secure-dedup-smoke-gzzo9tts`
- Summary: `7/7` passed, `0` failed

## Test Cases

- `PASS` Health Endpoint (0 ms)
  - Data: `{"status": "ok"}`
- `PASS` Config Endpoint (0 ms)
  - Data: `{"detection_mode": "supervised", "storage": "filesystem", "encryption_enabled": false}`
- `PASS` Upload Success (54 ms)
  - Data: `{"file_id": "c66c9873-de3b-443e-84f4-7b547ec728c1", "total_chunks": 1, "first_chunk": "f9890a81d2372b491b699431bdb5e857af79e1dcac1db551872a5944eec53542"}`
- `PASS` Duplicate Requires PoW (10 ms)
  - Data: `{"challenge_count": 1, "hint": "Call /pow/verify or provide pow_proofs_json and retry /upload"}`
- `PASS` PoW Solve And Retry (39 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
- `PASS` Status And Metrics (6 ms)
  - Data: `{"active_clients": 1, "total_buffered_events": 7, "metrics_keys": ["audit_challenges", "audit_events", "clients_seen", "detection_results_rows", "feature_snapshots", "file_versions", "owned_chunk_links", "ownership_events", "requests_seen"]}`
- `PASS` UI Assets Functional Hooks (0 ms)
  - Data: `{"ui_checks": "ok"}`
