# Secure Dedup Smoke Test Report

- Generated (UTC): `2026-03-22T06:54:59.986658+00:00`
- Python: `3.12.4`
- Platform: `Windows-11-10.0.26200-SP0`
- Repo: `E:\secure-dedup`
- Isolated Runtime Dir: `D:\secure-dedup-smoke-dk9onkc8`
- Summary: `7/7` passed, `0` failed

## Test Cases

- `PASS` Health Endpoint (0 ms)
  - Data: `{"status": "ok"}`
- `PASS` Config Endpoint (0 ms)
  - Data: `{"project_title": "Secure Cloud Deduplication with Secret-Assisted Encryption, PoW, and Behavioural Monitoring", "detection_mode": "supervised", "storage": "filesystem", "encryption_enabled": true, "fingerprint_mode": "secret_hmac"}`
- `PASS` Upload Success (48665 ms)
  - Data: `{"file_id": "cd2da734-2f53-48f1-b967-449824b479dc", "total_chunks": 1, "first_chunk": "91be17b16612c1443705ea686c1d266bcc32ab0316afcff477670347fe4a1e23"}`
- `PASS` Duplicate Requires PoW (36465 ms)
  - Data: `{"challenge_count": 1, "hint": "Call /pow/verify or provide pow_proofs_json and retry /upload", "retry_path": "direct_duplicate"}`
- `PASS` PoW Solve And Retry (73145 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
- `PASS` Status And Metrics (12205 ms)
  - Data: `{"active_clients": 1, "total_buffered_events": 9, "metrics_keys": ["active_files", "audit_challenges", "audit_events", "clients_seen", "dedup_saved_chunks", "detection_results_rows", "feature_snapshots", "file_versions", "logical_chunks", "owned_chunk_links", "ownership_events", "pow_challenges", "pow_rejected", "pow_verified", "requests_seen", "unique_chunks"], "pow_challenges": 1}`
- `PASS` UI Assets Functional Hooks (92 ms)
  - Data: `{"ui_checks": "ok"}`
