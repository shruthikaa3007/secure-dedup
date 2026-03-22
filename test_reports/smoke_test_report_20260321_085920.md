# Secure Dedup Smoke Test Report

- Generated (UTC): `2026-03-21T03:29:20.870100+00:00`
- Python: `3.12.4`
- Platform: `Windows-11-10.0.26200-SP0`
- Repo: `E:\secure-dedup`
- Isolated Runtime Dir: `D:\secure-dedup-smoke-4j2kcdeb`
- Summary: `7/7` passed, `0` failed

## Test Cases

- `PASS` Health Endpoint (0 ms)
  - Data: `{"status": "ok"}`
- `PASS` Config Endpoint (0 ms)
  - Data: `{"project_title": "Secure Cloud Deduplication with Secret-Assisted Encryption, PoW, and Behavioural Monitoring", "detection_mode": "supervised", "storage": "filesystem", "encryption_enabled": true, "fingerprint_mode": "secret_hmac"}`
- `PASS` Upload Success (48463 ms)
  - Data: `{"file_id": "462297b8-bd1e-4859-901e-2c9a5ada1cb0", "total_chunks": 1, "first_chunk": "6c9db4fce499caad8bf3b840d361d19a8339f7e7b7d59606cde220563d96c4de"}`
- `PASS` Duplicate Requires PoW (36311 ms)
  - Data: `{"challenge_count": 1, "hint": "Call /pow/verify or provide pow_proofs_json and retry /upload", "retry_path": "direct_duplicate"}`
- `PASS` PoW Solve And Retry (72685 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
- `PASS` Status And Metrics (12115 ms)
  - Data: `{"active_clients": 1, "total_buffered_events": 9, "metrics_keys": ["active_files", "audit_challenges", "audit_events", "clients_seen", "dedup_saved_chunks", "detection_results_rows", "feature_snapshots", "file_versions", "logical_chunks", "owned_chunk_links", "ownership_events", "pow_challenges", "pow_rejected", "pow_verified", "requests_seen", "unique_chunks"], "pow_challenges": 1}`
- `PASS` UI Assets Functional Hooks (1 ms)
  - Data: `{"ui_checks": "ok"}`
