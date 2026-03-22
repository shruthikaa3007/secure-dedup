# Secure Dedup Smoke Test Report

- Generated (UTC): `2026-03-20T19:43:57.399008+00:00`
- Python: `3.12.4`
- Platform: `Windows-11-10.0.26200-SP0`
- Repo: `E:\secure-dedup`
- Isolated Runtime Dir: `D:\secure-dedup-smoke-3ddhsv61`
- Summary: `7/7` passed, `0` failed

## Test Cases

- `PASS` Health Endpoint (0 ms)
  - Data: `{"status": "ok"}`
- `PASS` Config Endpoint (0 ms)
  - Data: `{"project_title": "Secure Cloud Deduplication with Secret-Assisted Encryption, PoW, and Behavioural Monitoring", "detection_mode": "supervised", "storage": "filesystem", "encryption_enabled": true, "fingerprint_mode": "secret_hmac"}`
- `PASS` Upload Success (48813 ms)
  - Data: `{"file_id": "b1899768-555a-49df-a390-2ba6082ecd45", "total_chunks": 1, "first_chunk": "9f6e3c6206c9313bdd726a7c8d45dd1411bbe3cba5dacaab933c275958a4a07f"}`
- `PASS` Duplicate Requires PoW (48618 ms)
  - Data: `{"challenge_count": 1, "hint": "Call /pow/verify or provide pow_proofs_json and retry /upload", "retry_path": "clear_policy_then_duplicate"}`
- `PASS` PoW Solve And Retry (69103 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
- `PASS` Status And Metrics (12164 ms)
  - Data: `{"active_clients": 1, "total_buffered_events": 9, "metrics_keys": ["active_files", "audit_challenges", "audit_events", "clients_seen", "dedup_saved_chunks", "detection_results_rows", "feature_snapshots", "file_versions", "logical_chunks", "owned_chunk_links", "ownership_events", "pow_challenges", "pow_rejected", "pow_verified", "requests_seen", "unique_chunks"], "pow_challenges": 1}`
- `PASS` UI Assets Functional Hooks (16 ms)
  - Data: `{"ui_checks": "ok"}`
