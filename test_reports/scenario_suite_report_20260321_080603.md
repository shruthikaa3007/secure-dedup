# Secure Dedup Scenario Suite Report

- Generated (UTC): `2026-03-21T02:43:12.814815+00:00`
- Python: `3.12.4`
- Platform: `Windows-11-10.0.26200-SP0`
- Repo: `E:\secure-dedup`
- Isolated Runtime Dir: `D:\secure-dedup-scenarios-g662uppa`
- Summary: `8/8` passed, `0` failed

## Scenario Outcomes

- `PASS` Scenario 1 - Baseline Upload (44596 ms)
  - Data: `{"file_id": "0bcb7616-2d83-49eb-b19a-55990d16162b", "total_chunks": 1, "chunk_hash": "ed2fb5bd197982c19615fc9b2057ce4d933b257bc796c31122fdef1f2d4879ee"}`
  - Metrics Delta: `{"active_files": 1, "audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "dedup_saved_chunks": 0, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "logical_chunks": 1, "owned_chunk_links": 1, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 3, "unique_chunks": 1}`
- `PASS` Scenario 2 - Duplicate Requires PoW (32483 ms)
  - Data: `{"challenge_count": 1, "retry_path": "direct_duplicate"}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 1, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 2, "unique_chunks": 0}`
- `PASS` Scenario 3 - PoW Solve And Retry (64952 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
  - Metrics Delta: `{"active_files": 1, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 1, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "logical_chunks": 1, "owned_chunk_links": 0, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 1, "requests_seen": 4, "unique_chunks": 0}`
- `PASS` Scenario 4 - Policy Enforcement And Recovery (154208 ms)
  - Data: `{"rate_limit_blocked": true, "block_blocked": true}`
  - Metrics Delta: `{"active_files": 2, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 2, "logical_chunks": 2, "owned_chunk_links": 2, "ownership_events": 2, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 6, "unique_chunks": 2}`
- `PASS` Scenario 5 - File Version Update And Delete (97524 ms)
  - Data: `{"file_id": "696def27-16ba-4b1b-b543-b002f2d81b4c", "version_after_update": 2}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "dedup_saved_chunks": 0, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 3, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 4, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 6, "unique_chunks": 0}`
- `PASS` Scenario 6 - Ownership Transfer And Audit (8166 ms)
  - Data: `{"owner_count_after_transfer": 1, "audit_verified": true}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 1, "audit_events": 3, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
- `PASS` Scenario 7 - Encryption Status And UI Hooks (4 ms)
  - Data: `{"encryption_enabled": true, "ui_hooks_present": true}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
- `PASS` Scenario 8 - Status And Metrics Summary (24295 ms)
  - Data: `{"active_clients": 2, "total_buffered_events": 21, "metrics_keys": ["active_files", "audit_challenges", "audit_events", "clients_seen", "dedup_saved_chunks", "detection_results_rows", "feature_snapshots", "file_versions", "logical_chunks", "owned_chunk_links", "ownership_events", "pow_challenges", "pow_rejected", "pow_verified", "requests_seen", "unique_chunks"], "pow_challenges": 1}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
