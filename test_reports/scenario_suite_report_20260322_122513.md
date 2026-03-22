# Secure Dedup Scenario Suite Report

- Generated (UTC): `2026-03-22T07:02:54.626776+00:00`
- Python: `3.12.4`
- Platform: `Windows-11-10.0.26200-SP0`
- Repo: `E:\secure-dedup`
- Isolated Runtime Dir: `D:\secure-dedup-scenarios-2mzj7vaj`
- Summary: `8/8` passed, `0` failed

## Scenario Outcomes

- `PASS` Scenario 1 - Baseline Upload (48805 ms)
  - Data: `{"file_id": "d5eafed8-d70e-4a09-9e90-ef5acf1b211d", "total_chunks": 1, "chunk_hash": "38f507e1c9d7e4d0fc1305435840fa9dbf7a2b6d1fcb719dfdd3b87ede374735"}`
  - Metrics Delta: `{"active_files": 1, "audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "dedup_saved_chunks": 0, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "logical_chunks": 1, "owned_chunk_links": 1, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 3, "unique_chunks": 1}`
- `PASS` Scenario 2 - Duplicate Requires PoW (36542 ms)
  - Data: `{"challenge_count": 1, "retry_path": "direct_duplicate"}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 1, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 2, "unique_chunks": 0}`
- `PASS` Scenario 3 - PoW Solve And Retry (73029 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
  - Metrics Delta: `{"active_files": 1, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 1, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "logical_chunks": 1, "owned_chunk_links": 0, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 1, "requests_seen": 4, "unique_chunks": 0}`
- `PASS` Scenario 4 - Policy Enforcement And Recovery (162471 ms)
  - Data: `{"rate_limit_blocked": true, "block_blocked": true}`
  - Metrics Delta: `{"active_files": 2, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 2, "logical_chunks": 2, "owned_chunk_links": 2, "ownership_events": 2, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 8, "unique_chunks": 2}`
- `PASS` Scenario 5 - File Version Update And Delete (105644 ms)
  - Data: `{"file_id": "7018945f-0888-4eae-8949-84ad18b6b7f9", "version_after_update": 2}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "dedup_saved_chunks": 0, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 3, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 4, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 6, "unique_chunks": 0}`
- `PASS` Scenario 6 - Ownership Transfer And Audit (8153 ms)
  - Data: `{"owner_count_after_transfer": 1, "audit_verified": true}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 1, "audit_events": 3, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
- `PASS` Scenario 7 - Encryption Status And UI Hooks (0 ms)
  - Data: `{"encryption_enabled": true, "ui_hooks_present": true}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
- `PASS` Scenario 8 - Status And Metrics Summary (24388 ms)
  - Data: `{"active_clients": 2, "total_buffered_events": 23, "metrics_keys": ["active_files", "audit_challenges", "audit_events", "clients_seen", "dedup_saved_chunks", "detection_results_rows", "feature_snapshots", "file_versions", "logical_chunks", "owned_chunk_links", "ownership_events", "pow_challenges", "pow_rejected", "pow_verified", "requests_seen", "unique_chunks"], "pow_challenges": 1}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
