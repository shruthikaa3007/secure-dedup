# Secure Dedup Scenario Suite Report

- Generated (UTC): `2026-03-19T14:54:14.064572+00:00`
- Python: `3.10.6`
- Platform: `macOS-15.7.4-arm64-arm-64bit`
- Repo: `/Users/shruthikaa.s/untitled folder/Project/secure-dedup`
- Isolated Runtime Dir: `/var/folders/w0/_q_88bx510l_bkzq33bv22xw0000gp/T/secure-dedup-scenarios-d5o9_btp`
- Summary: `8/8` passed, `0` failed

## Scenario Outcomes

- `PASS` Scenario 1 - Baseline Upload (50 ms)
  - Data: `{"file_id": "658e3c7f-796b-4103-9718-bbc12f8c79b5", "total_chunks": 1, "chunk_hash": "ef481a67fb26c3c974da207f954589068a6b1ef0dc059107dd338e3197f535ef"}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "owned_chunk_links": 1, "ownership_events": 1, "requests_seen": 3}`
- `PASS` Scenario 2 - Duplicate Requires PoW (20 ms)
  - Data: `{"challenge_count": 1, "retry_path": "clear_policy_then_duplicate"}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 1}`
- `PASS` Scenario 3 - PoW Solve And Retry (50 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "owned_chunk_links": 0, "ownership_events": 1, "requests_seen": 3}`
- `PASS` Scenario 4 - Policy Enforcement And Recovery (132 ms)
  - Data: `{"rate_limit_blocked": true, "block_blocked": true}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 2, "owned_chunk_links": 2, "ownership_events": 2, "requests_seen": 6}`
- `PASS` Scenario 5 - File Version Update And Delete (114 ms)
  - Data: `{"file_id": "16d5ab88-2c3a-4c31-adc0-4ffba7b0f387", "version_after_update": 2}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 3, "owned_chunk_links": 0, "ownership_events": 4, "requests_seen": 6}`
- `PASS` Scenario 6 - Ownership Transfer And Audit (25 ms)
  - Data: `{"owner_count_after_transfer": 1, "audit_verified": true}`
  - Metrics Delta: `{"audit_challenges": 1, "audit_events": 3, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 1, "requests_seen": 0}`
- `PASS` Scenario 7 - Encryption Status And UI Hooks (1 ms)
  - Data: `{"encryption_enabled": false, "ui_hooks_present": true}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 0}`
- `PASS` Scenario 8 - Status And Metrics Summary (8 ms)
  - Data: `{"active_clients": 2, "total_buffered_events": 19, "metrics_keys": ["audit_challenges", "audit_events", "clients_seen", "detection_results_rows", "feature_snapshots", "file_versions", "owned_chunk_links", "ownership_events", "requests_seen"]}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 0}`
