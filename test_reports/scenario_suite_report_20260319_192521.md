# Secure Dedup Scenario Suite Report

- Generated (UTC): `2026-03-19T13:55:23.881144+00:00`
- Python: `3.10.6`
- Platform: `macOS-15.7.4-arm64-arm-64bit`
- Repo: `/Users/shruthikaa.s/untitled folder/Project/secure-dedup`
- Isolated Runtime Dir: `/var/folders/w0/_q_88bx510l_bkzq33bv22xw0000gp/T/secure-dedup-scenarios-o0bi2hb2`
- Summary: `8/8` passed, `0` failed

## Scenario Outcomes

- `PASS` Scenario 1 - Baseline Upload (47 ms)
  - Data: `{"file_id": "bc250629-b38f-47d7-814a-4f4d3b6b2283", "total_chunks": 1, "chunk_hash": "1fb26d9808f80f9b7a7f6e3fad41b4dc1f6bb4d98bdb46817d4defbce62ba677"}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "owned_chunk_links": 1, "ownership_events": 1, "requests_seen": 3}`
- `PASS` Scenario 2 - Duplicate Requires PoW (17 ms)
  - Data: `{"challenge_count": 1, "retry_path": "clear_policy_then_duplicate"}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 1}`
- `PASS` Scenario 3 - PoW Solve And Retry (40 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "owned_chunk_links": 0, "ownership_events": 1, "requests_seen": 3}`
- `PASS` Scenario 4 - Policy Enforcement And Recovery (88 ms)
  - Data: `{"rate_limit_blocked": true, "block_blocked": true}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 2, "owned_chunk_links": 2, "ownership_events": 2, "requests_seen": 6}`
- `PASS` Scenario 5 - File Version Update And Delete (95 ms)
  - Data: `{"file_id": "18fc3d18-73f3-4519-98bc-f86e98a8fafd", "version_after_update": 2}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 3, "owned_chunk_links": 0, "ownership_events": 4, "requests_seen": 6}`
- `PASS` Scenario 6 - Ownership Transfer And Audit (14 ms)
  - Data: `{"owner_count_after_transfer": 1, "audit_verified": true}`
  - Metrics Delta: `{"audit_challenges": 1, "audit_events": 3, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 1, "requests_seen": 0}`
- `PASS` Scenario 7 - Encryption Status And UI Hooks (0 ms)
  - Data: `{"encryption_enabled": false, "ui_hooks_present": true}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 0}`
- `PASS` Scenario 8 - Status And Metrics Summary (11 ms)
  - Data: `{"active_clients": 2, "total_buffered_events": 19, "metrics_keys": ["audit_challenges", "audit_events", "clients_seen", "detection_results_rows", "feature_snapshots", "file_versions", "owned_chunk_links", "ownership_events", "requests_seen"]}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 0}`
