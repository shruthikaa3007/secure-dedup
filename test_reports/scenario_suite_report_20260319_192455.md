# Secure Dedup Scenario Suite Report

- Generated (UTC): `2026-03-19T13:55:00.025395+00:00`
- Python: `3.10.6`
- Platform: `macOS-15.7.4-arm64-arm-64bit`
- Repo: `/Users/shruthikaa.s/untitled folder/Project/secure-dedup`
- Isolated Runtime Dir: `/var/folders/w0/_q_88bx510l_bkzq33bv22xw0000gp/T/secure-dedup-scenarios-fze079l1`
- Summary: `7/8` passed, `1` failed

## Scenario Outcomes

- `PASS` Scenario 1 - Baseline Upload (34 ms)
  - Data: `{"file_id": "84833a5a-b888-45ae-b338-98a74ccc860c", "total_chunks": 1, "chunk_hash": "74b550f546cf3411c535f449c9e94dedc77f71d9fdb7ec1efeebb9758bd59cac"}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "owned_chunk_links": 1, "ownership_events": 1, "requests_seen": 3}`
- `PASS` Scenario 2 - Duplicate Requires PoW (8 ms)
  - Data: `{"challenge_count": 1, "retry_path": "clear_policy_then_duplicate"}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 1}`
- `PASS` Scenario 3 - PoW Solve And Retry (33 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "owned_chunk_links": 0, "ownership_events": 1, "requests_seen": 3}`
- `PASS` Scenario 4 - Policy Enforcement And Recovery (74 ms)
  - Data: `{"rate_limit_blocked": true, "block_blocked": true}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 2, "owned_chunk_links": 2, "ownership_events": 2, "requests_seen": 6}`
- `FAIL` Scenario 5 - File Version Update And Delete (26 ms)
  - Detail: `429: {'error': 'Rate limited by anomaly policy', 'client_id': 'scenario-second-client', 'policy': {'action': 'RATE_LIMIT', 'status_code': 429, 'remaining_sec': 29.99484610557556}}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "owned_chunk_links": 1, "ownership_events": 1, "requests_seen": 3}`
- `PASS` Scenario 6 - Ownership Transfer And Audit (10 ms)
  - Data: `{"owner_count_after_transfer": 1, "audit_verified": true}`
  - Metrics Delta: `{"audit_challenges": 1, "audit_events": 3, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 1, "requests_seen": 0}`
- `PASS` Scenario 7 - Encryption Status And UI Hooks (1 ms)
  - Data: `{"encryption_enabled": false, "ui_hooks_present": true}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 0}`
- `PASS` Scenario 8 - Status And Metrics Summary (4 ms)
  - Data: `{"active_clients": 2, "total_buffered_events": 16, "metrics_keys": ["audit_challenges", "audit_events", "clients_seen", "detection_results_rows", "feature_snapshots", "file_versions", "owned_chunk_links", "ownership_events", "requests_seen"]}`
  - Metrics Delta: `{"audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "owned_chunk_links": 0, "ownership_events": 0, "requests_seen": 0}`
