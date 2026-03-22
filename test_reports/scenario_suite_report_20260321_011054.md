# Secure Dedup Scenario Suite Report

- Generated (UTC): `2026-03-20T19:48:30.096171+00:00`
- Python: `3.12.4`
- Platform: `Windows-11-10.0.26200-SP0`
- Repo: `E:\secure-dedup`
- Isolated Runtime Dir: `D:\secure-dedup-scenarios-5wevs1b_`
- Summary: `7/8` passed, `1` failed

## Scenario Outcomes

- `PASS` Scenario 1 - Baseline Upload (48819 ms)
  - Data: `{"file_id": "bd0c38e7-74cb-4cab-874c-cd6323a15a8a", "total_chunks": 1, "chunk_hash": "09876d0b8b2a60eddad5c30807d869004825732e9e24545a5302e26fd00043af"}`
  - Metrics Delta: `{"active_files": 1, "audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "dedup_saved_chunks": 0, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "logical_chunks": 1, "owned_chunk_links": 1, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 3, "unique_chunks": 1}`
- `PASS` Scenario 2 - Duplicate Requires PoW (48604 ms)
  - Data: `{"challenge_count": 1, "retry_path": "clear_policy_then_duplicate"}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 1, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 2, "unique_chunks": 0}`
- `PASS` Scenario 3 - PoW Solve And Retry (69115 ms)
  - Data: `{"proof_count": 1, "retry_total_chunks": 1}`
  - Metrics Delta: `{"active_files": 1, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 1, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "logical_chunks": 1, "owned_chunk_links": 0, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 1, "requests_seen": 4, "unique_chunks": 0}`
- `FAIL` Scenario 4 - Policy Enforcement And Recovery (130280 ms)
  - Detail: `429: {'error': 'Rate limited by anomaly policy', 'client_id': 'scenario-main-client', 'policy': {'action': 'RATE_LIMIT', 'status_code': 429, 'risk_score': 0.595, 'rate_limit_threshold': 0.55, 'block_threshold': 0.8}, 'detection': {'model_scores': {'predicted_label': 'normal', 'prediction_confidence': 0.405, 'normal_probability': 0.405}, 'is_anomaly': False, 'risk_score': 0.595, 'anomaly_votes': 0, 'models_considered': 1, 'model_flags': {'supervised_classifier': False}, 'lstm_is_anomaly': False, 'lstm_error': None, 'predicted_attack_label': 'normal', 'class_probabilities': {'dedup_dos': 0.27, 'hash_probing': 0.28, 'normal': 0.405, 'ownership_fraud': 0.045}, 'detection_mode': 'supervised'}}`
  - Metrics Delta: `{"active_files": 1, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 1, "feature_snapshots": 1, "file_versions": 1, "logical_chunks": 1, "owned_chunk_links": 1, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 3, "unique_chunks": 1}`
- `PASS` Scenario 5 - File Version Update And Delete (122117 ms)
  - Data: `{"file_id": "688fed4d-cf3d-4f30-ac50-a9b994eb63b6", "version_after_update": 2}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 1, "dedup_saved_chunks": 0, "detection_results_rows": 2, "feature_snapshots": 2, "file_versions": 3, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 4, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 6, "unique_chunks": 0}`
- `PASS` Scenario 6 - Ownership Transfer And Audit (8174 ms)
  - Data: `{"owner_count_after_transfer": 1, "audit_verified": true}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 1, "audit_events": 3, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 1, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
- `PASS` Scenario 7 - Encryption Status And UI Hooks (1 ms)
  - Data: `{"encryption_enabled": true, "ui_hooks_present": true}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
- `PASS` Scenario 8 - Status And Metrics Summary (24263 ms)
  - Data: `{"active_clients": 2, "total_buffered_events": 18, "metrics_keys": ["active_files", "audit_challenges", "audit_events", "clients_seen", "dedup_saved_chunks", "detection_results_rows", "feature_snapshots", "file_versions", "logical_chunks", "owned_chunk_links", "ownership_events", "pow_challenges", "pow_rejected", "pow_verified", "requests_seen", "unique_chunks"], "pow_challenges": 1}`
  - Metrics Delta: `{"active_files": 0, "audit_challenges": 0, "audit_events": 0, "clients_seen": 0, "dedup_saved_chunks": 0, "detection_results_rows": 0, "feature_snapshots": 0, "file_versions": 0, "logical_chunks": 0, "owned_chunk_links": 0, "ownership_events": 0, "pow_challenges": 0, "pow_rejected": 0, "pow_verified": 0, "requests_seen": 0, "unique_chunks": 0}`
