# PPT Test Cases Summary

This document is a slide-ready summary of the project test coverage.

Use it for:

- validation slides,
- viva preparation,
- and explaining why the prototype is not only implemented but also tested at multiple levels.

## 1. Validation Strategy Slide

Suggested slide title:

`Validation Strategy`

Suggested bullet points:

- Unit tests for encryption correctness and fingerprint behaviour
- Security tests for frequency-attack resistance
- Behavioural attack tests for hash probing, dedup DoS, and ownership fraud
- Smoke tests for core API flow
- Scenario suite for end-to-end behaviour and metrics

Suggested summary line:

`The prototype was validated at cryptographic, behavioural, API, and end-to-end levels.`

## 2. Encryption Unit Tests

Suggested slide title:

`Encryption Unit Tests`

Suite:

- [test_encryption.py](/e:/secure-dedup/tests/test_encryption.py)

Coverage:

- `5/5 passed`

Test cases:

1. `test_encrypt_decrypt_roundtrip_with_bound_context`
   - Validates successful encryption and decryption when the correct chunk context is used
   - Confirms the stored payload is not plaintext and uses the encryption envelope

2. `test_wrong_context_fails_decryption`
   - Verifies that ciphertext cannot be decrypted if the wrong chunk context is supplied
   - Demonstrates context binding of the encryption scheme

3. `test_encryption_disabled_returns_plain_payload`
   - Confirms the fallback path behaves correctly when encryption is disabled
   - Useful to show the system’s controlled non-encrypted mode for debugging

4. `test_secret_hmac_hash_differs_from_public_sha256`
   - Confirms the proposed secret-assisted token differs from the public SHA-256 token
   - Supports the claim that the dedup identity is no longer publicly reproducible

5. `test_encryption_status_reports_expected_scheme_metadata`
   - Verifies reported metadata such as scheme name, HKDF binding, and segment size
   - Helps validate system transparency and configuration reporting

Suggested PPT wording:

`These unit tests verify that encryption is context-bound, decryption fails under the wrong context, and the proposed secret-assisted fingerprint differs from the public baseline.`

## 3. Frequency-Attack Resistance Tests

Suggested slide title:

`Frequency-Attack Resistance Tests`

Suite:

- [test_frequency_attack_resistance.py](/e:/secure-dedup/tests/test_frequency_attack_resistance.py)

Coverage:

- `15/15 passed`

Saved report:

- [frequency_attack_pytest_20260322_181202.md](/e:/secure-dedup/test_reports/frequency_attack_pytest_20260322_181202.md)

What this suite proves:

- public `SHA-256` dedup tokens are reproducible by an adversary,
- `HMAC-SHA256` dedup tokens are not reproducible without the server secret,
- cross-user deduplication is preserved,
- frequency analysis and confirmation attacks are blocked at the token level,
- HKDF-derived encryption keys remain bound to the secret-assisted token.

Key test groups:

1. Token non-reproducibility
   - `test_sha256_token_is_reproducible_by_adversary`
   - `test_hmac_token_not_reproducible_with_sha256`
   - `test_hmac_token_not_reproducible_with_wrong_key`
   - `test_hmac_token_reproducible_with_correct_key`

2. Deduplication preserved
   - `test_ten_users_same_chunk_same_hmac_token`
   - `test_dedup_savings_identical_across_schemes`

3. Frequency analysis resistance
   - `test_sha256_frequency_leaks_to_adversary`
   - `test_hmac_frequency_opaque_to_adversary`
   - `test_hmac_adversary_recovers_zero_information`

4. Performance sanity
   - `test_hmac_overhead_within_reasonable_bound`
   - `test_absolute_hmac_time_is_negligible`

5. Confirmation attack resistance
   - `test_sha256_enables_confirmation_attack`
   - `test_hmac_blocks_confirmation_attack`

6. HKDF key binding
   - `test_different_chunks_produce_different_keys`
   - `test_same_chunk_produces_stable_32_byte_key`

Suggested PPT wording:

`This suite demonstrates the central security claim of the project: the proposed HMAC-based chunk token preserves deduplication while blocking public token reproducibility, confirmation attacks, and frequency leakage.`

## 4. Behavioural Attack Detection Tests

Suggested slide title:

`Behavioural Attack Detection Tests`

Suite:

- [test_attack_detection_demo.py](/e:/secure-dedup/tests/test_attack_detection_demo.py)

Coverage:

- `11/11 passed`

Saved report:

- [attack_detection_demo_pytest_20260322_181200.md](/e:/secure-dedup/test_reports/attack_detection_demo_pytest_20260322_181200.md)

What this suite proves:

- hash probing is detected and rate limited,
- dedup DoS is detected and blocked,
- ownership fraud through repeated PoW attempts is detected,
- legitimate behaviour is not misclassified,
- a static REFA-style threshold can miss a careful attacker while the behavioural model still flags it.

Key test cases:

1. Hash probing
   - `test_hash_probing_detected`
   - Expected action: `RATE_LIMIT`

2. Benign normal user
   - `test_normal_client_not_flagged`
   - Expected action: `ALLOW`

3. Adaptive PoW difficulty
   - `test_hash_probing_adaptive_pow_increases_difficulty`
   - Expected result: attacker receives harder challenge than a normal client

4. Deduplication denial of service
   - `test_dedup_dos_detected`
   - Expected action: `BLOCK`

5. High duplicate ratio but benign backup behaviour
   - `test_high_duplicate_ratio_alone_is_not_dos`
   - Expected result: not misclassified as attack

6. Ownership fraud
   - `test_ownership_fraud_detected`
   - Expected action: `RATE_LIMIT` or `BLOCK`

7. Legitimate PoW retries
   - `test_legitimate_pow_retries_are_allowed`
   - Expected result: not misclassified

8. Pipeline integration
   - `test_full_pipeline_hash_probing`
   - `test_full_pipeline_normal_user`

9. REFA gap demonstrations
   - `test_gap1_static_pow_fails_against_determined_attacker`
   - `test_gap2_refa_has_no_behaviour_detection`

Best viva line from this suite:

`REFA would: ALLOW | Our framework would: RATE_LIMIT.`

Suggested PPT wording:

`These tests show that the project does not only secure the dedup token; it also identifies suspicious behaviour patterns such as hash probing, dedup DoS, and repeated failed proof-of-ownership attempts.`

## 5. Smoke Tests

Suggested slide title:

`API Smoke Tests`

Suite:

- [run_smoke_tests.py](/e:/secure-dedup/tests/run_smoke_tests.py)

Coverage:

- `7/7 passed`

Saved report:

- [smoke_test_report_20260322_122459.md](/e:/secure-dedup/test_reports/smoke_test_report_20260322_122459.md)

Covered cases:

1. Health endpoint
2. Config endpoint
3. Upload success
4. Duplicate requires PoW
5. PoW solve and retry
6. Status and metrics
7. UI asset functional hooks

What this slide should say:

`Smoke tests confirm that the core live demo path works: health, configuration, upload, duplicate detection, PoW, retry, and metrics reporting.`

## 6. Scenario Suite

Suggested slide title:

`End-to-End Scenario Suite`

Suite:

- [run_scenario_suite.py](/e:/secure-dedup/tests/run_scenario_suite.py)

Coverage:

- `8/8 passed`

Saved report:

- [scenario_suite_report_20260322_122513.md](/e:/secure-dedup/test_reports/scenario_suite_report_20260322_122513.md)

Covered scenarios:

1. Baseline upload
2. Duplicate requires PoW
3. PoW solve and retry
4. Policy enforcement and recovery
5. File version update and delete
6. Ownership transfer and audit
7. Encryption status and UI hooks
8. Status and metrics summary

Suggested note:

`Although the thesis focus is now centered on Wu et al.-style dedup security, the scenario suite still shows that the wider application behaves consistently across upload, policy, metrics, and lifecycle flows.`

## 7. One Overall Results Slide

Suggested slide title:

`Overall Test Results`

Suggested table:

| Suite | Focus | Result |
|---|---|---|
| Encryption unit tests | correctness of bound encryption | `5/5 passed` |
| Frequency-attack tests | token secrecy vs baseline | `15/15 passed` |
| Behavioural attack tests | hash probing, DoS, ownership fraud | `11/11 passed` |
| Smoke tests | core API path | `7/7 passed` |
| Scenario suite | end-to-end workflow | `8/8 passed` |

Suggested conclusion line:

`Across all major validation layers, the current project evidence shows consistent success in cryptographic correctness, attack resistance, live API behaviour, and end-to-end workflow execution.`

## 8. Best Slides If You Need Only 3

If you have very limited PPT space, use these three:

1. `Frequency-Attack Resistance Tests`
   - because this supports the main thesis claim

2. `Behavioural Attack Detection Tests`
   - because this shows the project goes beyond crypto-only protection

3. `Overall Test Results`
   - because it gives a clear summary of the validation breadth
