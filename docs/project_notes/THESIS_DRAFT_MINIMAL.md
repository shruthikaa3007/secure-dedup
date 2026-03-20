# SECURE CLOUD DEDUPLICATION WITH SECRET-ASSISTED ENCRYPTION, PROOF-OF-OWNERSHIP, AND BEHAVIOURAL MONITORING

## Abstract
Cloud storage systems use deduplication to reduce storage and bandwidth by eliminating repeated data. However, naive deduplication allows attackers to claim duplicate ownership without possessing actual content, which can lead to unauthorized access, storage abuse, and denial-of-service behavior. This project presents a secure chunk-level deduplication system that combines secret-assisted dedup tokens, fingerprint-bound segmented encryption, proof-of-ownership (PoW), behavioral anomaly detection, adaptive policy control, ownership lifecycle management, and integrity auditing. The implemented system uses FastAPI-based APIs, HMAC- or hash-based chunk indexing, HKDF-derived AES-GCM chunk encryption, challenge-response verification for duplicate claims, and runtime risk-aware policy actions (`ALLOW`, `RATE_LIMIT`, `BLOCK`). Experimental validation compares a baseline public-hash encryption path against the proposed secret-assisted scheme while also measuring adaptive PoW effectiveness. The final prototype supports end-to-end demo workflows with reproducible scenario reports and runtime metrics.

## Chapter 1: Introduction
### 1.1 Background
Deduplication is essential for efficient cloud storage because many users store similar or identical data. Standard deduplication works by splitting a file into chunks, hashing each chunk, and storing only unique chunks. Although efficient, this approach introduces security risks when duplicate checks are exposed to untrusted clients.

### 1.2 Problem Statement
Existing deduplication deployments face a core conflict:
1. They need high storage efficiency through cross-user deduplication.
2. They must prevent malicious users from falsely claiming ownership of existing chunks.
3. They must handle repeated suspicious behavior (hash probing, abuse bursts, dedup DoS attempts) in real time.

A purely hash-match-based deduplication pipeline is not sufficient for secure multi-tenant cloud environments. Therefore, the problem is to design and implement a system that preserves deduplication gains while adding practical security controls for ownership verification, abuse resistance, and auditability.

### 1.3 Objectives
1. Build secure chunk-level deduplication with duplicate-claim verification.
2. Enforce proof-of-ownership before accepting duplicate references.
3. Compare a baseline content-hash dedup-encryption path against a proposed secret-assisted encryption path.
4. Detect risky client behavior using request-pattern features.
5. Apply adaptive runtime policy (`ALLOW`, `RATE_LIMIT`, `BLOCK`).
6. Support ownership transfer, file version updates, deletion, and integrity audit checks.
7. Provide reproducible test scenarios and measurable system metrics.

### 1.4 Scope
The work focuses on API-level secure deduplication and adaptive defense mechanisms in a cloud-style storage setting. It does not claim production-scale benchmarking on very large distributed clusters.

## Chapter 2: Proposed Solution
### 2.1 Solution Overview
The proposed solution is a layered secure deduplication pipeline:
1. **Content-defined chunking + dedup tokening** to identify duplicate data.
2. **Secret-assisted fingerprint-bound encryption** using HMAC-derived dedup tokens, HKDF-derived chunk keys, and segmented AES-GCM.
3. **Challenge-based PoW** for duplicate ownership verification.
4. **Behavioral detection** using engineered request features and ML models.
5. **Adaptive policy control** for request throttling/blocking under risk.
6. **Ownership and audit modules** for lifecycle correctness and integrity proof.

### 2.2 System Architecture
Main runtime layers:
1. API ingress and authentication (`X-API-Key`, `X-Client-ID`).
2. Chunking, fingerprinting, and dedup index/ref-count management.
3. Secret-assisted dedup token generation and token-bound chunk encryption.
4. Chunk storage backend with encryption-at-rest enabled by default for the demo path.
5. PoW challenge/verify flow integrated into duplicate upload path.
6. Feature extraction, anomaly scoring, policy decision engine, reputation updates.
7. Telemetry and metrics persistence for observability and reporting.

### 2.3 Core Workflow
1. Client uploads file.
2. Server chunks data and computes dedup tokens.
3. For new chunks: derive token-bound keys, encrypt chunks, store and register references.
4. For duplicate chunks: require PoW proof; reject if missing/invalid.
5. Extract behavior features and compute risk.
6. Decide policy (`ALLOW`, `RATE_LIMIT`, `BLOCK`) for subsequent requests.
7. Persist telemetry, ownership events, and metrics.

## Chapter 3: Methodology
### 3.1 Development Method
A prototype-driven, modular implementation approach was used:
1. Implement secure dedup core and PoW verification.
2. Add behavior feature extraction and detector integration.
3. Add policy/reputation control loop.
4. Add ownership transfer, file versioning, and audit protocol.
5. Build UI-guided and script-based scenario automation for validation.

### 3.2 Experimental Setup
1. API service implemented in Python/FastAPI.
2. Encryption comparison script evaluates baseline and proposed dedup-aware schemes on reproducible chunk datasets.
3. Model artifacts loaded from trained supervised/unsupervised pipelines.
4. Automated scenario suite executes key attack/defense workflows.
5. Reports generated in JSON/Markdown/CSV for reproducibility.

### 3.3 Evaluation Criteria
1. Functional correctness of upload, duplicate, PoW solve/retry flow.
2. Encryption-scheme comparison: dedup preservation, token-generation cost, encryption/decryption cost, and storage overhead.
3. Policy enforcement correctness (`429` for rate-limit, `403` for block).
4. Ownership transfer and audit verification correctness.
5. Runtime metric deltas per scenario.
6. Detection and adaptive-PoW effectiveness from generated artifacts.

## Chapter 4: Implementation Summary
### 4.1 Major Modules
1. **Dedup and storage**: chunking, hashing, dedup index, storage abstraction.
2. **Encryption scheme**: secret-assisted dedup token generation, HKDF key derivation, segmented AES-GCM chunk envelopes.
3. **PoW security**: duplicate challenge generation and proof verification.
4. **Adaptive detection**: feature extraction + supervised/unsupervised detector.
5. **Policy and reputation**: dynamic `ALLOW/RATE_LIMIT/BLOCK` decisioning.
6. **Ownership and audit**: transfer, challenge/verify integrity checks.
7. **UI and automation**: guided demo flow and full scenario suite.

### 4.2 Key Endpoints
1. `/upload`, `/pow/challenge`, `/pow/verify`
2. `/demo/status`, `/metrics`, `/demo/config`
3. `/files`, `/files/{file_id}`
4. `/ownership/{chunk_hash}`, `/ownership/transfer`
5. `/audit/challenge`, `/audit/verify`, `/audit/quick/{chunk_hash}`

## Chapter 5: Results and Discussion
### 5.1 Functional Validation
Recent automated validation confirms both workflow correctness and demo readiness:
1. Smoke validation passed with `7/7` checks.
2. Scenario execution passed with `8/8` end-to-end workflows.
3. Covered flows include baseline upload and duplicate detection.
4. Covered flows include PoW challenge, solve, and retry success.
5. Covered flows include policy force/recovery behavior.
6. Covered flows include file version update/delete.
7. Covered flows include ownership transfer and audit verification.
8. Covered flows include encryption status checks and metrics snapshot.
9. Covered flows include secret-assisted dedup token mode exposure in the demo configuration and metrics pipeline.

### 5.2 Security-Relevant Findings
From project artifacts:
1. Adaptive PoW reduced estimated attacker success on anomaly rows from `1.0000` to `0.4735` (about `52.65%` relative reduction).
2. The encryption benchmark preserved deduplication efficiency exactly in both schemes: `70.00%` logical-chunk savings, `210` saved chunks, and `38` bytes of average storage overhead per encrypted chunk.
3. The proposed secret-assisted scheme increased dedup-token generation from `0.003880 ms` to `0.007529 ms` per chunk, while encryption and decryption time remained effectively unchanged (`0.082679 ms` vs `0.082339 ms` encrypt, `0.090448 ms` vs `0.090789 ms` decrypt).
4. Supervised detector artifacts report strong classification performance, supporting practical anomaly-aware control.

### 5.3 Discussion
The results indicate that secure deduplication can remain operational while adding active abuse controls and stronger dedup-token secrecy. The proposed secret-assisted construction preserved dedup savings and storage overhead exactly in this benchmark, and its measurable cost was concentrated almost entirely in dedup-token generation rather than in bulk encryption or decryption. This is a favorable tradeoff for a security-first design because the additional cost stays at the fingerprinting boundary while the stored-chunk cryptographic path remains effectively unchanged.

## Chapter 6: Conclusion and Future Work
### 6.1 Conclusion
This project successfully demonstrates a practical secure deduplication system that addresses the central cloud dedup problem: preserving efficiency while preventing fake duplicate claims and abusive behavior. The combined secret-assisted encryption + PoW + anomaly-aware policy architecture provides a defendable and implementable solution for modern storage systems.

### 6.2 Future Work
1. Large-scale benchmarking with higher concurrency and larger datasets.
2. Broader real-world attack trace evaluation.
3. Extended cryptographic hardening toward multi-key-server or OPRF-assisted deployments.
4. Scheduled periodic auditing and long-term integrity dashboards.

## References
1. X. Peng, W. Shen, Y. Yang, X. Zhang, “Secure Deduplication and Cloud Storage Auditing With Efficient Dynamic Ownership Management and Data Dynamics,” *IEEE Transactions on Network and Service Management*, vol. 22, no. 4, 2025, doi:10.1109/TNSM.2025.3569833.
2. S. Halevi, D. Harnik, B. Pinkas, A. Shulman-Peleg, “Proofs of Ownership in Remote Storage Systems,” *ACM CCS*, 2011.
3. S. Lee, C. Seo, “Secure and Efficient Deduplication for Cloud Storage with Dynamic Ownership Management,” *Applied Sciences*, vol. 13, no. 24, 2023, doi:10.3390/app132413270.
4. J. Wu et al., “A randomized encryption deduplication method against frequency attack,” *Journal of Information Security and Applications*, vol. 83, 2024, doi:10.1016/j.jisa.2024.103774.
5. X. Tang, C. Guo, K.-K. R. Choo, X. Jiang, Y. Liu, “A secure and lightweight cloud data deduplication scheme with efficient access control and key management,” *Computer Communications*, vol. 222, 2024, pp. 209-219, doi:10.1016/j.comcom.2024.05.003.
6. C. Gan et al., “Coupling Secret Sharing with Decentralized Server-Aided Encryption in Encrypted Deduplication,” *Applied Sciences*, vol. 15, no. 3, 2025, doi:10.3390/app15031245.
7. Project repository implementation and validation artifacts: `README.md`, `compare_dedup_encryption_schemes.py`, `tests/run_scenario_suite.py`, `docs/project_notes/encryption_scheme_comparison.md`, `advanced_artifacts/training_metrics.json`, `pow_comparison_summary.json`.
