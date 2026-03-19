# SECURE DEDUPLICATION AND ADAPTIVE DEFENSE FOR CLOUD STORAGE

## Abstract
Cloud storage systems use deduplication to reduce storage and bandwidth by eliminating repeated data. However, naive deduplication allows attackers to claim duplicate ownership without possessing actual content, which can lead to unauthorized access, storage abuse, and denial-of-service behavior. This project presents a secure chunk-level deduplication system that combines proof-of-ownership (PoW), behavioral anomaly detection, adaptive policy control, ownership lifecycle management, and integrity auditing. The implemented system uses FastAPI-based APIs, hash-based chunk indexing, challenge-response verification for duplicate claims, and runtime risk-aware policy actions (`ALLOW`, `RATE_LIMIT`, `BLOCK`). Experimental validation shows that the system preserves deduplication functionality while significantly reducing estimated attacker success in duplicate-claim scenarios. The final prototype supports end-to-end demo workflows with reproducible scenario reports and runtime metrics.

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
3. Detect risky client behavior using request-pattern features.
4. Apply adaptive runtime policy (`ALLOW`, `RATE_LIMIT`, `BLOCK`).
5. Support ownership transfer, file version updates, deletion, and integrity audit checks.
6. Provide reproducible test scenarios and measurable system metrics.

### 1.4 Scope
The work focuses on API-level secure deduplication and adaptive defense mechanisms in a cloud-style storage setting. It does not claim production-scale benchmarking on very large distributed clusters.

## Chapter 2: Proposed Solution
### 2.1 Solution Overview
The proposed solution is a layered secure deduplication pipeline:
1. **Content-defined chunking + hashing** to identify duplicate data.
2. **Challenge-based PoW** for duplicate ownership verification.
3. **Behavioral detection** using engineered request features and ML models.
4. **Adaptive policy control** for request throttling/blocking under risk.
5. **Ownership and audit modules** for lifecycle correctness and integrity proof.

### 2.2 System Architecture
Main runtime layers:
1. API ingress and authentication (`X-API-Key`, `X-Client-ID`).
2. Chunking, fingerprinting, and dedup index/ref-count management.
3. Chunk storage backend with optional encryption-at-rest.
4. PoW challenge/verify flow integrated into duplicate upload path.
5. Feature extraction, anomaly scoring, policy decision engine, reputation updates.
6. Telemetry and metrics persistence for observability and reporting.

### 2.3 Core Workflow
1. Client uploads file.
2. Server chunks data and computes chunk hashes.
3. For new chunks: store and register references.
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
2. Model artifacts loaded from trained supervised/unsupervised pipelines.
3. Automated scenario suite executes key attack/defense workflows.
4. Reports generated in JSON/Markdown/CSV for reproducibility.

### 3.3 Evaluation Criteria
1. Functional correctness of upload, duplicate, PoW solve/retry flow.
2. Policy enforcement correctness (`429` for rate-limit, `403` for block).
3. Ownership transfer and audit verification correctness.
4. Runtime metric deltas per scenario.
5. Detection and adaptive-PoW effectiveness from generated artifacts.

## Chapter 4: Implementation Summary
### 4.1 Major Modules
1. **Dedup and storage**: chunking, hashing, dedup index, storage abstraction.
2. **PoW security**: duplicate challenge generation and proof verification.
3. **Adaptive detection**: feature extraction + supervised/unsupervised detector.
4. **Policy and reputation**: dynamic `ALLOW/RATE_LIMIT/BLOCK` decisioning.
5. **Ownership and audit**: transfer, challenge/verify integrity checks.
6. **UI and automation**: guided demo flow and full scenario suite.

### 4.2 Key Endpoints
1. `/upload`, `/pow/challenge`, `/pow/verify`
2. `/demo/status`, `/metrics`, `/demo/config`
3. `/files`, `/files/{file_id}`
4. `/ownership/{chunk_hash}`, `/ownership/transfer`
5. `/audit/challenge`, `/audit/verify`, `/audit/quick/{chunk_hash}`

## Chapter 5: Results and Discussion
### 5.1 Functional Validation
Recent automated scenario execution confirms complete workflow coverage with successful end-to-end status (`8/8` scenarios passed), including:
1. Baseline upload and duplicate detection.
2. PoW challenge, solve, and retry success.
3. Policy force/recovery behavior.
4. File version update/delete.
5. Ownership transfer and audit verification.
6. Encryption status checks and metrics snapshot.

### 5.2 Security-Relevant Findings
From project artifacts:
1. Adaptive PoW reduced estimated attacker success on anomaly rows from `1.0000` to `0.4735` (about `52.65%` relative reduction).
2. Supervised detector artifacts report strong classification performance, supporting practical anomaly-aware control.

### 5.3 Discussion
The results indicate that secure deduplication can remain operational while adding active abuse controls. The main tradeoff is additional verification/computation overhead for suspicious duplicate paths, which is expected in a security-first design.

## Chapter 6: Conclusion and Future Work
### 6.1 Conclusion
This project successfully demonstrates a practical secure deduplication system that addresses the central cloud dedup problem: preserving efficiency while preventing fake duplicate claims and abusive behavior. The combined PoW + anomaly-aware policy architecture provides a defendable and implementable solution for modern storage systems.

### 6.2 Future Work
1. Large-scale benchmarking with higher concurrency and larger datasets.
2. Broader real-world attack trace evaluation.
3. Extended cryptographic hardening and key-management integration.
4. Scheduled periodic auditing and long-term integrity dashboards.

## References
1. X. Peng, W. Shen, Y. Yang, X. Zhang, “Secure Deduplication and Cloud Storage Auditing With Efficient Dynamic Ownership Management and Data Dynamics,” *IEEE Transactions on Network and Service Management*, vol. 22, no. 4, 2025, doi:10.1109/TNSM.2025.3569833.
2. S. Halevi, D. Harnik, B. Pinkas, A. Shulman-Peleg, “Proofs of Ownership in Remote Storage Systems,” *ACM CCS*, 2011.
3. Project repository implementation and validation artifacts: `README.md`, `tests/run_scenario_suite.py`, `test_reports/scenario_suite_report_*.json`, `advanced_artifacts/training_metrics.json`, `pow_comparison_summary.json`.
