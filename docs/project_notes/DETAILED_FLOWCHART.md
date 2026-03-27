# Detailed Flowchart

This document shows the actual runtime flow of the current prototype:

- file upload and chunking,
- dedup fingerprint generation,
- fingerprint-bound encryption,
- storage and dedup index updates,
- duplicate handling with PoW,
- behavioural detection and policy response,
- and the LocalStack / Redis backing services.

These diagrams are based on the current code in:

- [app.py](/e:/secure-dedup/app.py)
- [chunking.py](/e:/secure-dedup/chunking.py)
- [hashing.py](/e:/secure-dedup/hashing.py)
- [encryption.py](/e:/secure-dedup/encryption.py)
- [storage.py](/e:/secure-dedup/storage.py)
- [pow_session.py](/e:/secure-dedup/pow_session.py)
- [features.py](/e:/secure-dedup/features.py)
- [detector.py](/e:/secure-dedup/detector.py)
- [policy_engine.py](/e:/secure-dedup/policy_engine.py)
- [dedup_index.py](/e:/secure-dedup/dedup_index.py)

## 1. End-to-End Upload Flow

```mermaid
flowchart TD
    A[Client uploads file to POST /upload] --> B[Resolve client id and enforce any active pre-request policy]
    B --> C[Log upload_start event]
    C --> D[Read uploaded bytes]
    D --> E[Save original file copy under uploads/]
    E --> F[Chunk file]
    F --> F1{pyfastcdc available?}
    F1 -->|Yes| F2[Use FastCDC content-defined chunking]
    F1 -->|No| F3[Fallback to fixed-size chunking]
    F2 --> G[For each chunk compute dedup fingerprint]
    F3 --> G
    G --> G1{DEDUP_FINGERPRINT_MODE}
    G1 -->|sha256| G2[chunk_hash = SHA-256(chunk)]
    G1 -->|secret_hmac| G3[chunk_hash = HMAC-SHA256(secret_key, chunk)]
    G2 --> H[Build recipe list of chunk hashes]
    G3 --> H
    H --> I[Check existing ref counts in dedup index]
    I --> J[Compute adaptive inputs from reputation plus history]
    J --> K[Phase 1: verify duplicate chunks before mutating storage]
    K --> K1{Chunk already exists?}
    K1 -->|No| L[Mark as new chunk]
    K1 -->|Yes| M{Valid PoW proof supplied or already verified?}
    M -->|No| N[Create or reuse PoW challenge for this client and chunk]
    N --> O[Return HTTP 409 with required_challenges plus chunk_summary]
    M -->|Yes| P[Mark duplicate chunk as verified for reuse]
    L --> Q[Phase 2: mutate storage and index]
    P --> Q
    Q --> Q1[Log hash_query for each chunk]
    Q1 --> Q2{Chunk exists in dedup index?}
    Q2 -->|No| R[Encrypt and store new chunk]
    R --> R1[Increment ref count]
    R1 --> R2[Add owner]
    R2 --> R3[Log upload_chunk]
    Q2 -->|Yes| S[Require verified duplicate]
    S --> S1[Increment ref count]
    S1 --> S2[Add owner]
    S2 --> S3[Log pow success]
    S3 --> S4[Record PoW success]
    R3 --> T[Create or update file recipe record]
    S4 --> T
    T --> U[Extract behavioural features from request log]
    U --> V[Run anomaly detection model]
    V --> W[Map risk score to policy action]
    W --> X{Policy action}
    X -->|ALLOW| Y[Record benign activity]
    X -->|RATE_LIMIT or BLOCK| Z[Register policy cooldown and update reputation]
    Y --> AA[Label attack type for telemetry]
    Z --> AA
    AA --> AB[Save features plus label plus policy action]
    AB --> AC[Build final chunk_summary and chunk_details]
    AC --> AD[Return HTTP 200 with file recipe, chunk details, anomaly result, policy decision, and reputation]
```

## 2. Fingerprint and Encryption Flow

```mermaid
flowchart TD
    A[Chunk bytes] --> B[Compute dedup fingerprint]
    B --> B1{Fingerprint mode}
    B1 -->|Baseline| C[SHA-256 chunk]
    B1 -->|Proposed| D[HMAC-SHA256 server_secret plus chunk]
    C --> E[chunk_hash / dedup token]
    D --> E
    E --> F[encrypt_chunk data, context = chunk_hash]
    F --> G[Load master AES key from env or demo default]
    G --> H{Encryption enabled?}
    H -->|No| I[Return plaintext chunk]
    H -->|Yes| J[Derive content key from master key]
    J --> J1[HKDF-like derivation using SHA-256 and HMAC]
    J1 --> J2[salt = SHA-256 secure-dedup/salt plus context]
    J2 --> J3[PRK = HMAC salt over master key]
    J3 --> J4[Expand output blocks with info = secure-dedup/chunk-key/v1 plus SHA-256 context]
    J4 --> K[Derived per-chunk AES key]
    K --> L[Split chunk into segments]
    L --> L1{Segment size}
    L1 -->|Default| L2[4096-byte segments]
    L2 --> M[For each segment]
    M --> N[Generate fresh 12-byte nonce]
    N --> O[Build AAD = dedup_token plus context plus segment index]
    O --> P[AES-GCM encrypt segment with derived key]
    P --> Q[Produce ciphertext plus 16-byte tag]
    Q --> R[Append length plus nonce plus tag plus ciphertext]
    R --> S[Prefix whole payload with SDENC3 magic header]
    S --> T[Encrypted payload stored using chunk_hash as storage key]
```

## 3. Storage and Backing Services

```mermaid
flowchart TD
    A[upload_chunk chunk_hash, chunk_bytes] --> B[encrypt_chunk using context = chunk_hash]
    B --> C{Storage backend}
    C -->|localstack or s3| D[Put object into bucket using key = chunk_hash]
    C -->|minio| E[Put object into MinIO bucket]
    C -->|fallback| F[Write encrypted payload to local_chunks/]
    D --> G[Chunk payload stored encrypted]
    E --> G
    F --> G

    H[dedup_index] --> H1{Redis reachable?}
    H1 -->|Yes| H2[Store ref_count in Redis hash keyed by chunk_hash]
    H1 -->|No| H3[Store ref_count in in-memory dictionary]

    I[pow_session] --> I1{Redis reachable?}
    I1 -->|Yes| I2[Store active challenge, verified markers, and used markers in Redis]
    I1 -->|No| I3[Store them in in-memory fallback structures]

    J[policy_engine and reputation] --> J1{Redis reachable?}
    J1 -->|Yes| J2[Store active cooldown state in Redis]
    J1 -->|No| J3[Store active cooldown state in memory]
```

## 4. Duplicate Chunk and PoW Flow

```mermaid
flowchart TD
    A[Upload contains chunk_hash already present in dedup index] --> B[Check supplied pow_proofs_json]
    B --> C{Proof for this chunk provided?}
    C -->|Yes| D[Load stored chunk]
    D --> E[verify_challenge client_id, challenge_id, chunk_hash, stored_chunk, client_proof]
    E --> E1{Challenge valid?}
    E1 -->|Yes| F[Mark chunk as verified for this client and chunk]
    E1 -->|No| G[Verification fails]
    C -->|No| G
    G --> H[Try consume_verified for already verified duplicate marker]
    H --> H1{Verified marker exists?}
    H1 -->|Yes| F
    H1 -->|No| I[get_or_create_challenge]
    I --> J[select_challenge_profile from risk score, reputation, and duplicate context]
    J --> K[generate challenge with nonce, offset, length, and adaptive window]
    K --> L[Store active challenge in Redis or memory]
    L --> M[Return HTTP 409]
    M --> N[Client receives required_challenges plus chunk_summary plus chunk_details]
    N --> O[Client solves proof over requested byte slice]
    O --> P[Retry POST /upload with pow_proofs_json]
    P --> Q[verify_challenge succeeds]
    Q --> R[Delete active challenge, mark used, set verified marker]
    R --> S[Duplicate chunk can now be reused]
```

## 5. Behavioural Detection and Policy Flow

```mermaid
flowchart TD
    A[Request logs for one client] --> B[extract_features]
    B --> C[Compute frequency features]
    C --> C1[requests_per_minute]
    C --> C2[requests_per_5_min]
    C --> C3[requests_per_hour]
    B --> D[Compute dedup and PoW features]
    D --> D1[unique_hash_count]
    D --> D2[duplicate_ratio]
    D --> D3[pow_attempt_rate]
    B --> E[Compute query and temporal features]
    E --> E1[hash_diversity]
    E --> E2[upload_to_query_ratio]
    E --> E3[inter_request_time_variance]
    E --> E4[burst_score]
    E --> E5[session_duration]
    B --> F[Compute cross-user feature]
    F --> F1[cross_user_hash_overlap]
    C1 --> G[detect_anomaly]
    C2 --> G
    C3 --> G
    D1 --> G
    D2 --> G
    D3 --> G
    E1 --> G
    E2 --> G
    E3 --> G
    E4 --> G
    E5 --> G
    F1 --> G
    G --> H{Supervised artifacts loaded?}
    H -->|Yes| I[Supervised classifier predicts normal, hash_probing, dedup_dos, ownership_fraud]
    H -->|No| J[Fallback to unsupervised detectors]
    I --> K[Produce risk_score plus predicted_attack_label]
    J --> K
    K --> L[policy_engine decide_response]
    L --> L1{risk score >= block threshold?}
    L1 -->|Yes| M[BLOCK, HTTP 403]
    L1 -->|No| L2{risk score >= rate-limit threshold?}
    L2 -->|Yes| N[RATE_LIMIT, HTTP 429]
    L2 -->|No| O[ALLOW, HTTP 200]
    M --> P[Register cooldown state]
    N --> P
    O --> Q[Record benign activity]
    P --> R[Future requests hit pre-request enforcement]
```

## 6. One-Chunk Walkthrough

This is the shortest way to explain one chunk in the viva:

1. The uploaded file is split into chunks.
2. Each chunk gets a dedup fingerprint.
3. In the proposed design, that fingerprint is `HMAC-SHA256(secret, chunk)` instead of plain `SHA-256(chunk)`.
4. That fingerprint becomes the `chunk_hash` and also the encryption context.
5. The encryption layer derives a per-chunk AES key from the master key plus the fingerprint context using `HKDF-SHA256`.
6. The chunk is then encrypted segment by segment using `AES-GCM`.
7. The encrypted payload is stored in LocalStack S3 using the `chunk_hash` as the object key.
8. Redis stores the dedup reference count and the PoW/policy state.
9. If another user uploads the same chunk, the dedup index sees that the `chunk_hash` already exists.
10. Before allowing reuse, the server issues a PoW challenge tied to the stored chunk content.
11. After successful verification, the reference count is incremented and the duplicate chunk is reused instead of stored again.

## 7. Key Talking Points

- `SHA-256` baseline:
  the dedup token is public and reproducible.
- `secret_hmac` proposal:
  the dedup token stays stable for the system but is not reproducible to outsiders without the server secret.
- Encryption is not separate from dedup:
  the chunk fingerprint is used as the context for deriving the per-chunk AES key.
- Duplicate detection is not enough by itself:
  duplicate reuse is gated by PoW.
- Runtime misuse is still possible even with stronger tokens:
  that is why the behavioural layer watches for `hash_probing`, `dedup_dos`, and `ownership_fraud`.

## 8. Best Order To Present This

1. Show the end-to-end upload flow.
2. Zoom into the fingerprint and encryption flow.
3. Show the duplicate plus PoW flow.
4. Show the behavioural detection flow.
5. End with the one-chunk walkthrough.
