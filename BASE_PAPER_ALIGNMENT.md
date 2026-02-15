# Base Paper Selection and Project Alignment

## Selected base paper
**X. Peng, W. Shen, Y. Yang, X. Zhang (2025)**
**"Secure Deduplication and Cloud Storage Auditing With Efficient Dynamic Ownership Management and Data Dynamics"**
IEEE Transactions on Network and Service Management (TNSM), Vol. 22, No. 4.
DOI: `10.1109/TNSM.2025.3569833`

## Why this is the closest fit
1. It is the only candidate that explicitly combines:
   - secure deduplication,
   - cloud storage auditing,
   - dynamic ownership management,
   - data dynamics.
2. Your project already centers on deduplication + ownership verification (PoW) and now adds adaptive control.
3. This gives a strong, recent, high-quality baseline for thesis defense.

## What your project already matches
1. **Secure dedup workflow** (chunking, fingerprint index, duplicate handling).
2. **Ownership verification path** (`/pow/challenge`, `/pow/verify`, duplicate proof checks).
3. **Dynamic control layer** beyond baseline via anomaly-driven and reputation-aware adaptive PoW.

## What to add to align more strongly with the paper
1. **Auditing protocol module**
   - Add challenge-response integrity auditing over stored chunks.
   - Proposed endpoints: `POST /audit/challenge`, `POST /audit/verify`.
2. **Explicit ownership management model**
   - Persist per-chunk owner set + ownership events (grant/revoke/transfer).
3. **Data dynamics support**
   - Add update/delete/version operations over file recipes, not only upload.
4. **Periodic audit scheduler**
   - Background task to audit random chunk subsets and record integrity evidence.

## How to position your novelty vs the base paper
1. Base paper focus: cryptographic dedup + auditing with ownership/data dynamics.
2. Your extension: **closed-loop behavioral defense** (risk + reputation -> adaptive PoW difficulty).
3. Defense line: you implement the secure dedup core and extend it with runtime adaptive security controls.

## Immediate implementation order
1. Add ownership event store and owner-set model.
2. Add file recipe versioning with update/delete support.
3. Add audit challenge/verify API and audit logs.
4. Evaluate static PoW vs adaptive PoW on the same dedup/audit pipeline.

## Additional papers screened (from your latest set)

| File | Identified paper | Fit to your project | Use in thesis |
|---|---|---|---|
| `1-s2.0-S1319157820305140-main.pdf` | **A Review on Secure Data Deduplication: Cloud Storage Security Issue** (JKSUCI, 2020), DOI `10.1016/j.jksuci.2020.10.021` | Background survey only; not a system blueprint | Related work citation, not base paper |
| `1-s2.0-S2214212623001084-main.pdf` | **Decentralized and secure deduplication with dynamic ownership in MLaaS** (JISA, 2023), DOI `10.1016/j.jisa.2023.103524` | Strong on dedup + dynamic ownership, but ML model/storage setting differs from your architecture | Good secondary technical reference |
| `2208.09030v3.pdf` | **A Secure and Efficient Data Deduplication Scheme with Dynamic Ownership Management in Cloud Computing** (arXiv preprint, 2022) | Conceptually close, but weaker as a defense anchor than peer-reviewed IEEE/Elsevier journal papers | Supporting citation only |
| `3725340.pdf` | **Privacy and Accuracy-Aware AI/ML Model Deduplication** (PACMMOD/SIGMOD, 2025), DOI `10.1145/3725340` | Focuses on model-level dedup + differential privacy, not cloud file/chunk dedup security path | Out of core scope (optional comparison) |
| `applsci-13-13270.pdf` | **Secure and Efficient Deduplication for Cloud Storage with Dynamic Ownership Management** (Applied Sciences, 2023), DOI `10.3390/app132413270` | Very close to your core flow (secure dedup + dynamic ownership) | Strong secondary baseline for implementation details |

## Updated recommendation after reviewing these five
1. Keep **TNSM 2025 (`10.1109/TNSM.2025.3569833`)** as primary base paper.
2. Use **Applied Sciences 2023 (`10.3390/app132413270`)** as implementation-oriented companion paper.
3. Use **JISA 2023 (`10.1016/j.jisa.2023.103524`)** to justify dynamic ownership and architecture alternatives.
