# Project Definition

## Final Title

Secure Cloud Deduplication with Secret-Assisted Encrypted Storage, Proof-of-Ownership, and Behavioural Monitoring

## Problem

Classic deduplication is efficient, but deterministic content-based chunk identities can leak useful information to attackers. In particular, Wu et al. motivate the need to move beyond deterministic dedup-encryption behavior because chunk-frequency patterns can reveal sensitive structure.

## Base Paper Anchor

Wu et al., *Journal of Information Security and Applications* (2024):
"A randomized encryption deduplication method against frequency attack"

## Final Scope

This project is now defined around one primary story:

1. chunk the uploaded file,
2. derive a stronger dedup identity for each chunk,
3. encrypt stored chunk payloads at rest with token-bound segmented AES-GCM,
4. show where similar files reuse the same stored chunks,
5. require proof-of-ownership before duplicate reuse,
6. keep behavioural monitoring visible through request telemetry,
7. show clear metrics for dedup savings, PoW behavior, and throttling events.

## How the Repo Improves on the Base Paper Direction

The repo should present three concrete improvements clearly:

1. Secret-assisted fingerprint-bound encryption
   Instead of a public content-only dedup token, stored chunks use a secret HMAC dedup token and a HKDF-derived segmented AES-GCM envelope.

2. Visible duplicate-verification workflow
   Duplicate uploads do not silently succeed. The client receives a PoW challenge, solves it, and retries with proof.

3. Lightweight runtime abuse control
   Behavioural monitoring and policy actions (`ALLOW`, `RATE_LIMIT`, `BLOCK`) make suspicious duplicate behavior visible during the demo.

## What Counts As "Complete"

The project is complete when the following path works cleanly:

1. A first upload succeeds.
2. A slightly similar or duplicate upload clearly shows chunk reuse.
3. Duplicate reuse returns a PoW challenge.
4. Solving the challenge and retrying succeeds.
5. Metrics show:
   - active files,
   - unique chunks,
   - dedup saved chunks,
   - PoW challenges issued,
   - PoW proofs verified or rejected,
   - monitored clients and request volume,
   - encryption enabled status and dedup token mode.
6. The encryption comparison clearly positions the proposed scheme against a deterministic baseline.

## De-emphasized Items

These are no longer the main project story:

- auditing as a thesis-defining contribution,
- ownership/data-dynamics as the main literature anchor,
- overloaded demo controls,
- large checked-in datasets as the primary evidence.

They may remain in the repo as secondary modules, but they should not distract from the encryption-focused project definition.

## Out Of Scope For The Final Claim

Do not present these as core contributions:

- integrity auditing protocols,
- ownership transfer workflows,
- file lifecycle management as a novelty claim,
- a brand-new cryptographic primitive.

The final claim is narrower and stronger: a Wu-et-al-inspired secure deduplication prototype that improves deterministic dedup-aware encryption while making chunk reuse, PoW, and throttling easy to observe.
