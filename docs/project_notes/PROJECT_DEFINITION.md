# Project Definition

## Final Title

Secure Cloud Deduplication with Secret-Assisted Encrypted Storage, Proof-of-Ownership, and Behavioural Monitoring

## Problem

Normal deduplication saves storage, but it can also let an attacker claim data they do not own if duplicate checks are not protected.

## Base Paper Anchor

Peng et al., IEEE TNSM 2025:
"Secure Deduplication and Cloud Storage Auditing With Efficient Dynamic Ownership Management and Data Dynamics"

## Final Scope

This project is now defined around one primary pipeline:

1. chunk the uploaded file,
2. derive a secret-assisted dedup token for each chunk,
3. encrypt stored chunk payloads at rest with token-bound segmented AES-GCM,
4. detect duplicate claims,
5. require proof-of-ownership before duplicate reuse,
6. keep behavioural monitoring visible through request telemetry,
7. show clear metrics for dedup savings and PoW behavior,
8. demonstrate the storage path on a reproducible LocalStack S3 environment.

## Novelty Over the Base Paper

The repo should present two concrete improvements clearly:

1. Secret-assisted fingerprint-bound encryption
   Stored chunks use a secret HMAC dedup token and a HKDF-derived segmented AES-GCM envelope.
   This reduces reliance on public content-only chunk identifiers and ties encryption to the deduplicated chunk identity.

2. Step-wise PoW duplicate verification
   Duplicate uploads do not silently succeed.
   The client receives a challenge, solves it, and retries the upload with proof.
   This makes ownership verification visible, testable, and easy to demonstrate.

Behavioural monitoring remains a supporting layer:
recent client activity and request volume stay visible in the dashboard and metrics, but they no longer dominate the UI.

Deployment stance:
the main demo environment is LocalStack S3 on a local reproducible stack, not a fragile hosted web deployment.

## What Counts As "Complete"

The project is complete when the following path works cleanly:

1. A first upload succeeds.
2. A duplicate upload returns a PoW challenge.
3. Solving the challenge and retrying succeeds.
4. Metrics show:
   - active files,
   - unique chunks,
   - dedup saved chunks,
   - PoW challenges issued,
   - PoW proofs verified or rejected,
   - monitored clients and request volume,
   - encryption enabled status and dedup token mode.
5. A deployed smoke test can run from Colab and generate a readable report.

## De-emphasized Items

These are no longer the main project story:

- large research datasets in the repo root,
- checked-in generated reports,
- overloaded demo controls,
- policy and anomaly features as the primary UI narrative.

They can remain as secondary modules, but they should not distract from the final project definition.
