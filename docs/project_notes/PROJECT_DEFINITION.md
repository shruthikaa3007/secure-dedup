# Project Definition

## Final Title

Secure Encrypted Deduplication with Proof-of-Ownership for Duplicate Claims

## Problem

Normal deduplication saves storage, but it can also let an attacker claim data they do not own if duplicate checks are not protected.

## Base Paper Anchor

Peng et al., IEEE TNSM 2025:
"Secure Deduplication and Cloud Storage Auditing With Efficient Dynamic Ownership Management and Data Dynamics"

## Final Scope

This project is now defined around one primary pipeline:

1. chunk the uploaded file,
2. hash each chunk for deduplication,
3. encrypt stored chunk payloads at rest,
4. detect duplicate claims,
5. require proof-of-ownership before duplicate reuse,
6. keep behavioural monitoring visible through request telemetry,
7. show clear metrics for dedup savings and PoW behavior.

## Novelty Over the Base Paper

The repo should present two concrete improvements clearly:

1. Hash-bound segmented encryption
   Stored chunks use a segmented AES-GCM envelope derived from a master key and the chunk hash.
   This ties encryption and integrity to the deduplicated chunk identity.

2. Step-wise PoW duplicate verification
   Duplicate uploads do not silently succeed.
   The client receives a challenge, solves it, and retries the upload with proof.
   This makes ownership verification visible, testable, and easy to demonstrate.

Behavioural monitoring remains a supporting layer:
recent client activity and request volume stay visible in the dashboard and metrics, but they no longer dominate the UI.

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
   - encryption enabled status.
5. A deployed smoke test can run from Colab and generate a readable report.

## De-emphasized Items

These are no longer the main project story:

- large research datasets in the repo root,
- checked-in generated reports,
- overloaded demo controls,
- policy and anomaly features as the primary UI narrative.

They can remain as secondary modules, but they should not distract from the final project definition.
