# Security Model Note

## Scope

This note makes the current security claim precise enough for paper writing and reviewer discussion.

The prototype has three relevant adversary classes:

1. `Outsider`: sees public API responses, S3 object names, and leaked client-side metadata, but does not know the server dedup secret or any user's `K_U`.
2. `Unauthorized client`: can make upload/download requests, but does not know the target user's password-derived `K_U` and does not own a valid `ownership_token_t`.
3. `Single key server`: holds the epoch OPRF secret and the dedup locator secret. This server is trusted for functionality and is not hidden from duplicate structure in the current design.

The current implementation protects against classes `1` and `2`. It does not hide duplicate structure from class `3`.

## OPRF Core

The active backend in `src/crypto/oprf_backends.py` now implements a real blind-evaluate-unblind flow over `ristretto255`:

- `H_1(m)`: hash-to-group using `crypto_core_ristretto255_from_hash(SHA512(...))`
- client blind: `a = H_1(m) + g^r`
- server evaluate: returns `(g^k, a^k)`
- client unblind: `N = a^k + (g^k)^(-r) = H_1(m)^k`
- finalize: `K_M = H_2(N || SHA256(m) || epoch)`

This is the same blind GDH structure used by DupLESS-style key servers, implemented in the prime-order `ristretto255` group rather than simulated with HMAC.

## Formal Meaning Of "Opaque To Outsiders"

Let:

- `FP(c) = SHA256(c)`
- `Loc(c) = HMAC_{K_D}("chunk-locator" || FP(c))`
- `Tag_u(c) = HMAC_{K_U}("public-handle" || u || Loc(c))`

where:

- `K_D` is the server-only dedup secret,
- `K_U` is the user's Argon2id-derived key,
- `u` is the user identity string.

`Opaque to outsiders` means:

For any PPT adversary that does not know `K_D` or `K_U`, the values `Loc(c)` and `Tag_u(c)` are computationally indistinguishable from random tags of the same length, except with negligible advantage in the security parameter. In particular, such an adversary should not be able to:

- test whether two public handles correspond to the same plaintext chunk,
- infer cross-user duplicate frequency from public handles alone,
- mount a confirmation attack by comparing leaked handles to guessed plaintexts.

## Reduction Sketch

### Public-handle opacity

Assume an outsider can distinguish whether two public handles came from equal or unequal chunks with non-negligible advantage.

Construct a distinguisher against the PRF security of HMAC:

1. Replace `Loc(c)` with a truly random function output.
2. Replace `Tag_u(c)` with a truly random function output keyed by `K_U`.
3. If the outsider still distinguishes equal from unequal chunks, it distinguishes HMAC from random.

Therefore, any non-negligible public-handle linkage attack implies a non-negligible PRF attack on HMAC-SHA256.

### Unauthorized download resistance

Suppose an unauthorized client downloads and decrypts a chunk it does not own.

It must then do one of the following:

1. recover the correct `K_U` without the password, contradicting the assumed password-hardness of Argon2id under the configured parameters, or
2. forge a valid `ownership_token_t` / ciphertext pair that passes `AES-GCM` verification, contradicting the authenticity of AES-GCM.

So unauthorized recovery reduces to password guessing against Argon2id or AEAD forgery against AES-GCM.

### OPRF key secrecy

Suppose an adversary predicts `K_M` for a fresh chunk without access to the epoch OPRF secret.

Then it distinguishes the `ristretto255` OPRF output from random or forges the result of the blind GDH computation. In the paper, this should be stated as a reduction to the pseudorandomness of the underlying OPRF in a prime-order group under the usual DDH/GDH-style assumption used by DupLESS/REFA-family systems.

This repository provides the implementation boundary and theorem statement, not a complete mechanized proof.

## Important Limitation

The single key server knows both:

- the epoch OPRF secret used to derive `K_M`, and
- the dedup secret `K_D` used to compute `Loc(c)`.

So the server can still observe duplicate structure. The current scheme only makes chunk linkage opaque to outsiders and unauthorized clients. Hiding duplicate structure from the key server itself would require a stronger architecture such as:

- a two-server OPRF split,
- a TEE-backed key server,
- ORAM-style access-pattern hiding,
- or encrypted search / oblivious dedup metadata.

That limitation should be stated explicitly in any paper draft.
