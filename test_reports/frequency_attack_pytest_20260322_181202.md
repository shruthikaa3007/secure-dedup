# Frequency Attack Pytest Report

- Generated: `2026-03-22 18:12:02`
- Suite: `tests/test_frequency_attack_resistance.py`
- Result: `15/15 passed`

## Saved Artifacts

- Raw pytest output: `test_reports/frequency_attack_pytest_20260322_181202.txt`
- JUnit XML: `test_reports/frequency_attack_pytest_20260322_181202.xml`

## What This Suite Demonstrates

- public `SHA-256` tokens are reproducible by an adversary,
- `HMAC-SHA256` tokens are not reproducible without the server secret,
- cross-user dedup is preserved,
- frequency analysis and confirmation attacks are blocked at the token level,
- HKDF-derived chunk keys remain bound to the secret-assisted token.
