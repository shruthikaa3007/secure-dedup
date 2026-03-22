# Behavioural Attack Demo Pytest Report

- Generated: `2026-03-22 18:12:00`
- Suite: `tests/test_attack_detection_demo.py`
- Result: `11/11 passed`

## Saved Artifacts

- Raw pytest output: `test_reports/attack_detection_demo_pytest_20260322_181200.txt`
- JUnit XML: `test_reports/attack_detection_demo_pytest_20260322_181200.xml`

## What This Suite Demonstrates

- hash probing is detected and rate limited,
- dedup DoS is detected and blocked,
- ownership fraud through repeated PoW attempts is detected,
- legitimate low-rate or low-failure behaviour is not misclassified,
- the REFA gap demonstration shows:
  `REFA would: ALLOW | Our framework would: RATE_LIMIT`.
