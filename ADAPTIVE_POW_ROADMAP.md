# Adaptive PoW Roadmap (Final-Year Novelty Track)

## 1) Project contribution statement
Build and evaluate a **risk-adaptive proof-of-ownership (PoW) controller** for secure deduplication, where PoW challenge difficulty is dynamically tuned using behavioral anomaly risk and client reputation.

## 2) Research questions
1. Does adaptive PoW reduce attack success versus static PoW?
2. Can adaptive PoW keep honest-user latency close to baseline?
3. Which signal contributes most: anomaly risk, reputation, or both?

## 3) Thesis claims you should be able to defend
1. A closed-loop defense is more robust than fixed-threshold PoW in mixed workloads.
2. Dynamic challenge tuning improves security/usability trade-off.
3. Reputation-aware adaptation reduces repeated-abuse efficiency.

## 4) Implementation phases

### Phase 0: Baseline freeze and reproducibility
1. Freeze current baseline behavior and metrics.
2. Save baseline config in `model_metadata.json` and a new `experiments/` folder.
3. Record baseline run outputs in `experiments/baseline_static_pow/`.

Files:
- `app.py`
- `pow_session.py`
- `policy_engine.py`
- `detector.py`
- `evaluate_model.py`

Deliverable:
- Baseline metrics table (attack success, false block/rate-limit, p95 upload latency, server cost proxy).

### Phase 1: Adaptive challenge controller
1. Add `adaptive_pow.py` with function `select_challenge_profile(risk_score, reputation_score, duplicate_context)`.
2. Extend challenge payload in `pow_session.py` to persist adaptive fields:
   - `difficulty_level`
   - `challenge_length`
   - `challenge_window`
3. Update `/pow/challenge` in `app.py` to return selected profile metadata.
4. Keep backward compatibility: default static profile when adaptive config missing.

Files:
- `adaptive_pow.py` (new)
- `pow_session.py`
- `app.py`
- `pow.py`

Deliverable:
- Adaptive profile generation tested with deterministic unit tests.

### Phase 2: Reputation engine
1. Add `reputation.py` with decayed trust score per client.
2. Update score from telemetry events:
   - successful verified ownership
   - failed verification attempts
   - policy-trigger events
3. Store state in Redis with in-memory fallback (same pattern as existing modules).
4. Expose current score in challenge and upload responses for debugging.

Files:
- `reputation.py` (new)
- `logger.py`
- `policy_engine.py`
- `app.py`

Deliverable:
- Reputation trend plots for normal vs attacker clients.

### Phase 3: Closed-loop policy integration
1. Feed detector outputs and reputation into adaptive controller.
2. Add guardrails:
   - max difficulty cap
   - cooldown decay after benign behavior
   - emergency static fallback switch (env flag)
3. Add structured telemetry fields for analysis:
   - `risk_score`
   - `reputation_score`
   - `selected_difficulty`
   - `verification_outcome`

Files:
- `detector.py`
- `policy_engine.py`
- `app.py`
- `feature_store.py`
- `request_logs.csv` schema handling in builders

Deliverable:
- End-to-end runtime demo: same user shifts across ALLOW -> RATE_LIMIT -> tougher PoW -> recovery.

### Phase 4: Evaluation harness and ablation study
1. Build `run_experiments.py` to execute controlled comparisons:
   - Static PoW baseline
   - Adaptive PoW (risk only)
   - Adaptive PoW (reputation only)
   - Adaptive PoW (risk + reputation)
2. Reuse existing adapters (`dataset_adapters.py`) to generate replay workloads.
3. Add result aggregator `analyze_experiments.py` for confidence intervals and delta metrics.

Files:
- `run_experiments.py` (new)
- `analyze_experiments.py` (new)
- `dataset_adapters.py`
- `build_feature_dataset_from_logs.py`

Deliverable:
- Comparison plots and statistical summary for report chapter.

### Phase 5: Report-ready artifacts
1. Create final tables:
   - security gain (attack reduction)
   - usability cost (latency impact)
   - operational cost (extra verification effort)
2. Add failure cases and limitations section.
3. Include reproducibility appendix with exact commands and seeds.

Deliverable:
- Final chapter package under `experiments/final_report_assets/`.

## 5) Metrics to track
1. `Attack Success Rate` = successful malicious duplicates / malicious duplicate attempts.
2. `False Block Rate` = normal requests blocked / normal requests.
3. `False Rate-Limit Rate` = normal requests rate-limited / normal requests.
4. `PoW Verification Cost` = avg verification time and challenge complexity.
5. `p95 Upload Latency` per client type.
6. `Defense Utility Score` = weighted score you define for security vs usability.

## 6) Suggested 6-week timeline
1. Week 1: baseline freeze + instrumentation.
2. Week 2: adaptive controller implementation.
3. Week 3: reputation engine + integration.
4. Week 4: closed-loop guardrails + hardening.
5. Week 5: experiment runner + ablation.
6. Week 6: report figures, discussion, and reproducibility pack.

## 7) Minimum viable novelty (if time gets tight)
1. Implement only two difficulty tiers (`normal`, `hardened`) using risk + reputation.
2. Run baseline vs adaptive comparison on one FIU split and one MSRC split.
3. Provide ablation with and without reputation.
4. Report statistically supported improvement and one known limitation.
