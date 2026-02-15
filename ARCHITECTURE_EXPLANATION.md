# Secure Deduplication Final Cloud Architecture: Explanation

This document explains the architecture shown in `architecture.drawio` and the concepts it represents.

## 1. Purpose of This Architecture

The diagram represents a **target-state cloud platform** for secure deduplicated uploads.  
It combines:

- Deduplication for storage efficiency
- Adaptive Proof-of-Work (PoW) for abuse resistance
- Behavioral detection and policy enforcement
- MLOps-driven continuous improvement
- Operational controls like audit, SIEM, backup, and DR

## 2. Layered View

The diagram is organized into two major zones:

- `Cloud Runtime: Multi-Tenant Secure Dedup Platform`
- `MLOps, Governance, and Continuous Improvement`

### 2.1 Cloud Runtime (Online path)

Main components:

- `Tenant Apps + Partner Integrations`
- `API Gateway + Ingress Service`
- `Upload Orchestrator + Chunking`
- `Deduplication Service`
- `PoW and Abuse Mitigation Service`
- `Adaptive Security Orchestrator`
- `Event Stream + Telemetry`
- `Real-Time Feature Pipeline`
- `Model Serving Endpoint`
- `Policy Decision Service (ALLOW / RATE_LIMIT / BLOCK)`
- `Reputation and Trust Service`
- `Online Feature Store + Audit Log`
- `Session Cache + Rate Limits`

### 2.2 Data and Control Stores

Supporting stores used by runtime:

- `Object Storage`
- `Fingerprint Index (NoSQL)`
- `Online Feature Store + Audit Log`
- `Session Cache + Rate Limits`

### 2.3 MLOps and Governance (Offline path)

Main components:

- `Telemetry Lakehouse`
- `Offline Feature Store + Data Prep`
- `Training + Evaluation Pipeline`
- `Model Registry + Artifacts`
- `Release Orchestrator`
- `Central Config + Feature Flags`
- `Security Operations + SIEM`
- `Multi-Region DR + Backup`

## 3. Core Request Lifecycle

The main upload lifecycle is:

1. **Ingress**
   - Client traffic enters through `API Gateway + Ingress Service` (`API traffic` label).
2. **Preparation**
   - Request moves through `Upload Orchestrator + Chunking`.
3. **Dedup decision**
   - `Deduplication Service` checks fingerprints.
4. **Branch: new vs duplicate**
   - `new chunk flow` -> write via `Object Storage Writer` to `Object Storage`.
   - `duplicate flow` -> route to `PoW and Abuse Mitigation Service`.
5. **Adaptive challenge**
   - PoW service requests `challenge profile` from `Adaptive Security Orchestrator`.
   - Orchestrator returns `difficulty settings`.
6. **Enforcement**
   - `Policy Decision Service` returns `ALLOW / RATE_LIMIT / BLOCK` to ingress path.

## 4. Security and Abuse-Defense Concepts

### 4.1 Adaptive PoW

PoW is not static. Challenge difficulty is adapted from:

- Current risk (`risk score`)
- User trust/reputation (`reputation score`)
- Runtime context (`session and cooldown state`)

### 4.2 Behavior-based policy loop

Security decisions are feedback-driven:

- `Event Stream + Telemetry` captures request behavior.
- `Real-Time Feature Pipeline` converts behavior into model features.
- `Model Serving Endpoint` predicts risk.
- `Policy Decision Service` enforces action.
- `Reputation and Trust Service` updates trust signals for future requests.

### 4.3 Defense-in-depth

The architecture uses multiple controls together:

- Access control at ingress/API
- Dedup + PoW challenge path
- Real-time anomaly scoring
- Policy enforcement and rate limiting
- Session/cooldown state
- Security operations telemetry (`security telemetry`)

## 5. Data Concepts

### 5.1 Deduplication data plane

- `Fingerprint Index (NoSQL)` stores content signatures for existence checks.
- `Object Storage` stores canonical chunk data.

### 5.2 Security/analytics data plane

- `Online Feature Store + Audit Log` supports online decisions and traceability.
- `Telemetry Lakehouse` is long-term historical storage for training and analysis.

## 6. MLOps and Release Concepts

### 6.1 Continuous training

Runtime telemetry is reused for model improvement:

- `Telemetry Lakehouse` -> `Offline Feature Store + Data Prep` -> `Training + Evaluation Pipeline` -> `Model Registry + Artifacts`

### 6.2 Controlled release

The `Release Orchestrator` receives:

- `approved model package`
- `security sign-off`
- `DR readiness`
- `runtime config bundle`

It then performs staged rollout:

- `deploy model`
- `deploy policy`
- `deploy adaptive controls`

### 6.3 Decoupled runtime configuration

`Central Config + Feature Flags` enables configuration updates (thresholds, adaptive settings) without full code redeploy.

## 7. Operations, Audit, and Resilience

The target architecture explicitly includes future-step operational maturity:

- `Online Feature Store + Audit Log` for traceability
- `Security Operations + SIEM` for monitoring and incident workflows
- `Multi-Region DR + Backup` for continuity and recovery

This moves the system from a prototype runtime into a production-grade cloud platform.

## 8. How to Read Arrow Labels

Only **important arrows** are labeled to keep the diagram readable.  
Labeled arrows indicate:

- Critical decision branches (`new chunk flow`, `duplicate flow`)
- Security control exchanges (`challenge profile`, `difficulty settings`)
- Enforcement outcomes (`ALLOW / RATE_LIMIT / BLOCK`)
- Release governance and rollout (`approved model package`, `security sign-off`, `deploy *`)

Unlabeled arrows are supporting data/control connections that are structurally necessary but not conceptually primary.

