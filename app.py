import base64
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, UploadFile
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from audit_store import create_audit_challenge, quick_audit, verify_audit_challenge

from attack_labeler import label_attack
from auth import REQUIRE_API_KEY, resolve_client_id, validate_api_key
from chunking import chunk_file
from dedup_index import chunk_exists, decrement_chunk_ref, get_ref_count, register_chunk
from detector import DETECTION_MODE, UNSUPERVISED_ANOMALY_THRESHOLD, detect_anomaly
from encryption import encryption_status, is_encrypted_payload
from feature_store import save_features
from encryption import encryption_enabled
from file_catalog import create_file, delete_file, get_file, list_files, update_file
from features import extract_features
from hashing import fingerprint_status, hash_chunk
from logger import REQUEST_LOGS, log_request
from metrics_tools import runtime_metrics_snapshot, runtime_metrics_summary
from policy_engine import (
    DEFAULT_BLOCK_THRESHOLD,
    DEFAULT_RATE_LIMIT_THRESHOLD,
    BLOCK_COOLDOWN_SEC,
    RATE_LIMIT_COOLDOWN_SEC,
    clear_policy_action,
    decide_response,
    get_active_policy_action,
    register_policy_action,
)
from pow import compute_proof
from pow_session import CHALLENGE_TTL_SEC, VERIFIED_TTL_SEC
from pow_session import consume_verified, get_or_create_challenge, verify_challenge
from ownership_store import add_owner, is_owner, ownership_summary, remove_owner, transfer_owner
from reputation import (
    get_reputation,
    record_benign_activity,
    record_policy_action as record_reputation_policy_action,
    record_pow_result,
)
from storage import delete_chunk, get_chunk, get_chunk_envelope_info, get_chunk_raw, storage_status, upload_chunk

app = FastAPI()

DEMO_MODE = os.getenv("DEMO_MODE", "true").strip().lower() in {"1", "true", "yes", "on"}
BASE_DIR = Path(__file__).resolve().parent
UI_DIR = BASE_DIR / "ui"
ENCRYPTION_COMPARISON_JSON = BASE_DIR / "docs" / "project_notes" / "encryption_scheme_comparison.json"

if UI_DIR.exists():
    app.mount("/ui", StaticFiles(directory=str(UI_DIR), html=True), name="ui")

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


class PowChallengeRequest(BaseModel):
    chunk_hash: str = Field(min_length=16)


class PowVerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=8)
    chunk_hash: str = Field(min_length=16)
    proof: str = Field(min_length=16)


class OwnershipTransferRequest(BaseModel):
    chunk_hash: str = Field(min_length=16)
    to_client_id: str = Field(min_length=1)


class AuditChallengeRequest(BaseModel):
    chunk_hash: str = Field(min_length=16)
    length: int = Field(default=32, ge=8, le=4096)


class AuditVerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=8)
    proof: str = Field(min_length=16)


class DemoChallenge(BaseModel):
    chunk_hash: str = Field(min_length=16)
    challenge_id: str = Field(min_length=8)
    nonce_hex: str = Field(min_length=16)
    offset: int = Field(ge=0)
    length: int = Field(ge=1)


class DemoSolvePowRequest(BaseModel):
    challenges: List[DemoChallenge]


class DemoSolveAuditRequest(BaseModel):
    challenge: DemoChallenge


class DemoForcePolicyRequest(BaseModel):
    client_id: str = Field(min_length=1)
    action: str = Field(min_length=1)


class DemoClearPolicyRequest(BaseModel):
    client_id: str = Field(min_length=1)


def _safe_detect(features: Dict, client_id: str) -> Dict:
    try:
        return detect_anomaly(features, client_id=client_id)
    except Exception as exc:
        return {
            "model_scores": {},
            "is_anomaly": False,
            "risk_score": 0.0,
            "anomaly_votes": 0,
            "models_considered": 0,
            "lstm_is_anomaly": False,
            "lstm_error": None,
            "predicted_attack_label": "normal",
            "class_probabilities": {},
            "detection_mode": "unavailable",
            "detection_error": str(exc),
        }


def _safe_risk(value) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except Exception:
        return 0.0


def _compute_adaptive_inputs(client_id: str) -> Dict:
    reputation_snapshot = get_reputation(client_id)
    risk_score = 0.0
    detection_mode = "insufficient_history"

    active_policy = get_active_policy_action(client_id)
    if active_policy:
        action = str(active_policy.get("action", "ALLOW")).upper()
        if action == "BLOCK":
            risk_score = max(risk_score, 1.0)
        elif action == "RATE_LIMIT":
            risk_score = max(risk_score, 0.75)

    history = REQUEST_LOGS.get(client_id)
    if history and len(history) >= 5:
        history_features = extract_features(history, REQUEST_LOGS)
        history_result = _safe_detect(history_features, client_id=client_id)
        risk_score = max(risk_score, _safe_risk(history_result.get("risk_score", 0.0)))
        detection_mode = str(history_result.get("detection_mode", "unknown"))

    return {
        "risk_score": _safe_risk(risk_score),
        "reputation_score": float(reputation_snapshot.get("score", 0.6)),
        "detection_mode": detection_mode,
    }


def _challenge_response_payload(challenge: Dict) -> Dict:
    return {
        "challenge_id": challenge["challenge_id"],
        "nonce_hex": challenge["nonce_hex"],
        "offset": challenge["offset"],
        "length": challenge["length"],
        "expires_at": challenge["expires_at"],
        "adaptive_profile": {
            "adaptive_enabled": challenge.get("adaptive_enabled", False),
            "difficulty_level": challenge.get("difficulty_level", "static"),
            "difficulty_score": challenge.get("difficulty_score", 0.0),
            "challenge_window_start": challenge.get("challenge_window_start", 0),
            "challenge_window_end": challenge.get("challenge_window_end", challenge.get("length", 0)),
            "risk_score": challenge.get("risk_score", 0.0),
            "reputation_score": challenge.get("reputation_score", 0.6),
        },
    }


def _raise_policy_exception(client_id: str, policy: Dict, detection: Optional[Dict] = None) -> None:
    action = str(policy.get("action", "ALLOW")).upper()
    if action in {"RATE_LIMIT", "BLOCK"}:
        log_request(
            client_id=client_id,
            operation_type="policy_rate_limit" if action == "RATE_LIMIT" else "policy_block",
            chunk_hash=None,
            pow_result=policy.get("risk_score", "enforced"),
        )
    detail = {
        "error": "Request blocked by anomaly policy" if policy["action"] == "BLOCK" else "Rate limited by anomaly policy",
        "client_id": client_id,
        "policy": policy,
    }
    if detection is not None:
        detail["detection"] = detection
    raise HTTPException(status_code=policy["status_code"], detail=detail)


def _enforce_pre_request_policy(client_id: str) -> None:
    active_policy = get_active_policy_action(client_id)
    if active_policy and active_policy.get("action") in {"RATE_LIMIT", "BLOCK"}:
        policy = {
            "action": active_policy["action"],
            "status_code": 429 if active_policy["action"] == "RATE_LIMIT" else 403,
            "remaining_sec": active_policy.get("remaining_sec", 0),
        }
        record_reputation_policy_action(client_id, policy["action"])
        _raise_policy_exception(client_id, policy)

    history = REQUEST_LOGS.get(client_id)
    if not history or len(history) < 8:
        return

    history_features = extract_features(history, REQUEST_LOGS)
    history_result = _safe_detect(history_features, client_id=client_id)
    history_policy = decide_response(history_result)

    if history_policy["action"] in {"RATE_LIMIT", "BLOCK"}:
        register_policy_action(client_id, history_policy["action"])
        record_reputation_policy_action(client_id, history_policy["action"])
        _raise_policy_exception(client_id, history_policy, history_result)


def _normalize_optional_form_value(raw: Optional[str]) -> Optional[str]:
    """Normalize optional form values and swallow placeholder defaults."""
    if raw is None:
        return None
    if not isinstance(raw, str):
        raw = str(raw)
    normalized = raw.strip()
    if not normalized:
        return None
    if normalized.lower() in {"string", "none", "null"}:
        return None
    return normalized


def _parse_pow_proofs(raw: Optional[str]) -> Dict[str, Dict[str, str]]:
    normalized = _normalize_optional_form_value(raw)
    if not normalized:
        return {}

    try:
        data = json.loads(normalized)
    except json.JSONDecodeError as exc:
        raise HTTPException(
            status_code=400,
            detail={
                "error": f"Invalid pow_proofs_json: {exc}",
                "hint": "Leave pow_proofs_json empty for first upload, or send valid JSON like {}",
            },
        )

    if not isinstance(data, dict):
        raise HTTPException(status_code=400, detail={"error": "pow_proofs_json must be an object"})

    parsed: Dict[str, Dict[str, str]] = {}
    for chunk_hash, payload in data.items():
        if not isinstance(payload, dict):
            continue
        challenge_id = payload.get("challenge_id")
        proof = payload.get("proof")
        if isinstance(challenge_id, str) and isinstance(proof, str):
            parsed[str(chunk_hash)] = {
                "challenge_id": challenge_id,
                "proof": proof,
            }

    return parsed


def _request_log_snapshot():
    return [(client_id, list(history)) for client_id, history in list(REQUEST_LOGS.items())]


def _recipe_positions(recipe: List[str]) -> Dict[str, List[int]]:
    positions: Dict[str, List[int]] = {}
    for index, chunk_hash in enumerate(recipe):
        positions.setdefault(chunk_hash, []).append(index)
    return positions


def _chunk_detail_rows(
    chunk_records,
    preexisting_ref_counts: Dict[str, int],
    verified_duplicate_hashes: Optional[set] = None,
    pending_challenges_by_hash: Optional[Dict[str, Dict]] = None,
) -> List[Dict]:
    verified_duplicate_hashes = verified_duplicate_hashes or set()
    pending_challenges_by_hash = pending_challenges_by_hash or {}
    rows = []

    for index, (chunk, chunk_hash) in enumerate(chunk_records):
        existed_before_upload = chunk_hash in preexisting_ref_counts
        challenge = pending_challenges_by_hash.get(chunk_hash)
        if challenge:
            status = "pow_required"
        elif existed_before_upload:
            status = "reused_existing"
        else:
            status = "stored_new"

        row = {
            "index": index,
            "chunk_hash": chunk_hash,
            "size_bytes": len(chunk),
            "existed_before_upload": existed_before_upload,
            "ref_count_before_upload": int(preexisting_ref_counts.get(chunk_hash, 0)),
            "pow_required": bool(challenge),
            "pow_verified": chunk_hash in verified_duplicate_hashes,
            "status": status,
        }
        if challenge:
            row["challenge_id"] = challenge.get("challenge_id")
            row["difficulty_level"] = challenge.get("adaptive_profile", {}).get("difficulty_level")
        rows.append(row)

    return rows


def _chunk_summary_payload(chunk_records, details: List[Dict]) -> Dict:
    recipe = [chunk_hash for _, chunk_hash in chunk_records]
    unique_chunk_hashes = list(dict.fromkeys(recipe))
    return {
        "logical_chunk_count": len(recipe),
        "unique_chunk_count": len(set(recipe)),
        "shared_with_existing_count": sum(1 for item in details if item.get("existed_before_upload")),
        "new_chunk_count": sum(1 for item in details if item.get("status") == "stored_new"),
        "reused_existing_count": sum(1 for item in details if item.get("status") == "reused_existing"),
        "pow_required_count": sum(1 for item in details if item.get("pow_required")),
        "pow_verified_count": sum(1 for item in details if item.get("pow_verified")),
        "shared_chunk_hashes": [item["chunk_hash"] for item in details if item.get("existed_before_upload")],
        "unique_chunk_hashes": unique_chunk_hashes,
    }


def _compare_file_recipes_payload(file_a: Dict, file_b: Dict) -> Dict:
    recipe_a = list(file_a.get("recipe", []))
    recipe_b = list(file_b.get("recipe", []))
    positions_a = _recipe_positions(recipe_a)
    positions_b = _recipe_positions(recipe_b)
    shared_hashes = sorted(set(positions_a) & set(positions_b))
    shared_recipe_entries = sum(min(len(positions_a[h]), len(positions_b[h])) for h in shared_hashes)

    return {
        "file_a": {
            "file_id": file_a.get("file_id"),
            "file_name": file_a.get("file_name"),
            "version": file_a.get("version"),
            "chunk_count": len(recipe_a),
        },
        "file_b": {
            "file_id": file_b.get("file_id"),
            "file_name": file_b.get("file_name"),
            "version": file_b.get("version"),
            "chunk_count": len(recipe_b),
        },
        "shared_chunk_count": len(shared_hashes),
        "shared_recipe_entries": shared_recipe_entries,
        "overlap_ratio_vs_file_a": round(shared_recipe_entries / len(recipe_a), 4) if recipe_a else 0.0,
        "overlap_ratio_vs_file_b": round(shared_recipe_entries / len(recipe_b), 4) if recipe_b else 0.0,
        "shared_chunk_positions": [
            {
                "chunk_hash": chunk_hash,
                "positions_in_file_a": positions_a[chunk_hash],
                "positions_in_file_b": positions_b[chunk_hash],
            }
            for chunk_hash in shared_hashes
        ],
        "only_in_file_a": sorted(set(positions_a) - set(positions_b)),
        "only_in_file_b": sorted(set(positions_b) - set(positions_a)),
        "interpretation": (
            "These files share chunk hashes and can visibly demonstrate dedup reuse."
            if shared_hashes
            else "These files do not share chunk hashes with the current chunking settings."
        ),
    }


def _client_highlights_payload(client_id: str) -> Dict:
    snapshot = list(REQUEST_LOGS.get(client_id, []))
    op_counts = Counter(
        item.get("operation_type") for item in snapshot if item.get("operation_type")
    )
    recent_events = [
        {
            "timestamp": item.get("timestamp"),
            "operation_type": item.get("operation_type"),
            "chunk_hash": item.get("chunk_hash"),
            "pow_result": item.get("pow_result"),
        }
        for item in snapshot[-12:]
    ]
    features = extract_features(snapshot, REQUEST_LOGS) if snapshot else {}
    detection = _safe_detect(features, client_id=client_id) if snapshot else {
        "is_anomaly": False,
        "risk_score": 0.0,
        "predicted_attack_label": "normal",
        "detection_mode": "insufficient_history",
        "class_probabilities": {},
    }
    policy = decide_response(detection)
    return {
        "client_id": client_id,
        "event_counts": dict(op_counts),
        "highlights": {
            "upload_attempts": int(op_counts.get("upload_start", 0)),
            "stored_new_chunks": int(op_counts.get("upload_chunk", 0)),
            "pow_challenges_issued": int(op_counts.get("pow_challenge", 0)),
            "pow_verifications": int(op_counts.get("pow_verify", 0)),
            "duplicate_reuse_successes": int(op_counts.get("pow", 0)),
            "rate_limit_events": int(op_counts.get("policy_rate_limit", 0)),
            "block_events": int(op_counts.get("policy_block", 0)),
        },
        "active_policy": get_active_policy_action(client_id),
        "reputation": get_reputation(client_id),
        "features": features,
        "detection": detection,
        "policy_decision": policy,
        "recent_events": recent_events,
    }


def _require_demo_mode() -> None:
    if not DEMO_MODE:
        raise HTTPException(status_code=404, detail={"error": "Demo mode disabled"})


def _require_api_key(x_api_key: Optional[str] = Header(default=None, alias="X-API-Key")) -> str:
    return validate_api_key(x_api_key)


@app.get("/", include_in_schema=False)
def demo_root():
    return RedirectResponse(url="/docs")


@app.get("/demo/config")
def demo_config():
    storage = storage_status()
    return {
        "status": "ok",
        "server_time_utc": datetime.now(timezone.utc).isoformat(),
        "demo_mode": DEMO_MODE,
        "project": {
            "title": "Secure Deduplication Prototype Centered on Wu et al. (2024)",
            "base_paper": "Wu et al., Journal of Information Security and Applications, 2024",
            "thesis_claim": (
                "Improve deterministic deduplication encryption with a secret-assisted chunk identity, "
                "fingerprint-bound AES-GCM, visible PoW, and lightweight runtime throttling."
            ),
            "focus": [
                "Use Wu et al. as the literature anchor for improving deterministic deduplication encryption under frequency-attack concerns.",
                "Compare a public-hash baseline against a stronger secret-assisted chunk-identity design.",
                "Upload unique content once and store token-bound encrypted chunks.",
                "Require proof-of-ownership before reusing duplicate chunks.",
                "Keep runtime monitoring visible through PoW, rate-limit, and chunk-reuse metrics.",
            ],
            "novelty": [
                "Replace public content-only dedup tokens with secret-assisted HMAC chunk identities.",
                "Bind segmented AES-GCM chunk encryption to those dedup identities through HKDF-derived keys.",
                "Add visible PoW and runtime throttling on top of the encryption-focused dedup path.",
            ],
            "out_of_scope": [
                "Data auditing is not part of the core thesis claim or main demo flow.",
                "Ownership transfer and file-version lifecycle support remain secondary code paths.",
            ],
        },
        "auth": {"require_api_key": REQUIRE_API_KEY},
        "storage": storage,
        "encryption": encryption_status(),
        "fingerprint": fingerprint_status(),
        "detection": {
            "mode": DETECTION_MODE,
            "unsupervised_threshold": UNSUPERVISED_ANOMALY_THRESHOLD,
            "model_dir": os.getenv("MODEL_DIR", "."),
        },
        "policy": {
            "rate_limit_threshold": DEFAULT_RATE_LIMIT_THRESHOLD,
            "block_threshold": DEFAULT_BLOCK_THRESHOLD,
            "rate_limit_cooldown_sec": RATE_LIMIT_COOLDOWN_SEC,
            "block_cooldown_sec": BLOCK_COOLDOWN_SEC,
        },
        "pow": {
            "challenge_ttl_sec": CHALLENGE_TTL_SEC,
            "verified_ttl_sec": VERIFIED_TTL_SEC,
        },
    }


@app.get("/demo/policy/{client_id}")
def demo_policy_snapshot(
    client_id: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    validate_api_key(x_api_key)

    history = REQUEST_LOGS.get(client_id, [])
    features = extract_features(history, REQUEST_LOGS) if history else {}
    detection = _safe_detect(features, client_id=client_id) if history else {
        "model_scores": {},
        "is_anomaly": False,
        "risk_score": 0.0,
        "anomaly_votes": 0,
        "models_considered": 0,
        "lstm_is_anomaly": False,
        "lstm_error": None,
        "predicted_attack_label": "normal",
        "class_probabilities": {},
        "detection_mode": "insufficient_history",
    }

    policy = decide_response(detection)
    active_policy = get_active_policy_action(client_id)
    reputation_snapshot = get_reputation(client_id)

    return {
        "client_id": client_id,
        "features": features,
        "detection": detection,
        "policy_decision": policy,
        "active_policy": active_policy,
        "reputation": reputation_snapshot,
    }


@app.get("/demo/highlights/{client_id}")
def demo_client_highlights(
    client_id: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    """
    Demo-facing summary of chunk reuse, PoW activity, and policy/rate-limit events for one client.
    """
    validate_api_key(x_api_key)
    return {"status": "ok", **_client_highlights_payload(client_id)}


@app.post("/demo/force-policy")
def demo_force_policy(
    request: DemoForcePolicyRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    _require_demo_mode()
    validate_api_key(x_api_key)

    action = request.action.strip().upper()
    if action not in {"RATE_LIMIT", "BLOCK"}:
        raise HTTPException(status_code=400, detail={"error": "action must be RATE_LIMIT or BLOCK"})

    register_policy_action(request.client_id, action)
    record_reputation_policy_action(request.client_id, action)
    active_policy = get_active_policy_action(request.client_id)

    return {
        "client_id": request.client_id,
        "action": action,
        "active_policy": active_policy,
    }


@app.post("/demo/clear-policy")
def demo_clear_policy(
    request: DemoClearPolicyRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    _require_demo_mode()
    validate_api_key(x_api_key)

    clear_policy_action(request.client_id)
    return {"client_id": request.client_id, "cleared": True}


@app.post("/demo/solve_pow")
def demo_solve_pow(
    request: DemoSolvePowRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    _require_demo_mode()
    validate_api_key(x_api_key)

    proofs: Dict[str, Dict[str, str]] = {}
    for challenge in request.challenges:
        try:
            stored_chunk = get_chunk(challenge.chunk_hash)
        except FileNotFoundError:
            raise HTTPException(
                status_code=404,
                detail={"error": "Chunk not found", "chunk_hash": challenge.chunk_hash},
            )
        try:
            nonce = bytes.fromhex(challenge.nonce_hex)
        except Exception:
            raise HTTPException(status_code=400, detail={"error": "Invalid nonce_hex"})

        proof = compute_proof(stored_chunk, nonce, challenge.offset, challenge.length)
        proofs[challenge.chunk_hash] = {
            "challenge_id": challenge.challenge_id,
            "proof": proof,
        }

    return {"pow_proofs": proofs}


@app.post("/demo/solve_audit", include_in_schema=False)
def demo_solve_audit(
    request: DemoSolveAuditRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    _require_demo_mode()
    validate_api_key(x_api_key)

    challenge = request.challenge
    try:
        stored_chunk = get_chunk(challenge.chunk_hash)
    except FileNotFoundError:
        raise HTTPException(
            status_code=404,
            detail={"error": "Chunk not found", "chunk_hash": challenge.chunk_hash},
        )

    try:
        nonce = bytes.fromhex(challenge.nonce_hex)
    except Exception:
        raise HTTPException(status_code=400, detail={"error": "Invalid nonce_hex"})

    proof = compute_proof(stored_chunk, nonce, challenge.offset, challenge.length)
    return {
        "challenge_id": challenge.challenge_id,
        "chunk_hash": challenge.chunk_hash,
        "proof": proof,
    }


@app.get("/demo/chunk/{chunk_hash}")
def demo_chunk_inspect(
    chunk_hash: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    validate_api_key(x_api_key)
    try:
        raw = get_chunk_raw(chunk_hash)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail={"error": "Chunk not found", "chunk_hash": chunk_hash})
    prefix = base64.b64encode(raw[:16]).decode("ascii") if raw else ""
    return {
        "chunk_hash": chunk_hash,
        "raw_size": len(raw),
        "encrypted_payload": is_encrypted_payload(raw),
        "magic_prefix_b64": prefix,
    }


@app.get("/demo/compare-files")
def demo_compare_files(
    file_id_a: str,
    file_id_b: str,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    """
    Compare two uploaded file recipes and show exactly which chunk hashes are shared.
    This is the easiest Swagger-visible proof that slightly similar files reuse the same chunks.
    """
    client_id = resolve_client_id(x_client_id, f"{file_id_a}:{file_id_b}", api_key)
    try:
        file_a = get_file(file_id_a)
        file_b = get_file(file_id_b)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"error": str(exc)})

    if file_a["owner_client_id"] != client_id or file_b["owner_client_id"] != client_id:
        raise HTTPException(status_code=403, detail={"error": "Only the owner can compare file recipes"})

    return {
        "status": "ok",
        "comparison": _compare_file_recipes_payload(file_a, file_b),
    }


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics")
def metrics():
    return {
        "status": "ok",
        "metrics": runtime_metrics_snapshot(),
        "summary": runtime_metrics_summary(),
    }


@app.get("/demo/metrics/summary")
def demo_metrics_summary():
    return {
        "status": "ok",
        "summary": runtime_metrics_summary(),
    }


@app.get("/demo/encryption")
def demo_encryption(
    chunk_hash: Optional[str] = None,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, chunk_hash or "demo-encryption", api_key)

    result = {
        "status": "ok",
        "client_id": client_id,
        "encryption_enabled": encryption_enabled(),
        "strict_mode": os.getenv("CHUNK_ENCRYPTION_STRICT", "false").strip().lower() in {"1", "true", "yes", "on"},
        "segment_size": os.getenv("CHUNK_ENCRYPTION_SEGMENT_SIZE", "4096"),
    }

    if chunk_hash:
        if not is_owner(chunk_hash, client_id):
            raise HTTPException(status_code=403, detail={"error": "Only owners can inspect chunk encryption", "chunk_hash": chunk_hash})
        try:
            result["chunk"] = {
                "chunk_hash": chunk_hash,
                **get_chunk_envelope_info(chunk_hash),
            }
        except FileNotFoundError:
            raise HTTPException(status_code=404, detail={"error": "Chunk not found", "chunk_hash": chunk_hash})

    return result


@app.get("/demo/encryption/comparison")
def demo_encryption_comparison():
    """
    Return the checked-in baseline-vs-proposed encryption comparison used for the demo.
    """
    if not ENCRYPTION_COMPARISON_JSON.exists():
        raise HTTPException(
            status_code=404,
            detail={
                "error": "Encryption comparison report not found",
                "path": str(ENCRYPTION_COMPARISON_JSON),
            },
        )

    with open(ENCRYPTION_COMPARISON_JSON, "r", encoding="utf-8") as fh:
        comparison = json.load(fh)

    schemes = comparison.get("schemes", [])
    baseline = schemes[0] if len(schemes) > 0 else {}
    proposed = schemes[1] if len(schemes) > 1 else {}
    deltas = comparison.get("comparison", {})
    return {
        "status": "ok",
        "base_paper": {
            "citation": "J. Wu et al., Journal of Information Security and Applications, 2024",
            "title": "A randomized encryption deduplication method against frequency attack",
            "doi": "10.1016/j.jisa.2024.103774",
            "why_it_matters": (
                "Wu et al. motivate moving beyond deterministic deduplication encryption because "
                "frequency patterns can leak sensitive structure."
            ),
        },
        "positioning": {
            "baseline_story": (
                "Treat public SHA-256-bound deduplication encryption as the deterministic baseline direction "
                "to improve on, then compare it with a secret-assisted HMAC-bound alternative."
            ),
            "our_improvements": [
                "Replace public content hashes with secret-assisted HMAC chunk tokens.",
                "Derive per-chunk AES-GCM keys from those tokens via HKDF-SHA256 while keeping standard cryptographic primitives.",
                "Add visible proof-of-ownership and lightweight throttling around duplicate reuse.",
            ],
            "out_of_scope": [
                "Data auditing is not part of the core project claim.",
                "Ownership transfer and file-version workflows are secondary support modules, not primary evaluation evidence.",
            ],
            "recommended_demo_endpoints": [
                "/demo/encryption/comparison",
                "/upload",
                "/demo/compare-files",
                "/demo/highlights/{client_id}",
            ],
        },
        "headline": {
            "baseline_scheme": baseline.get("scheme"),
            "proposed_scheme": proposed.get("scheme"),
            "dedup_saved_percent_baseline": baseline.get("dedup_saved_percent"),
            "dedup_saved_percent_proposed": proposed.get("dedup_saved_percent"),
            "token_time_delta_pct": deltas.get("token_time_delta_pct"),
            "encrypt_time_delta_pct": deltas.get("encrypt_time_delta_pct"),
            "decrypt_time_delta_pct": deltas.get("decrypt_time_delta_pct"),
            "storage_overhead_delta_bytes": deltas.get("storage_overhead_delta_bytes"),
        },
        "comparison": comparison,
    }


@app.get("/demo/status")
def demo_status(limit: int = 20):
    bounded_limit = max(1, min(100, int(limit)))

    clients = []
    events = []
    request_log_items = _request_log_snapshot()
    for client_id, history in request_log_items:
        if not history:
            continue
        history_snapshot = list(history)
        latest_event = history_snapshot[-1]
        clients.append(
            {
                "client_id": client_id,
                "request_count": len(history_snapshot),
                "last_event_ts": latest_event.get("timestamp"),
                "active_policy": get_active_policy_action(client_id),
                "reputation": get_reputation(client_id),
            }
        )
        for item in history_snapshot[-bounded_limit:]:
            events.append(
                {
                    "client_id": client_id,
                    "timestamp": item.get("timestamp"),
                    "operation_type": item.get("operation_type"),
                    "chunk_hash": item.get("chunk_hash"),
                    "pow_result": item.get("pow_result"),
                }
            )

    clients.sort(key=lambda item: item.get("last_event_ts") or 0.0, reverse=True)
    events.sort(key=lambda item: item.get("timestamp") or 0.0, reverse=True)

    return {
        "status": "ok",
        "service": "secure-dedup",
        "server_time": time.time(),
        "summary": {
            "active_clients": len(clients),
            "total_buffered_events": sum(len(history) for _, history in request_log_items),
            "recent_operation_types": Counter(
                event["operation_type"] for event in events if event.get("operation_type")
            ),
        },
        "clients": clients[:bounded_limit],
        "recent_events": events[:bounded_limit],
    }


@app.get("/demo/ui")
def demo_ui():
    return RedirectResponse(url="/docs")


@app.post("/pow/challenge")
def create_pow_challenge(
    request: PowChallengeRequest,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, request.chunk_hash, api_key)

    if not chunk_exists(request.chunk_hash):
        raise HTTPException(status_code=404, detail={"error": "Chunk not found", "chunk_hash": request.chunk_hash})

    stored_chunk = get_chunk(request.chunk_hash)
    adaptive_inputs = _compute_adaptive_inputs(client_id)
    challenge = get_or_create_challenge(
        client_id,
        request.chunk_hash,
        len(stored_chunk),
        risk_score=adaptive_inputs["risk_score"],
        reputation_score=adaptive_inputs["reputation_score"],
        duplicate_context={"duplicate_hits": 1},
    )
    log_request(
        client_id=client_id,
        operation_type="pow_challenge",
        chunk_hash=request.chunk_hash,
        pow_result="issued",
    )

    return {
        "status": "challenge_created",
        "client_id": client_id,
        "chunk_hash": request.chunk_hash,
        "challenge": _challenge_response_payload(challenge),
        "adaptive_inputs": adaptive_inputs,
    }


@app.post("/pow/verify")
def verify_pow(
    request: PowVerifyRequest,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, request.chunk_hash, api_key)

    if not chunk_exists(request.chunk_hash):
        raise HTTPException(status_code=404, detail={"error": "Chunk not found", "chunk_hash": request.chunk_hash})

    stored_chunk = get_chunk(request.chunk_hash)
    verified = verify_challenge(
        client_id=client_id,
        challenge_id=request.challenge_id,
        chunk_hash=request.chunk_hash,
        stored_chunk=stored_chunk,
        client_proof=request.proof,
    )

    log_request(
        client_id=client_id,
        operation_type="pow_verify",
        chunk_hash=request.chunk_hash,
        pow_result=verified,
    )

    if not verified:
        reputation_snapshot = record_pow_result(client_id, success=False)
        raise HTTPException(
            status_code=403,
            detail={
                "error": "PoW verification failed",
                "reputation_score": reputation_snapshot.get("score"),
            },
        )

    reputation_snapshot = record_pow_result(client_id, success=True)

    return {
        "status": "verified",
        "client_id": client_id,
        "chunk_hash": request.chunk_hash,
        "reputation": reputation_snapshot,
    }


@app.post("/upload")
async def upload_file(
    file: UploadFile = File(...),
    pow_proofs_json: Optional[str] = Form(
        default=None,
        description=(
            "Optional JSON map of duplicate chunk proofs. "
            "Leave empty for first upload. Example: {\"<chunk_hash>\": {\"challenge_id\": \"...\", \"proof\": \"...\"}}"
        ),
    ),
    file_id: Optional[str] = Form(default=None, description="Optional existing file ID for version update. Leave empty for new uploads."),
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, file.filename, api_key)
    _enforce_pre_request_policy(client_id)

    log_request(
        client_id=client_id,
        operation_type="upload_start",
        chunk_hash=None,
        pow_result=None,
    )

    data = await file.read()
    if not data:
        raise HTTPException(status_code=400, detail={"error": "Empty file uploaded"})

    safe_name = file.filename or "uploaded.bin"
    save_path = os.path.join(UPLOAD_DIR, safe_name)
    with open(save_path, "wb") as f:
        f.write(data)

    chunks = chunk_file(data)
    if not chunks:
        raise HTTPException(status_code=400, detail={"error": "Unable to split uploaded data into chunks"})

    chunk_records = [(chunk, hash_chunk(chunk)) for chunk in chunks if chunk]
    recipe = [chunk_hash for _, chunk_hash in chunk_records]
    duplicate_hits_by_hash = Counter(recipe)
    preexisting_ref_counts = {
        chunk_hash: get_ref_count(chunk_hash)
        for chunk_hash in set(recipe)
        if chunk_exists(chunk_hash)
    }
    adaptive_inputs = _compute_adaptive_inputs(client_id)

    supplied_proofs = _parse_pow_proofs(pow_proofs_json)
    verified_duplicate_hashes = set()
    pending_challenges_by_hash: Dict[str, Dict] = {}

    # Phase 1: ensure duplicate chunks have valid PoW before mutating storage/index.
    for chunk, chunk_hash in chunk_records:
        if chunk_hash not in preexisting_ref_counts:
            continue

        proof_payload = supplied_proofs.get(chunk_hash)
        is_verified = False
        if proof_payload:
            stored_chunk = get_chunk(chunk_hash)
            is_verified = verify_challenge(
                client_id=client_id,
                challenge_id=proof_payload["challenge_id"],
                chunk_hash=chunk_hash,
                stored_chunk=stored_chunk,
                client_proof=proof_payload["proof"],
            )
            log_request(
                client_id=client_id,
                operation_type="pow_verify",
                chunk_hash=chunk_hash,
                pow_result=is_verified,
            )
            record_pow_result(client_id, success=is_verified)

        if not is_verified:
            is_verified = consume_verified(client_id, chunk_hash)

        if is_verified:
            verified_duplicate_hashes.add(chunk_hash)
            continue

        challenge = get_or_create_challenge(
            client_id=client_id,
            chunk_hash=chunk_hash,
            chunk_length=len(chunk),
            risk_score=adaptive_inputs["risk_score"],
            reputation_score=adaptive_inputs["reputation_score"],
            duplicate_context={"duplicate_hits": duplicate_hits_by_hash.get(chunk_hash, 1)},
        )
        pending_challenges_by_hash[chunk_hash] = {
            "chunk_hash": chunk_hash,
            **_challenge_response_payload(challenge),
        }

    if pending_challenges_by_hash:
        preview_details = _chunk_detail_rows(
            chunk_records,
            preexisting_ref_counts=preexisting_ref_counts,
            verified_duplicate_hashes=verified_duplicate_hashes,
            pending_challenges_by_hash=pending_challenges_by_hash,
        )
        for chunk_hash in pending_challenges_by_hash:
            log_request(
                client_id=client_id,
                operation_type="pow_challenge",
                chunk_hash=chunk_hash,
                pow_result="required",
            )
        raise HTTPException(
            status_code=409,
            detail={
                "error": "PoW verification required for duplicate chunks",
                "client_id": client_id,
                "required_challenges": list(pending_challenges_by_hash.values()),
                "chunk_summary": _chunk_summary_payload(chunk_records, preview_details),
                "chunk_details": preview_details,
                "hint": "Call /pow/verify or provide pow_proofs_json and retry /upload",
            },
        )

    # Optional data-dynamics context: update an existing file version instead of creating a new one.
    previous_recipe = []
    normalized_file_id = _normalize_optional_form_value(file_id)
    if normalized_file_id:
        try:
            existing = get_file(normalized_file_id)
        except KeyError:
            raise HTTPException(status_code=404, detail={"error": "File not found", "file_id": normalized_file_id})
        if existing["owner_client_id"] != client_id:
            raise HTTPException(status_code=403, detail={"error": "Only file owner can update", "file_id": normalized_file_id})
        if existing["status"] != "active":
            raise HTTPException(status_code=409, detail={"error": "File is deleted", "file_id": normalized_file_id})
        previous_recipe = list(existing.get("recipe", []))

    # Phase 2: perform dedup processing for the new version recipe.
    for chunk, chunk_hash in chunk_records:
        log_request(
            client_id=client_id,
            operation_type="hash_query",
            chunk_hash=chunk_hash,
            pow_result=None,
        )

        if not chunk_exists(chunk_hash):
            upload_chunk(chunk_hash, chunk)
            register_chunk(chunk_hash)
            add_owner(chunk_hash, client_id)
            log_request(
                client_id=client_id,
                operation_type="upload_chunk",
                chunk_hash=chunk_hash,
                pow_result="N/A",
            )
        else:
            if chunk_hash not in verified_duplicate_hashes:
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "Missing verified PoW for duplicate chunk",
                        "chunk_hash": chunk_hash,
                    },
                )

            register_chunk(chunk_hash)
            add_owner(chunk_hash, client_id)
            log_request(
                client_id=client_id,
                operation_type="pow",
                chunk_hash=chunk_hash,
                pow_result=True,
            )
            record_pow_result(client_id, success=True)

    # If this was a file update, decrement refs from the previous recipe and clean orphan chunks.
    if previous_recipe:
        new_counts = Counter(recipe)
        old_counts = Counter(previous_recipe)
        for old_hash, old_count in old_counts.items():
            remove_n = max(0, old_count - new_counts.get(old_hash, 0))
            for _ in range(remove_n):
                remaining = decrement_chunk_ref(old_hash)
                if remaining <= 0:
                    delete_chunk(old_hash)
                remove_owner(old_hash, client_id)

    if normalized_file_id:
        file_record = update_file(normalized_file_id, client_id, recipe, file_name=safe_name)
    else:
        file_record = create_file(client_id, safe_name, recipe)

    client_features = extract_features(REQUEST_LOGS[client_id], REQUEST_LOGS)
    result = _safe_detect(client_features, client_id=client_id)
    policy = decide_response(result)

    reputation_snapshot = get_reputation(client_id)
    if policy["action"] in {"RATE_LIMIT", "BLOCK"}:
        register_policy_action(client_id, policy["action"])
        reputation_snapshot = record_reputation_policy_action(client_id, policy["action"])
    else:
        reputation_snapshot = record_benign_activity(client_id)

    attack_label = label_attack(client_features)

    save_features(
        client_id,
        client_features,
        anomaly=result["is_anomaly"],
        label=attack_label,
        risk_score=result.get("risk_score"),
        policy_action=policy["action"],
    )

    final_chunk_details = _chunk_detail_rows(
        chunk_records,
        preexisting_ref_counts=preexisting_ref_counts,
        verified_duplicate_hashes=verified_duplicate_hashes,
    )
    for item in final_chunk_details:
        item["ref_count_after_upload"] = int(get_ref_count(item["chunk_hash"]))

    return {
        "status": "Upload successful",
        "client_id": client_id,
        "total_chunks": len(recipe),
        "file_recipe": recipe,
        "chunk_summary": _chunk_summary_payload(chunk_records, final_chunk_details),
        "chunk_details": final_chunk_details,
        "file": file_record,
        "features": client_features,
        "saved_to": save_path,
        "anomaly_result": result,
        "policy_decision": policy,
        "attack_label": attack_label,
        "adaptive_inputs": adaptive_inputs,
        "reputation": reputation_snapshot,
    }



@app.get("/files", include_in_schema=False)
def get_my_files(
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, "files", api_key)
    return {"client_id": client_id, "files": list_files(client_id)}


@app.get("/files/{file_id}", include_in_schema=False)
def get_file_by_id(
    file_id: str,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, file_id, api_key)
    try:
        record = get_file(file_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"error": "File not found", "file_id": file_id})
    if record["owner_client_id"] != client_id:
        raise HTTPException(status_code=403, detail={"error": "Forbidden", "file_id": file_id})
    return record


@app.delete("/files/{file_id}", include_in_schema=False)
def delete_file_by_id(
    file_id: str,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, file_id, api_key)
    try:
        record = delete_file(file_id, client_id)
    except KeyError:
        raise HTTPException(status_code=404, detail={"error": "File not found", "file_id": file_id})
    except PermissionError as exc:
        raise HTTPException(status_code=403, detail={"error": str(exc), "file_id": file_id})

    for chunk_hash in record.get("recipe", []):
        remaining = decrement_chunk_ref(chunk_hash)
        remove_owner(chunk_hash, client_id)
        if remaining <= 0:
            delete_chunk(chunk_hash)

    return {"status": "deleted", "file": record}


@app.get("/ownership/{chunk_hash}", include_in_schema=False)
def get_chunk_ownership(
    chunk_hash: str,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, chunk_hash, api_key)
    if not is_owner(chunk_hash, client_id):
        raise HTTPException(status_code=403, detail={"error": "Not an owner", "chunk_hash": chunk_hash})
    return ownership_summary(chunk_hash)


@app.post("/ownership/transfer", include_in_schema=False)
def transfer_chunk_ownership(
    request: OwnershipTransferRequest,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, request.chunk_hash, api_key)
    if not is_owner(request.chunk_hash, client_id):
        raise HTTPException(status_code=403, detail={"error": "Only owner can transfer", "chunk_hash": request.chunk_hash})

    transfer_owner(request.chunk_hash, client_id, request.to_client_id, actor_client_id=client_id)
    return {"status": "transferred", "ownership": ownership_summary(request.chunk_hash)}


@app.post("/audit/challenge", include_in_schema=False)
def create_chunk_audit(
    request: AuditChallengeRequest,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, request.chunk_hash, api_key)
    if not is_owner(request.chunk_hash, client_id):
        raise HTTPException(status_code=403, detail={"error": "Only owners can audit", "chunk_hash": request.chunk_hash})

    try:
        challenge = create_audit_challenge(request.chunk_hash, request.length)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail={"error": "Chunk not found", "chunk_hash": request.chunk_hash})
    return {"status": "challenge_created", "challenge": challenge}


@app.post("/audit/verify", include_in_schema=False)
def verify_chunk_audit(
    request: AuditVerifyRequest,
    api_key: str = Depends(_require_api_key),
):
    _ = api_key
    try:
        result = verify_audit_challenge(request.challenge_id, request.proof)
    except KeyError:
        raise HTTPException(status_code=404, detail={"error": "Challenge not found", "challenge_id": request.challenge_id})
    return result


@app.get("/audit/quick/{chunk_hash}", include_in_schema=False)
def quick_chunk_audit(
    chunk_hash: str,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, chunk_hash, api_key)
    if not is_owner(chunk_hash, client_id):
        raise HTTPException(status_code=403, detail={"error": "Only owners can audit", "chunk_hash": chunk_hash})

    return quick_audit(chunk_hash)
