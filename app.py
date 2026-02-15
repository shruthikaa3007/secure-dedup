import json
import os
from collections import Counter
from typing import Dict, Optional

from fastapi import FastAPI, File, Form, Header, HTTPException, UploadFile
from pydantic import BaseModel, Field

from attack_labeler import label_attack
from auth import resolve_client_id, validate_api_key
from chunking import chunk_file
from dedup_index import chunk_exists, register_chunk
from detector import detect_anomaly
from feature_store import save_features
from features import extract_features
from hashing import hash_chunk
from logger import REQUEST_LOGS, log_request
from policy_engine import (
    decide_response,
    get_active_policy_action,
    register_policy_action,
)
from pow_session import consume_verified, get_or_create_challenge, verify_challenge
from reputation import (
    get_reputation,
    record_benign_activity,
    record_policy_action as record_reputation_policy_action,
    record_pow_result,
)
from storage import get_chunk, upload_chunk

app = FastAPI()

UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)


class PowChallengeRequest(BaseModel):
    chunk_hash: str = Field(min_length=16)


class PowVerifyRequest(BaseModel):
    challenge_id: str = Field(min_length=8)
    chunk_hash: str = Field(min_length=16)
    proof: str = Field(min_length=16)


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


def _parse_pow_proofs(raw: Optional[str]) -> Dict[str, Dict[str, str]]:
    if not raw:
        return {}

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=400, detail={"error": f"Invalid pow_proofs_json: {exc}"})

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


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/pow/challenge")
def create_pow_challenge(
    request: PowChallengeRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    api_key = validate_api_key(x_api_key)
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
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    api_key = validate_api_key(x_api_key)
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
    pow_proofs_json: Optional[str] = Form(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    api_key = validate_api_key(x_api_key)
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
    adaptive_inputs = _compute_adaptive_inputs(client_id)

    supplied_proofs = _parse_pow_proofs(pow_proofs_json)
    verified_duplicate_hashes = set()
    pending_challenges_by_hash: Dict[str, Dict] = {}

    # Phase 1: ensure duplicate chunks have valid PoW before mutating storage/index.
    for chunk, chunk_hash in chunk_records:
        if not chunk_exists(chunk_hash):
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
        raise HTTPException(
            status_code=409,
            detail={
                "error": "PoW verification required for duplicate chunks",
                "client_id": client_id,
                "required_challenges": list(pending_challenges_by_hash.values()),
                "hint": "Call /pow/verify or provide pow_proofs_json and retry /upload",
            },
        )

    # Phase 2: perform dedup processing.
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
            log_request(
                client_id=client_id,
                operation_type="pow",
                chunk_hash=chunk_hash,
                pow_result=True,
            )
            record_pow_result(client_id, success=True)

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

    return {
        "status": "Upload successful",
        "client_id": client_id,
        "total_chunks": len(recipe),
        "file_recipe": recipe,
        "features": client_features,
        "saved_to": save_path,
        "anomaly_result": result,
        "policy_decision": policy,
        "attack_label": attack_label,
        "adaptive_inputs": adaptive_inputs,
        "reputation": reputation_snapshot,
    }
