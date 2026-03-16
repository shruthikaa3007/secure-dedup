import json
import os
import time
from collections import Counter
from typing import Dict, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Security, UploadFile
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field

from audit_store import create_audit_challenge, quick_audit, verify_audit_challenge

from attack_labeler import label_attack
from auth import resolve_client_id, validate_api_key
from chunking import chunk_file
from dedup_index import chunk_exists, decrement_chunk_ref, register_chunk
from detector import detect_anomaly
from feature_store import save_features
from file_catalog import create_file, delete_file, get_file, list_files, update_file
from features import extract_features
from hashing import hash_chunk
from logger import REQUEST_LOGS, log_request
from metrics_tools import runtime_metrics_snapshot
from policy_engine import (
    decide_response,
    get_active_policy_action,
    register_policy_action,
)
from pow_session import consume_verified, get_or_create_challenge, verify_challenge
from ownership_store import add_owner, is_owner, ownership_summary, remove_owner, transfer_owner
from reputation import (
    get_reputation,
    record_benign_activity,
    record_policy_action as record_reputation_policy_action,
    record_pow_result,
)
from storage import delete_chunk, get_chunk, upload_chunk

app = FastAPI()

_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def _require_api_key(api_key: Optional[str] = Security(_api_key_header)) -> str:
    return validate_api_key(api_key)

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


@app.get("/")
def root():
    return {"status": "ok", "service": "secure-dedup"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/metrics")
def metrics():
    return {"status": "ok", "metrics": runtime_metrics_snapshot()}


@app.get("/demo/status")
def demo_status(limit: int = 20):
    bounded_limit = max(1, min(100, int(limit)))

    clients = []
    events = []
    for client_id, history in REQUEST_LOGS.items():
        if not history:
            continue
        latest_event = history[-1]
        clients.append(
            {
                "client_id": client_id,
                "request_count": len(history),
                "last_event_ts": latest_event.get("timestamp"),
                "active_policy": get_active_policy_action(client_id),
                "reputation": get_reputation(client_id),
            }
        )
        for item in list(history)[-bounded_limit:]:
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
            "total_buffered_events": sum(len(history) for history in REQUEST_LOGS.values()),
            "recent_operation_types": Counter(
                event["operation_type"] for event in events if event.get("operation_type")
            ),
        },
        "clients": clients[:bounded_limit],
        "recent_events": events[:bounded_limit],
    }


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
    pow_proofs_json: Optional[str] = Form(default=None),
    file_id: Optional[str] = Form(default=None),
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

    # Optional data-dynamics context: update an existing file version instead of creating a new one.
    previous_recipe = []
    if file_id:
        try:
            existing = get_file(file_id)
        except KeyError:
            raise HTTPException(status_code=404, detail={"error": "File not found", "file_id": file_id})
        if existing["owner_client_id"] != client_id:
            raise HTTPException(status_code=403, detail={"error": "Only file owner can update", "file_id": file_id})
        if existing["status"] != "active":
            raise HTTPException(status_code=409, detail={"error": "File is deleted", "file_id": file_id})
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

    if file_id:
        file_record = update_file(file_id, client_id, recipe, file_name=safe_name)
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

    return {
        "status": "Upload successful",
        "client_id": client_id,
        "total_chunks": len(recipe),
        "file_recipe": recipe,
        "file": file_record,
        "features": client_features,
        "saved_to": save_path,
        "anomaly_result": result,
        "policy_decision": policy,
        "attack_label": attack_label,
        "adaptive_inputs": adaptive_inputs,
        "reputation": reputation_snapshot,
    }



@app.get("/files")
def get_my_files(
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, "files", api_key)
    return {"client_id": client_id, "files": list_files(client_id)}


@app.get("/files/{file_id}")
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


@app.delete("/files/{file_id}")
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


@app.get("/ownership/{chunk_hash}")
def get_chunk_ownership(
    chunk_hash: str,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, chunk_hash, api_key)
    if not is_owner(chunk_hash, client_id):
        raise HTTPException(status_code=403, detail={"error": "Not an owner", "chunk_hash": chunk_hash})
    return ownership_summary(chunk_hash)


@app.post("/ownership/transfer")
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


@app.post("/audit/challenge")
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


@app.post("/audit/verify")
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


@app.get("/audit/quick/{chunk_hash}")
def quick_chunk_audit(
    chunk_hash: str,
    api_key: str = Depends(_require_api_key),
    x_client_id: Optional[str] = Header(default=None, alias="X-Client-ID"),
):
    client_id = resolve_client_id(x_client_id, chunk_hash, api_key)
    if not is_owner(chunk_hash, client_id):
        raise HTTPException(status_code=403, detail={"error": "Only owners can audit", "chunk_hash": chunk_hash})

    return quick_audit(chunk_hash)
