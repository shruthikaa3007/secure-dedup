#!/usr/bin/env python3
import hashlib
import json
import os
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Optional

import requests


@dataclass
class CaseResult:
    name: str
    status: str
    duration_ms: int
    detail: str = ""
    data: Optional[Dict[str, Any]] = None


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _json_or_text(response: requests.Response):
    content_type = response.headers.get("content-type", "")
    if "application/json" in content_type:
        return response.json()
    return response.text


def _run_case(name: str, fn: Callable[[], Optional[Dict[str, Any]]]) -> CaseResult:
    start = time.time()
    try:
        data = fn() or None
        elapsed = int((time.time() - start) * 1000)
        return CaseResult(name=name, status="PASS", duration_ms=elapsed, data=data)
    except Exception as exc:
        elapsed = int((time.time() - start) * 1000)
        return CaseResult(name=name, status="FAIL", duration_ms=elapsed, detail=str(exc))


def _compute_proof(chunk: bytes, nonce_hex: str, offset: int, length: int) -> str:
    nonce = bytes.fromhex(nonce_hex)
    partial = chunk[offset : offset + length]
    return hashlib.sha256(nonce + partial).hexdigest()


def main() -> int:
    base_url = os.getenv("SECURE_DEDUP_BASE_URL", "").strip().rstrip("/")
    api_key = os.getenv("SECURE_DEDUP_API_KEY", "dev-api-key").strip()
    client_id = os.getenv("SECURE_DEDUP_CLIENT_ID", f"deployment-smoke-{int(time.time())}")
    repo_root = Path(__file__).resolve().parents[1]
    reports_dir = repo_root / "test_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    _assert(bool(base_url), "Set SECURE_DEDUP_BASE_URL before running deployment smoke tests")

    session = requests.Session()
    payload = f"secure dedup deployment smoke payload {time.time()}".encode("utf-8")
    file_name = "deployment_smoke.txt"
    challenges = []
    proofs = {}

    def request_json(method: str, path: str, **kwargs):
        response = session.request(method, f"{base_url}{path}", timeout=30, **kwargs)
        body = _json_or_text(response)
        return response, body

    def clear_policy() -> None:
        request_json(
            "POST",
            "/demo/clear-policy",
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key,
            },
            data=json.dumps({"client_id": client_id}),
        )

    def upload(pow_proofs_json: Optional[str] = None):
        data = {}
        if pow_proofs_json is not None:
            data["pow_proofs_json"] = pow_proofs_json
        response, body = request_json(
            "POST",
            "/upload",
            headers={
                "X-API-Key": api_key,
                "X-Client-ID": client_id,
            },
            files={
                "file": (file_name, payload, "text/plain"),
            },
            data=data,
        )
        return response, body

    def case_health() -> Dict[str, Any]:
        response, body = request_json("GET", "/health")
        _assert(response.status_code == 200, f"/health returned {response.status_code}")
        _assert(body.get("status") == "ok", "/health status is not ok")
        return body

    def case_config() -> Dict[str, Any]:
        response, body = request_json("GET", "/demo/config")
        _assert(response.status_code == 200, f"/demo/config returned {response.status_code}")
        for key in ("project", "storage", "encryption", "pow"):
            _assert(key in body, f"missing key in /demo/config response: {key}")
        return {
            "project_title": body.get("project", {}).get("title"),
            "encryption_enabled": body.get("encryption", {}).get("enabled"),
            "storage_backend": body.get("storage", {}).get("backend"),
        }

    def case_first_upload() -> Dict[str, Any]:
        response, body = upload()
        _assert(response.status_code == 200, f"first upload returned {response.status_code}")
        _assert(body.get("status") == "Upload successful", "first upload did not succeed")
        return {
            "file_id": body.get("file", {}).get("file_id"),
            "total_chunks": body.get("total_chunks"),
        }

    def case_duplicate_challenge() -> Dict[str, Any]:
        nonlocal challenges
        response, body = upload()
        if response.status_code in {403, 429}:
            clear_policy()
            response, body = upload()
        _assert(response.status_code == 409, f"duplicate upload returned {response.status_code}")
        challenges = body.get("detail", {}).get("required_challenges") or []
        _assert(bool(challenges), "duplicate upload did not return required challenges")
        return {
            "challenge_count": len(challenges),
            "challenge_length": challenges[0].get("length"),
        }

    def case_solve_and_retry() -> Dict[str, Any]:
        nonlocal proofs
        _assert(bool(challenges), "challenge list is empty before solve step")
        proofs = {}
        for challenge in challenges:
            proofs[challenge["chunk_hash"]] = {
                "challenge_id": challenge["challenge_id"],
                "proof": _compute_proof(payload, challenge["nonce_hex"], int(challenge["offset"]), int(challenge["length"])),
            }

        response, body = upload(pow_proofs_json=json.dumps(proofs))
        if response.status_code in {403, 429}:
            clear_policy()
            response, body = upload(pow_proofs_json=json.dumps(proofs))
        _assert(response.status_code == 200, f"retry upload returned {response.status_code}")
        _assert(body.get("status") == "Upload successful", "retry with proofs did not succeed")
        return {
            "proof_count": len(proofs),
            "retry_total_chunks": body.get("total_chunks"),
        }

    def case_metrics_summary() -> Dict[str, Any]:
        response, body = request_json(
            "GET",
            "/metrics",
            headers={
                "X-API-Key": api_key,
                "X-Client-ID": client_id,
            },
        )
        _assert(response.status_code == 200, f"/metrics returned {response.status_code}")
        summary = body.get("summary") or {}
        _assert("storage" in summary, "metrics summary missing storage section")
        _assert("pow" in summary, "metrics summary missing pow section")
        return {
            "dedup_saved_chunks": summary.get("storage", {}).get("dedup_saved_chunks"),
            "pow_challenges": summary.get("pow", {}).get("challenges_issued"),
            "pow_verified": summary.get("pow", {}).get("proofs_verified"),
            "clients_seen": summary.get("activity", {}).get("clients_seen"),
        }

    cases = [
        ("Health Endpoint", case_health),
        ("Config Endpoint", case_config),
        ("First Upload", case_first_upload),
        ("Duplicate Challenge", case_duplicate_challenge),
        ("Solve And Retry", case_solve_and_retry),
        ("Metrics Summary", case_metrics_summary),
    ]

    results = [_run_case(name, fn) for name, fn in cases]
    passed = sum(1 for item in results if item.status == "PASS")
    failed = len(results) - passed
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    generated_at = datetime.now(timezone.utc).isoformat()

    payload_summary = {
        "generated_at_utc": generated_at,
        "base_url": base_url,
        "client_id": client_id,
        "total": len(results),
        "passed": passed,
        "failed": failed,
        "results": [
            {
                "name": item.name,
                "status": item.status,
                "duration_ms": item.duration_ms,
                "detail": item.detail,
                "data": item.data,
            }
            for item in results
        ],
    }

    json_path = reports_dir / f"deployment_smoke_report_{stamp}.json"
    md_path = reports_dir / f"deployment_smoke_report_{stamp}.md"

    json_path.write_text(json.dumps(payload_summary, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    lines = [
        "# Secure Dedup Deployment Smoke Report",
        "",
        f"- Generated (UTC): `{generated_at}`",
        f"- Base URL: `{base_url}`",
        f"- Client ID: `{client_id}`",
        f"- Summary: `{passed}/{len(results)}` passed, `{failed}` failed",
        "",
        "## Test Cases",
        "",
    ]

    for item in results:
        lines.append(f"- `{item.status}` {item.name} ({item.duration_ms} ms)")
        if item.detail:
            lines.append(f"  - Detail: `{item.detail}`")
        if item.data:
            lines.append(f"  - Data: `{json.dumps(item.data, ensure_ascii=True)}`")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(f"Deployment smoke JSON: {json_path}")
    print(f"Deployment smoke MD:   {md_path}")
    print(f"Summary: {passed}/{len(results)} passed, {failed} failed")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
