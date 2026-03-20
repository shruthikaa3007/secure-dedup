#!/usr/bin/env python3
import asyncio
import io
import json
import os
import platform
import sys
import tempfile
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


@dataclass
class CaseResult:
    name: str
    status: str
    duration_ms: int
    detail: str = ""
    data: Optional[Dict[str, Any]] = None


@dataclass
class SmokeContext:
    client_id: str = "smoke-client"
    file_name: str = "smoke.txt"
    payload: bytes = b""
    challenges: List[Dict[str, Any]] = field(default_factory=list)
    proofs: Dict[str, Dict[str, str]] = field(default_factory=dict)


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _run_case(name: str, fn: Callable[[], Optional[Dict[str, Any]]]) -> CaseResult:
    start = time.time()
    try:
        data = fn() or None
        elapsed = int((time.time() - start) * 1000)
        return CaseResult(name=name, status="PASS", duration_ms=elapsed, data=data)
    except Exception as exc:
        elapsed = int((time.time() - start) * 1000)
        return CaseResult(name=name, status="FAIL", duration_ms=elapsed, detail=str(exc))


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    reports_dir = repo_root / "test_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    runtime_dir = Path(tempfile.mkdtemp(prefix="secure-dedup-smoke-"))

    os.environ["API_KEYS"] = os.getenv("API_KEYS", "dev-api-key")
    os.environ["STORAGE_BACKEND"] = "filesystem"
    os.environ["LOCAL_CHUNK_DIR"] = str(runtime_dir / "local_chunks")
    os.environ["TELEMETRY_DB"] = str(runtime_dir / "telemetry.db")
    os.environ["MODEL_DIR"] = str(repo_root / "advanced_artifacts")
    os.environ["REQUIRE_API_KEY"] = "true"
    os.environ["DEMO_MODE"] = "true"
    os.environ["CHUNK_ENCRYPTION_DEFAULT_ON"] = "true"
    os.environ["DEDUP_FINGERPRINT_MODE"] = "secret_hmac"
    os.environ["DEDUP_FINGERPRINT_DEFAULT_ON"] = "true"

    os.chdir(runtime_dir)
    sys.path.insert(0, str(repo_root))

    from fastapi import HTTPException
    from starlette.datastructures import UploadFile

    import app

    ctx = SmokeContext(
        payload=f"secure dedup smoke payload {time.time()}".encode("utf-8"),
    )

    async def _upload(pow_proofs_json: Optional[str] = None):
        upload_file = UploadFile(file=io.BytesIO(ctx.payload), filename=ctx.file_name)
        return await app.upload_file(
            file=upload_file,
            pow_proofs_json=pow_proofs_json,
            file_id=None,
            api_key="dev-api-key",
            x_client_id=ctx.client_id,
        )

    def case_health() -> Dict[str, Any]:
        response = app.health()
        _assert(response.get("status") == "ok", "health status is not ok")
        return response

    def case_config() -> Dict[str, Any]:
        response = app.demo_config()
        for key in ("project", "storage", "encryption", "detection", "policy", "pow"):
            _assert(key in response, f"missing key in /demo/config response: {key}")
        return {
            "project_title": response.get("project", {}).get("title"),
            "detection_mode": response.get("detection", {}).get("mode"),
            "storage": response.get("storage", {}).get("backend"),
            "encryption_enabled": response.get("encryption", {}).get("enabled"),
            "fingerprint_mode": response.get("fingerprint", {}).get("mode"),
        }

    def case_upload_success() -> Dict[str, Any]:
        response = asyncio.run(_upload())
        _assert(response.get("status") == "Upload successful", "first upload did not succeed")
        _assert(int(response.get("total_chunks", 0)) >= 1, "total_chunks not reported")
        recipe = response.get("file_recipe") or []
        _assert(bool(recipe), "file recipe is empty after upload")
        return {
            "file_id": response.get("file", {}).get("file_id"),
            "total_chunks": response.get("total_chunks"),
            "first_chunk": recipe[0],
        }

    def case_duplicate_requires_pow() -> Dict[str, Any]:
        try:
            asyncio.run(_upload())
        except HTTPException as exc:
            if exc.status_code in {403, 429}:
                app.demo_clear_policy(
                    request=app.DemoClearPolicyRequest(client_id=ctx.client_id),
                    x_api_key="dev-api-key",
                )
                try:
                    asyncio.run(_upload())
                except HTTPException as retry_exc:
                    _assert(retry_exc.status_code == 409, f"expected 409, got {retry_exc.status_code}")
                    detail = retry_exc.detail or {}
                    challenges = detail.get("required_challenges") or []
                    _assert(bool(challenges), "no PoW challenges returned on duplicate retry")
                    ctx.challenges = challenges
                    return {
                        "challenge_count": len(challenges),
                        "hint": detail.get("hint"),
                        "retry_path": "clear_policy_then_duplicate",
                    }
                raise AssertionError("duplicate retry did not trigger PoW challenge")
            _assert(exc.status_code == 409, f"expected 409, got {exc.status_code}")
            detail = exc.detail or {}
            challenges = detail.get("required_challenges") or []
            _assert(bool(challenges), "no PoW challenges returned on duplicate upload")
            ctx.challenges = challenges
            return {
                "challenge_count": len(challenges),
                "hint": detail.get("hint"),
                "retry_path": "direct_duplicate",
            }
        raise AssertionError("duplicate upload did not trigger PoW challenge")

    def case_pow_solve_and_retry() -> Dict[str, Any]:
        _assert(bool(ctx.challenges), "no challenges saved from previous step")

        challenge_payload = []
        for item in ctx.challenges:
            challenge_payload.append(
                {
                    "chunk_hash": item["chunk_hash"],
                    "challenge_id": item["challenge_id"],
                    "nonce_hex": item["nonce_hex"],
                    "offset": item["offset"],
                    "length": item["length"],
                }
            )

        solve_request = app.DemoSolvePowRequest(challenges=challenge_payload)
        solved = app.demo_solve_pow(request=solve_request, x_api_key="dev-api-key")
        proofs = solved.get("pow_proofs") or {}
        _assert(bool(proofs), "PoW solver did not return proofs")
        ctx.proofs = proofs

        try:
            retry = asyncio.run(_upload(pow_proofs_json=json.dumps(proofs)))
        except HTTPException as exc:
            if exc.status_code not in {403, 429}:
                raise
            app.demo_clear_policy(
                request=app.DemoClearPolicyRequest(client_id=ctx.client_id),
                x_api_key="dev-api-key",
            )
            retry = asyncio.run(_upload(pow_proofs_json=json.dumps(proofs)))
        _assert(retry.get("status") == "Upload successful", "retry with proofs failed")
        return {
            "proof_count": len(proofs),
            "retry_total_chunks": retry.get("total_chunks"),
        }

    def case_status_and_metrics() -> Dict[str, Any]:
        status = app.demo_status(limit=20)
        metrics = app.metrics()
        _assert(status.get("status") == "ok", "/demo/status did not return ok")
        _assert(metrics.get("status") == "ok", "/metrics did not return ok")
        summary = metrics.get("summary") or {}
        _assert("storage" in summary, "/metrics summary missing storage section")
        _assert("pow" in summary, "/metrics summary missing pow section")
        summary = status.get("summary", {})
        return {
            "active_clients": summary.get("active_clients"),
            "total_buffered_events": summary.get("total_buffered_events"),
            "metrics_keys": sorted((metrics.get("metrics") or {}).keys()),
            "pow_challenges": (metrics.get("summary") or {}).get("pow", {}).get("challenges_issued"),
        }

    def case_ui_assets() -> Dict[str, Any]:
        ui_index = (repo_root / "ui" / "index.html").read_text(encoding="utf-8")
        ui_app_js = (repo_root / "ui" / "app.js").read_text(encoding="utf-8")
        _assert("Step 1: Upload Original File" in ui_index, "UI step 1 CTA missing")
        _assert("stepSolveAndRetry" in ui_app_js, "UI step 3 flow missing")
        _assert("Behavioural Monitoring" in ui_index, "UI monitoring panel missing")
        return {"ui_checks": "ok"}

    cases: List[tuple[str, Callable[[], Optional[Dict[str, Any]]]]] = [
        ("Health Endpoint", case_health),
        ("Config Endpoint", case_config),
        ("Upload Success", case_upload_success),
        ("Duplicate Requires PoW", case_duplicate_requires_pow),
        ("PoW Solve And Retry", case_pow_solve_and_retry),
        ("Status And Metrics", case_status_and_metrics),
        ("UI Assets Functional Hooks", case_ui_assets),
    ]

    results = [_run_case(name, fn) for name, fn in cases]

    passed = sum(1 for item in results if item.status == "PASS")
    failed = len(results) - passed
    generated_at = datetime.now(timezone.utc).isoformat()
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    summary_payload = {
        "generated_at_utc": generated_at,
        "python_version": sys.version,
        "platform": platform.platform(),
        "repo_root": str(repo_root),
        "runtime_dir": str(runtime_dir),
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

    md_path = reports_dir / f"smoke_test_report_{stamp}.md"
    json_path = reports_dir / f"smoke_test_report_{stamp}.json"

    lines = [
        "# Secure Dedup Smoke Test Report",
        "",
        f"- Generated (UTC): `{generated_at}`",
        f"- Python: `{platform.python_version()}`",
        f"- Platform: `{platform.platform()}`",
        f"- Repo: `{repo_root}`",
        f"- Isolated Runtime Dir: `{runtime_dir}`",
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
    json_path.write_text(json.dumps(summary_payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    print(f"Smoke test report: {md_path}")
    print(f"Smoke test JSON:   {json_path}")
    print(f"Summary: {passed}/{len(results)} passed, {failed} failed")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
