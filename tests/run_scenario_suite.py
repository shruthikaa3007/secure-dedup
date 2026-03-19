#!/usr/bin/env python3
import asyncio
import csv
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
class ScenarioResult:
    name: str
    status: str
    duration_ms: int
    detail: str = ""
    data: Optional[Dict[str, Any]] = None
    metrics_before: Dict[str, int] = field(default_factory=dict)
    metrics_after: Dict[str, int] = field(default_factory=dict)
    metrics_delta: Dict[str, int] = field(default_factory=dict)


@dataclass
class ScenarioContext:
    main_client: str
    second_client: str
    third_client: str
    api_key: str = "dev-api-key"
    main_payload: bytes = b""
    main_file_name: str = "scenario_main.txt"
    main_chunk_hash: Optional[str] = None
    main_challenges: List[Dict[str, Any]] = field(default_factory=list)
    secondary_file_id: Optional[str] = None


def _assert(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def _delta(before: Dict[str, int], after: Dict[str, int]) -> Dict[str, int]:
    keys = sorted(set(before.keys()) | set(after.keys()))
    out = {}
    for key in keys:
        out[key] = int(after.get(key, 0)) - int(before.get(key, 0))
    return out


def main() -> int:
    repo_root = Path(__file__).resolve().parents[1]
    reports_dir = repo_root / "test_reports"
    reports_dir.mkdir(parents=True, exist_ok=True)

    runtime_dir = Path(tempfile.mkdtemp(prefix="secure-dedup-scenarios-"))
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    os.environ["API_KEYS"] = os.getenv("API_KEYS", "dev-api-key")
    os.environ["REQUIRE_API_KEY"] = "true"
    os.environ["STORAGE_BACKEND"] = "filesystem"
    os.environ["LOCAL_CHUNK_DIR"] = str(runtime_dir / "local_chunks")
    os.environ["TELEMETRY_DB"] = str(runtime_dir / "telemetry.db")
    os.environ["MODEL_DIR"] = str(repo_root / "advanced_artifacts")

    os.chdir(runtime_dir)
    sys.path.insert(0, str(repo_root))

    from fastapi import HTTPException
    from starlette.datastructures import UploadFile

    import app
    from pow import compute_proof
    from storage import get_chunk

    ctx = ScenarioContext(
        main_client="scenario-main-client",
        second_client="scenario-second-client",
        third_client="scenario-third-client",
        main_payload=f"secure dedup scenario payload {time.time()}".encode("utf-8"),
    )

    async def _upload(
        client_id: str,
        payload: bytes,
        file_name: str,
        pow_proofs_json: Optional[str] = None,
        file_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        upload_file = UploadFile(file=io.BytesIO(payload), filename=file_name)
        return await app.upload_file(
            file=upload_file,
            pow_proofs_json=pow_proofs_json,
            file_id=file_id,
            api_key=ctx.api_key,
            x_client_id=client_id,
        )

    def _metrics_snapshot() -> Dict[str, int]:
        snapshot = app.metrics()
        _assert(snapshot.get("status") == "ok", "metrics endpoint did not return ok")
        raw = snapshot.get("metrics") or {}
        return {str(k): int(v) for k, v in raw.items()}

    def _run_scenario(name: str, fn: Callable[[], Optional[Dict[str, Any]]]) -> ScenarioResult:
        before = _metrics_snapshot()
        start = time.time()
        try:
            data = fn() or None
            status = "PASS"
            detail = ""
        except Exception as exc:
            data = None
            status = "FAIL"
            detail = str(exc)
        after = _metrics_snapshot()
        elapsed = int((time.time() - start) * 1000)
        return ScenarioResult(
            name=name,
            status=status,
            duration_ms=elapsed,
            detail=detail,
            data=data,
            metrics_before=before,
            metrics_after=after,
            metrics_delta=_delta(before, after),
        )

    def scenario_1_baseline_upload() -> Dict[str, Any]:
        response = asyncio.run(_upload(ctx.main_client, ctx.main_payload, ctx.main_file_name))
        _assert(response.get("status") == "Upload successful", "baseline upload failed")
        recipe = response.get("file_recipe") or []
        _assert(bool(recipe), "baseline upload produced empty recipe")
        ctx.main_chunk_hash = recipe[0]
        return {
            "file_id": response.get("file", {}).get("file_id"),
            "total_chunks": response.get("total_chunks"),
            "chunk_hash": ctx.main_chunk_hash,
        }

    def scenario_2_duplicate_requires_pow() -> Dict[str, Any]:
        try:
            asyncio.run(_upload(ctx.main_client, ctx.main_payload, ctx.main_file_name))
        except HTTPException as exc:
            if exc.status_code == 429:
                app.demo_clear_policy(
                    request=app.DemoClearPolicyRequest(client_id=ctx.main_client),
                    x_api_key=ctx.api_key,
                )
                try:
                    asyncio.run(_upload(ctx.main_client, ctx.main_payload, ctx.main_file_name))
                except HTTPException as retry_exc:
                    _assert(retry_exc.status_code == 409, f"expected 409, got {retry_exc.status_code}")
                    detail = retry_exc.detail or {}
                    challenges = detail.get("required_challenges") or []
                    _assert(bool(challenges), "duplicate retry returned no challenges")
                    ctx.main_challenges = challenges
                    return {"challenge_count": len(challenges), "retry_path": "clear_policy_then_duplicate"}
                raise AssertionError("expected duplicate retry to raise HTTPException 409")

            _assert(exc.status_code == 409, f"expected 409, got {exc.status_code}")
            detail = exc.detail or {}
            challenges = detail.get("required_challenges") or []
            _assert(bool(challenges), "duplicate upload returned no challenges")
            ctx.main_challenges = challenges
            return {"challenge_count": len(challenges), "retry_path": "direct_duplicate"}

        raise AssertionError("duplicate upload should require PoW challenge")

    def scenario_3_pow_solve_and_retry() -> Dict[str, Any]:
        _assert(bool(ctx.main_challenges), "missing challenge state from previous scenario")
        challenge_payload = []
        for item in ctx.main_challenges:
            challenge_payload.append(
                {
                    "chunk_hash": item["chunk_hash"],
                    "challenge_id": item["challenge_id"],
                    "nonce_hex": item["nonce_hex"],
                    "offset": item["offset"],
                    "length": item["length"],
                }
            )
        solve = app.demo_solve_pow(
            request=app.DemoSolvePowRequest(challenges=challenge_payload),
            x_api_key=ctx.api_key,
        )
        proofs = solve.get("pow_proofs") or {}
        _assert(bool(proofs), "PoW solver returned empty proof set")
        retry = asyncio.run(
            _upload(
                ctx.main_client,
                ctx.main_payload,
                ctx.main_file_name,
                pow_proofs_json=json.dumps(proofs),
            )
        )
        _assert(retry.get("status") == "Upload successful", "retry with PoW proofs failed")
        return {"proof_count": len(proofs), "retry_total_chunks": retry.get("total_chunks")}

    def scenario_4_policy_enforcement_and_recovery() -> Dict[str, Any]:
        rate_payload = f"rate-limit check {time.time()}".encode("utf-8")
        block_payload = f"block check {time.time()}".encode("utf-8")

        app.demo_force_policy(
            request=app.DemoForcePolicyRequest(client_id=ctx.main_client, action="RATE_LIMIT"),
            x_api_key=ctx.api_key,
        )
        try:
            asyncio.run(_upload(ctx.main_client, rate_payload, "rate_limit.txt"))
        except HTTPException as exc:
            _assert(exc.status_code == 429, f"expected 429 after RATE_LIMIT, got {exc.status_code}")
        else:
            raise AssertionError("RATE_LIMIT scenario did not block request with 429")

        app.demo_clear_policy(
            request=app.DemoClearPolicyRequest(client_id=ctx.main_client),
            x_api_key=ctx.api_key,
        )
        recovered = asyncio.run(_upload(ctx.main_client, rate_payload, "rate_limit_recover.txt"))
        _assert(recovered.get("status") == "Upload successful", "recovery after RATE_LIMIT failed")

        app.demo_force_policy(
            request=app.DemoForcePolicyRequest(client_id=ctx.main_client, action="BLOCK"),
            x_api_key=ctx.api_key,
        )
        try:
            asyncio.run(_upload(ctx.main_client, block_payload, "block_case.txt"))
        except HTTPException as exc:
            _assert(exc.status_code == 403, f"expected 403 after BLOCK, got {exc.status_code}")
        else:
            raise AssertionError("BLOCK scenario did not block request with 403")

        app.demo_clear_policy(
            request=app.DemoClearPolicyRequest(client_id=ctx.main_client),
            x_api_key=ctx.api_key,
        )
        recovered_block = asyncio.run(_upload(ctx.main_client, block_payload, "block_recover.txt"))
        _assert(recovered_block.get("status") == "Upload successful", "recovery after BLOCK failed")
        return {"rate_limit_blocked": True, "block_blocked": True}

    def scenario_5_file_version_update_delete() -> Dict[str, Any]:
        payload_v1 = f"file-version-v1 {time.time()}".encode("utf-8")
        payload_v2 = f"file-version-v2 {time.time()}".encode("utf-8")

        def upload_with_policy_recovery(payload: bytes, file_name: str, file_id: Optional[str] = None) -> Dict[str, Any]:
            try:
                return asyncio.run(_upload(ctx.second_client, payload, file_name, file_id=file_id))
            except HTTPException as exc:
                if exc.status_code != 429:
                    raise
                app.demo_clear_policy(
                    request=app.DemoClearPolicyRequest(client_id=ctx.second_client),
                    x_api_key=ctx.api_key,
                )
                return asyncio.run(_upload(ctx.second_client, payload, file_name, file_id=file_id))

        first = upload_with_policy_recovery(payload_v1, "versioned.txt")
        _assert(first.get("status") == "Upload successful", "initial version upload failed")
        file_id = first.get("file", {}).get("file_id")
        _assert(bool(file_id), "missing file_id in initial version upload")
        ctx.secondary_file_id = file_id

        second = upload_with_policy_recovery(payload_v2, "versioned.txt", file_id=file_id)
        _assert(second.get("status") == "Upload successful", "version update upload failed")
        _assert(second.get("file", {}).get("version") == 2, "expected file version 2 after update")

        fetched = app.get_file_by_id(
            file_id=file_id,
            api_key=ctx.api_key,
            x_client_id=ctx.second_client,
        )
        _assert(fetched.get("version") == 2, "GET /files/{file_id} did not return latest version")

        deleted = app.delete_file_by_id(
            file_id=file_id,
            api_key=ctx.api_key,
            x_client_id=ctx.second_client,
        )
        _assert(deleted.get("status") == "deleted", "delete scenario did not return deleted status")
        return {"file_id": file_id, "version_after_update": fetched.get("version")}

    def scenario_6_ownership_transfer_and_audit() -> Dict[str, Any]:
        _assert(bool(ctx.main_chunk_hash), "main chunk hash missing from baseline upload")

        before = app.get_chunk_ownership(
            chunk_hash=ctx.main_chunk_hash,
            api_key=ctx.api_key,
            x_client_id=ctx.main_client,
        )
        _assert(before.get("owner_count", 0) >= 1, "ownership summary unexpectedly empty")

        transfer = app.transfer_chunk_ownership(
            request=app.OwnershipTransferRequest(
                chunk_hash=ctx.main_chunk_hash,
                to_client_id=ctx.third_client,
            ),
            api_key=ctx.api_key,
            x_client_id=ctx.main_client,
        )
        owners = transfer.get("ownership", {}).get("owners") or []
        _assert(ctx.third_client in owners, "ownership transfer did not include target client")

        challenge_resp = app.create_chunk_audit(
            request=app.AuditChallengeRequest(chunk_hash=ctx.main_chunk_hash, length=16),
            api_key=ctx.api_key,
            x_client_id=ctx.third_client,
        )
        challenge = challenge_resp.get("challenge") or {}
        nonce = bytes.fromhex(challenge["nonce_hex"])
        stored = get_chunk(ctx.main_chunk_hash)
        proof = compute_proof(stored, nonce, int(challenge["offset"]), int(challenge["length"]))

        verify = app.verify_chunk_audit(
            request=app.AuditVerifyRequest(challenge_id=challenge["challenge_id"], proof=proof),
            api_key=ctx.api_key,
        )
        _assert(bool(verify.get("verified")), "audit challenge verify failed")

        quick = app.quick_chunk_audit(
            chunk_hash=ctx.main_chunk_hash,
            api_key=ctx.api_key,
            x_client_id=ctx.third_client,
        )
        _assert(quick.get("integrity") == "ok", "quick audit did not return integrity=ok")
        return {"owner_count_after_transfer": len(owners), "audit_verified": True}

    def scenario_7_encryption_status_and_ui_hooks() -> Dict[str, Any]:
        enc = app.demo_encryption(
            chunk_hash=None,
            api_key=ctx.api_key,
            x_client_id=ctx.main_client,
        )
        _assert(enc.get("status") == "ok", "demo encryption endpoint failed")

        ui_index = (repo_root / "ui" / "index.html").read_text(encoding="utf-8")
        ui_app_js = (repo_root / "ui" / "app.js").read_text(encoding="utf-8")
        _assert("Run Full Demo Story" in ui_index, "UI missing full-demo CTA")
        _assert("runFullDemo" in ui_app_js, "UI missing full-demo handler")
        return {
            "encryption_enabled": bool(enc.get("encryption_enabled")),
            "ui_hooks_present": True,
        }

    def scenario_8_status_and_metrics_summary() -> Dict[str, Any]:
        status = app.demo_status(limit=30)
        metrics = app.metrics()
        _assert(status.get("status") == "ok", "demo status endpoint failed")
        _assert(metrics.get("status") == "ok", "metrics endpoint failed")
        summary = status.get("summary", {})
        return {
            "active_clients": summary.get("active_clients"),
            "total_buffered_events": summary.get("total_buffered_events"),
            "metrics_keys": sorted((metrics.get("metrics") or {}).keys()),
        }

    scenario_defs: List[tuple[str, Callable[[], Optional[Dict[str, Any]]]]] = [
        ("Scenario 1 - Baseline Upload", scenario_1_baseline_upload),
        ("Scenario 2 - Duplicate Requires PoW", scenario_2_duplicate_requires_pow),
        ("Scenario 3 - PoW Solve And Retry", scenario_3_pow_solve_and_retry),
        ("Scenario 4 - Policy Enforcement And Recovery", scenario_4_policy_enforcement_and_recovery),
        ("Scenario 5 - File Version Update And Delete", scenario_5_file_version_update_delete),
        ("Scenario 6 - Ownership Transfer And Audit", scenario_6_ownership_transfer_and_audit),
        ("Scenario 7 - Encryption Status And UI Hooks", scenario_7_encryption_status_and_ui_hooks),
        ("Scenario 8 - Status And Metrics Summary", scenario_8_status_and_metrics_summary),
    ]

    results = [_run_scenario(name, fn) for name, fn in scenario_defs]

    passed = sum(1 for item in results if item.status == "PASS")
    failed = len(results) - passed
    generated_at = datetime.now(timezone.utc).isoformat()

    summary_payload = {
        "generated_at_utc": generated_at,
        "python_version": sys.version,
        "platform": platform.platform(),
        "repo_root": str(repo_root),
        "runtime_dir": str(runtime_dir),
        "total_scenarios": len(results),
        "passed": passed,
        "failed": failed,
        "results": [
            {
                "name": item.name,
                "status": item.status,
                "duration_ms": item.duration_ms,
                "detail": item.detail,
                "data": item.data,
                "metrics_before": item.metrics_before,
                "metrics_after": item.metrics_after,
                "metrics_delta": item.metrics_delta,
            }
            for item in results
        ],
    }

    md_path = reports_dir / f"scenario_suite_report_{stamp}.md"
    json_path = reports_dir / f"scenario_suite_report_{stamp}.json"
    csv_path = reports_dir / f"scenario_suite_metrics_{stamp}.csv"

    lines = [
        "# Secure Dedup Scenario Suite Report",
        "",
        f"- Generated (UTC): `{generated_at}`",
        f"- Python: `{platform.python_version()}`",
        f"- Platform: `{platform.platform()}`",
        f"- Repo: `{repo_root}`",
        f"- Isolated Runtime Dir: `{runtime_dir}`",
        f"- Summary: `{passed}/{len(results)}` passed, `{failed}` failed",
        "",
        "## Scenario Outcomes",
        "",
    ]

    for item in results:
        lines.append(f"- `{item.status}` {item.name} ({item.duration_ms} ms)")
        if item.detail:
            lines.append(f"  - Detail: `{item.detail}`")
        if item.data:
            lines.append(f"  - Data: `{json.dumps(item.data, ensure_ascii=True)}`")
        if item.metrics_delta:
            lines.append(f"  - Metrics Delta: `{json.dumps(item.metrics_delta, ensure_ascii=True)}`")

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    json_path.write_text(json.dumps(summary_payload, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")

    metric_keys = sorted({key for item in results for key in item.metrics_delta.keys()})
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["scenario", "status", "duration_ms"] + [f"delta_{key}" for key in metric_keys])
        for item in results:
            row = [item.name, item.status, item.duration_ms]
            for key in metric_keys:
                row.append(item.metrics_delta.get(key, 0))
            writer.writerow(row)

    print(f"Scenario report (md):  {md_path}")
    print(f"Scenario report (json): {json_path}")
    print(f"Scenario metrics csv:   {csv_path}")
    print(f"Summary: {passed}/{len(results)} passed, {failed} failed")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
