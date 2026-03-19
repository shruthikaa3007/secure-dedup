import csv
import json
import os
import sqlite3
from typing import Dict, List

from db_utils import resolve_db_file
from encryption import encryption_status

from logger import REQUEST_LOGS

DB_FILE = resolve_db_file(os.getenv("TELEMETRY_DB", "telemetry.db"))
DETECTION_FILE = "detection_results.csv"


def _count_csv_rows(path: str) -> int:
    if not os.path.exists(path):
        return 0
    with open(path, newline="") as f:
        reader = csv.reader(f)
        count = -1
        for count, _ in enumerate(reader):
            pass
    return max(0, count)


def _safe_sql_count(conn: sqlite3.Connection, query: str) -> int:
    try:
        row = conn.execute(query).fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception:
        return 0


def _safe_sql_count_with_param(conn: sqlite3.Connection, query: str, params: tuple) -> int:
    try:
        row = conn.execute(query, params).fetchone()
        return int(row[0]) if row and row[0] is not None else 0
    except Exception:
        return 0


def _latest_file_recipes(conn: sqlite3.Connection) -> List[Dict]:
    try:
        rows = conn.execute(
            """
            SELECT fv.file_id, fv.file_name, fv.version, fv.recipe_json, fv.status
            FROM file_versions fv
            INNER JOIN (
                SELECT file_id, MAX(version) AS max_version
                FROM file_versions
                GROUP BY file_id
            ) latest
                ON latest.file_id = fv.file_id AND latest.max_version = fv.version
            ORDER BY fv.file_id
            """
        ).fetchall()
    except Exception:
        return []

    records = []
    for file_id, file_name, version, recipe_json, status in rows:
        try:
            recipe = json.loads(recipe_json)
        except Exception:
            recipe = []
        records.append(
            {
                "file_id": file_id,
                "file_name": file_name,
                "version": int(version),
                "recipe": recipe if isinstance(recipe, list) else [],
                "status": status,
            }
        )
    return records


def runtime_metrics_snapshot() -> Dict:
    requests_total = sum(len(events) for events in REQUEST_LOGS.values())
    with sqlite3.connect(DB_FILE) as conn:
        latest_files = _latest_file_recipes(conn)
        active_files = [item for item in latest_files if item.get("status") == "active"]
        logical_chunks = sum(len(item.get("recipe", [])) for item in active_files)
        unique_chunks = len({chunk_hash for item in active_files for chunk_hash in item.get("recipe", [])})
        pow_challenges = _safe_sql_count_with_param(
            conn,
            "SELECT COUNT(*) FROM request_events WHERE operation_type = ?",
            ("pow_challenge",),
        )
        pow_verified = _safe_sql_count_with_param(
            conn,
            "SELECT COUNT(*) FROM request_events WHERE operation_type = ? AND pow_result = ?",
            ("pow_verify", "True"),
        )
        pow_rejected = _safe_sql_count_with_param(
            conn,
            "SELECT COUNT(*) FROM request_events WHERE operation_type = ? AND pow_result = ?",
            ("pow_verify", "False"),
        )
        metrics = {
            "clients_seen": len(REQUEST_LOGS),
            "requests_seen": requests_total,
            "detection_results_rows": _count_csv_rows(DETECTION_FILE),
            "feature_snapshots": _safe_sql_count(conn, "SELECT COUNT(*) FROM feature_snapshots"),
            "file_versions": _safe_sql_count(conn, "SELECT COUNT(*) FROM file_versions"),
            "owned_chunk_links": _safe_sql_count(conn, "SELECT COUNT(*) FROM chunk_owners"),
            "ownership_events": _safe_sql_count(conn, "SELECT COUNT(*) FROM ownership_events"),
            "audit_challenges": _safe_sql_count(conn, "SELECT COUNT(*) FROM audit_challenges"),
            "audit_events": _safe_sql_count(conn, "SELECT COUNT(*) FROM audit_events"),
            "active_files": len(active_files),
            "logical_chunks": logical_chunks,
            "unique_chunks": unique_chunks,
            "dedup_saved_chunks": max(0, logical_chunks - unique_chunks),
            "pow_challenges": pow_challenges,
            "pow_verified": pow_verified,
            "pow_rejected": pow_rejected,
        }
    return metrics


def runtime_metrics_summary() -> Dict:
    requests_total = sum(len(events) for events in REQUEST_LOGS.values())
    with sqlite3.connect(DB_FILE) as conn:
        latest_files = _latest_file_recipes(conn)
        active_files = [item for item in latest_files if item.get("status") == "active"]
        logical_chunks = sum(len(item.get("recipe", [])) for item in active_files)
        unique_chunks = len({chunk_hash for item in active_files for chunk_hash in item.get("recipe", [])})
        dedup_saved_chunks = max(0, logical_chunks - unique_chunks)
        dedup_saved_percent = round((dedup_saved_chunks / logical_chunks) * 100.0, 2) if logical_chunks else 0.0

        pow_challenges = _safe_sql_count_with_param(
            conn,
            "SELECT COUNT(*) FROM request_events WHERE operation_type = ?",
            ("pow_challenge",),
        )
        pow_verified = _safe_sql_count_with_param(
            conn,
            "SELECT COUNT(*) FROM request_events WHERE operation_type = ? AND pow_result = ?",
            ("pow_verify", "True"),
        )
        pow_rejected = _safe_sql_count_with_param(
            conn,
            "SELECT COUNT(*) FROM request_events WHERE operation_type = ? AND pow_result = ?",
            ("pow_verify", "False"),
        )

        summary = {
            "definition": {
                "project_name": "Secure Encrypted Dedup with PoW Ownership Checks",
                "focus": "Store encrypted chunks once and verify duplicate claims with proof-of-ownership.",
                "base_paper": "Peng et al., IEEE TNSM 2025",
            },
            "storage": {
                "active_files": len(active_files),
                "logical_chunks": logical_chunks,
                "unique_chunks": unique_chunks,
                "dedup_saved_chunks": dedup_saved_chunks,
                "dedup_saved_percent": dedup_saved_percent,
            },
            "pow": {
                "challenges_issued": pow_challenges,
                "proofs_verified": pow_verified,
                "proofs_rejected": pow_rejected,
            },
            "encryption": {
                **encryption_status(),
                "mode": "chunk-hash-bound segmented AES-GCM",
            },
            "activity": {
                "clients_seen": len(REQUEST_LOGS),
                "requests_seen": requests_total,
                "owner_links": _safe_sql_count(conn, "SELECT COUNT(*) FROM chunk_owners"),
            },
        }
    return summary
