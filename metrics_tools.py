import csv
import os
import sqlite3
from typing import Dict

from logger import REQUEST_LOGS

DB_FILE = os.getenv("TELEMETRY_DB", "telemetry.db")
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


def runtime_metrics_snapshot() -> Dict:
    requests_total = sum(len(events) for events in REQUEST_LOGS.values())
    with sqlite3.connect(DB_FILE) as conn:
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
        }
    return metrics
