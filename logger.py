import csv
import os
import sqlite3
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Deque, Dict

MAX_EVENTS_PER_CLIENT = int(os.getenv("MAX_EVENTS_PER_CLIENT", "5000"))
HYDRATE_EVENT_LIMIT = int(os.getenv("HYDRATE_EVENT_LIMIT", "50000"))

# In-memory log store (real-time cache)
REQUEST_LOGS: Dict[str, Deque[dict]] = defaultdict(
    lambda: deque(maxlen=MAX_EVENTS_PER_CLIENT)
)

CSV_FILE = "request_logs.csv"
DB_FILE = os.getenv("TELEMETRY_DB", "telemetry.db")

# CSV header
CSV_HEADER = [
    "timestamp",
    "client_id",
    "operation_type",
    "chunk_hash",
    "pow_result",
]


def _ensure_log_file() -> None:
    """
    Create log CSV with header only when it does not exist yet.
    This preserves historical logs across process restarts.
    """
    path = Path(CSV_FILE)
    if path.exists() and path.stat().st_size > 0:
        return
    with open(CSV_FILE, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(CSV_HEADER)


def _ensure_db() -> None:
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS request_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                client_id TEXT NOT NULL,
                operation_type TEXT NOT NULL,
                chunk_hash TEXT,
                pow_result TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_request_events_client_ts
            ON request_events (client_id, timestamp)
            """
        )
        conn.commit()


def _hydrate_recent_events() -> None:
    """
    Hydrate in-memory cache from durable event store.
    """
    if not Path(DB_FILE).exists():
        return

    with sqlite3.connect(DB_FILE) as conn:
        rows = conn.execute(
            """
            SELECT timestamp, client_id, operation_type, chunk_hash, pow_result
            FROM request_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (HYDRATE_EVENT_LIMIT,),
        ).fetchall()

    for ts, client_id, op_type, chunk_hash, pow_result in reversed(rows):
        REQUEST_LOGS[client_id].append(
            {
                "timestamp": float(ts),
                "client_id": client_id,
                "operation_type": op_type,
                "chunk_hash": chunk_hash,
                "pow_result": pow_result,
            }
        )


def _persist_event_db(
    ts: float,
    client_id: str,
    operation_type: str,
    chunk_hash,
    pow_result,
) -> None:
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            INSERT INTO request_events
                (timestamp, client_id, operation_type, chunk_hash, pow_result)
            VALUES (?, ?, ?, ?, ?)
            """,
            (ts, client_id, operation_type, chunk_hash, str(pow_result) if pow_result is not None else None),
        )
        conn.commit()


_ensure_log_file()
_ensure_db()
_hydrate_recent_events()


def log_request(client_id, operation_type, chunk_hash=None, pow_result=None):
    ts = time.time()

    entry = {
        "timestamp": ts,
        "client_id": client_id,
        "operation_type": operation_type,
        "chunk_hash": chunk_hash,
        "pow_result": pow_result,
    }

    # In-memory cache
    REQUEST_LOGS[client_id].append(entry)

    # Durable sqlite event store
    _persist_event_db(ts, client_id, operation_type, chunk_hash, pow_result)

    # CSV append (human-friendly export)
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(
            [
                ts,
                client_id,
                operation_type,
                chunk_hash,
                pow_result,
            ]
        )
