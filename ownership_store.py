import os
import sqlite3
import time
from typing import Dict, List

from db_utils import resolve_db_file

DB_FILE = resolve_db_file(os.getenv("TELEMETRY_DB", "telemetry.db"))


def _connect():
    return sqlite3.connect(DB_FILE)


def _ensure_tables() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS chunk_owners (
                chunk_hash TEXT NOT NULL,
                client_id TEXT NOT NULL,
                created_at REAL NOT NULL,
                PRIMARY KEY (chunk_hash, client_id)
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ownership_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                event_type TEXT NOT NULL,
                chunk_hash TEXT NOT NULL,
                actor_client_id TEXT NOT NULL,
                target_client_id TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_ownership_events_chunk_ts
            ON ownership_events (chunk_hash, timestamp)
            """
        )
        conn.commit()


def _event(event_type: str, chunk_hash: str, actor_client_id: str, target_client_id: str = None) -> None:
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO ownership_events (timestamp, event_type, chunk_hash, actor_client_id, target_client_id)
            VALUES (?, ?, ?, ?, ?)
            """,
            (time.time(), event_type, chunk_hash, actor_client_id, target_client_id),
        )
        conn.commit()


def add_owner(chunk_hash: str, client_id: str, actor_client_id: str = None) -> None:
    actor = actor_client_id or client_id
    with _connect() as conn:
        conn.execute(
            """
            INSERT OR IGNORE INTO chunk_owners (chunk_hash, client_id, created_at)
            VALUES (?, ?, ?)
            """,
            (chunk_hash, client_id, time.time()),
        )
        conn.commit()
    _event("grant", chunk_hash, actor, client_id)


def remove_owner(chunk_hash: str, client_id: str, actor_client_id: str = None) -> None:
    actor = actor_client_id or client_id
    with _connect() as conn:
        conn.execute(
            "DELETE FROM chunk_owners WHERE chunk_hash = ? AND client_id = ?",
            (chunk_hash, client_id),
        )
        conn.commit()
    _event("revoke", chunk_hash, actor, client_id)


def transfer_owner(chunk_hash: str, from_client_id: str, to_client_id: str, actor_client_id: str) -> None:
    with _connect() as conn:
        conn.execute(
            "DELETE FROM chunk_owners WHERE chunk_hash = ? AND client_id = ?",
            (chunk_hash, from_client_id),
        )
        conn.execute(
            """
            INSERT OR IGNORE INTO chunk_owners (chunk_hash, client_id, created_at)
            VALUES (?, ?, ?)
            """,
            (chunk_hash, to_client_id, time.time()),
        )
        conn.commit()
    _event("transfer", chunk_hash, actor_client_id, to_client_id)


def is_owner(chunk_hash: str, client_id: str) -> bool:
    with _connect() as conn:
        row = conn.execute(
            "SELECT 1 FROM chunk_owners WHERE chunk_hash = ? AND client_id = ? LIMIT 1",
            (chunk_hash, client_id),
        ).fetchone()
    return row is not None


def list_owners(chunk_hash: str) -> List[str]:
    with _connect() as conn:
        rows = conn.execute(
            "SELECT client_id FROM chunk_owners WHERE chunk_hash = ? ORDER BY client_id",
            (chunk_hash,),
        ).fetchall()
    return [row[0] for row in rows]


def ownership_summary(chunk_hash: str) -> Dict:
    owners = list_owners(chunk_hash)
    return {"chunk_hash": chunk_hash, "owners": owners, "owner_count": len(owners)}


_ensure_tables()
