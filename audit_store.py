import hashlib
import os
import random
import sqlite3
import time
import uuid
from typing import Dict, Optional

from db_utils import resolve_db_file

from dedup_index import chunk_exists
from pow import compute_proof
from storage import get_chunk

DB_FILE = resolve_db_file(os.getenv("TELEMETRY_DB", "telemetry.db"))
AUDIT_CHALLENGE_TTL_SEC = int(os.getenv("AUDIT_CHALLENGE_TTL_SEC", "300"))




def _connect():
    return sqlite3.connect(DB_FILE)


def _ensure_tables() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_challenges (
                challenge_id TEXT PRIMARY KEY,
                chunk_hash TEXT NOT NULL,
                nonce_hex TEXT NOT NULL,
                offset INTEGER NOT NULL,
                length INTEGER NOT NULL,
                expected_proof TEXT NOT NULL,
                created_at REAL NOT NULL,
                expires_at REAL NOT NULL,
                status TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                chunk_hash TEXT NOT NULL,
                challenge_id TEXT,
                event_type TEXT NOT NULL,
                result TEXT,
                metadata_json TEXT
            )
            """
        )
        conn.commit()


def _log_event(chunk_hash: str, event_type: str, result: Optional[str] = None, challenge_id: Optional[str] = None, metadata_json: Optional[str] = None):
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_events (timestamp, chunk_hash, challenge_id, event_type, result, metadata_json)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (time.time(), chunk_hash, challenge_id, event_type, result, metadata_json),
        )
        conn.commit()


def create_audit_challenge(chunk_hash: str, length: int = 32) -> Dict:
    if not chunk_exists(chunk_hash):
        raise FileNotFoundError("Chunk not found")

    chunk = get_chunk(chunk_hash)
    challenge_len = max(8, min(length, len(chunk)))
    max_offset = max(0, len(chunk) - challenge_len)
    offset = random.randint(0, max_offset) if max_offset > 0 else 0
    nonce = os.urandom(16)

    expected = compute_proof(chunk, nonce, offset, challenge_len)
    challenge_id = str(uuid.uuid4())
    now = time.time()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO audit_challenges
            (challenge_id, chunk_hash, nonce_hex, offset, length, expected_proof, created_at, expires_at, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                challenge_id,
                chunk_hash,
                nonce.hex(),
                offset,
                challenge_len,
                expected,
                now,
                now + AUDIT_CHALLENGE_TTL_SEC,
                "open",
            ),
        )
        conn.commit()

    _log_event(chunk_hash, "challenge_created", challenge_id=challenge_id, result="open")

    return {
        "challenge_id": challenge_id,
        "chunk_hash": chunk_hash,
        "nonce_hex": nonce.hex(),
        "offset": offset,
        "length": challenge_len,
        "expires_at": now + AUDIT_CHALLENGE_TTL_SEC,
    }


def verify_audit_challenge(challenge_id: str, proof: str) -> Dict:
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT chunk_hash, expected_proof, expires_at, status
            FROM audit_challenges
            WHERE challenge_id = ?
            """,
            (challenge_id,),
        ).fetchone()

        if not row:
            raise KeyError("Challenge not found")

        chunk_hash, expected_proof, expires_at, status = row
        now = time.time()
        if status != "open":
            ok = False
            result = "already_used"
        elif now > float(expires_at):
            ok = False
            result = "expired"
        elif proof == expected_proof:
            ok = True
            result = "verified"
        else:
            ok = False
            result = "invalid"

        conn.execute(
            "UPDATE audit_challenges SET status = ? WHERE challenge_id = ?",
            (result, challenge_id),
        )
        conn.commit()

    _log_event(chunk_hash, "challenge_verified", result=result, challenge_id=challenge_id)
    return {"challenge_id": challenge_id, "chunk_hash": chunk_hash, "verified": ok, "result": result}


def quick_audit(chunk_hash: str) -> Dict:
    if not chunk_exists(chunk_hash):
        return {"chunk_hash": chunk_hash, "integrity": "missing"}

    data = get_chunk(chunk_hash)
    digest = hashlib.sha256(data).hexdigest()
    _log_event(chunk_hash, "quick_audit", result="ok")
    return {"chunk_hash": chunk_hash, "integrity": "ok", "size": len(data), "sha256": digest}


_ensure_tables()
