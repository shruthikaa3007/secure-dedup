import json
import os
import sqlite3
import time
import uuid
from typing import Dict, List, Optional

DB_FILE = os.getenv("TELEMETRY_DB", "telemetry.db")


def _connect():
    return sqlite3.connect(DB_FILE)


def _ensure_tables() -> None:
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS file_versions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id TEXT NOT NULL,
                owner_client_id TEXT NOT NULL,
                file_name TEXT NOT NULL,
                version INTEGER NOT NULL,
                recipe_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at REAL NOT NULL,
                UNIQUE(file_id, version)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_file_versions_file_id_version
            ON file_versions (file_id, version)
            """
        )
        conn.commit()


def _latest_row(file_id: str):
    with _connect() as conn:
        row = conn.execute(
            """
            SELECT file_id, owner_client_id, file_name, version, recipe_json, status, created_at
            FROM file_versions
            WHERE file_id = ?
            ORDER BY version DESC
            LIMIT 1
            """,
            (file_id,),
        ).fetchone()
    return row


def create_file(owner_client_id: str, file_name: str, recipe: List[str]) -> Dict:
    file_id = str(uuid.uuid4())
    created_at = time.time()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO file_versions (file_id, owner_client_id, file_name, version, recipe_json, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (file_id, owner_client_id, file_name, 1, json.dumps(recipe), "active", created_at),
        )
        conn.commit()
    return {
        "file_id": file_id,
        "owner_client_id": owner_client_id,
        "file_name": file_name,
        "version": 1,
        "recipe": recipe,
        "status": "active",
        "created_at": created_at,
    }


def update_file(file_id: str, owner_client_id: str, recipe: List[str], file_name: Optional[str] = None) -> Dict:
    latest = get_file(file_id)
    if latest["owner_client_id"] != owner_client_id:
        raise PermissionError("Only the file owner can update the file")
    if latest["status"] != "active":
        raise ValueError("Cannot update a deleted file")

    next_version = latest["version"] + 1
    new_name = file_name or latest["file_name"]
    created_at = time.time()

    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO file_versions (file_id, owner_client_id, file_name, version, recipe_json, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (file_id, owner_client_id, new_name, next_version, json.dumps(recipe), "active", created_at),
        )
        conn.commit()

    return {
        "file_id": file_id,
        "owner_client_id": owner_client_id,
        "file_name": new_name,
        "version": next_version,
        "recipe": recipe,
        "status": "active",
        "created_at": created_at,
    }


def delete_file(file_id: str, owner_client_id: str) -> Dict:
    latest = get_file(file_id)
    if latest["owner_client_id"] != owner_client_id:
        raise PermissionError("Only the file owner can delete the file")
    if latest["status"] == "deleted":
        return latest

    next_version = latest["version"] + 1
    created_at = time.time()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO file_versions (file_id, owner_client_id, file_name, version, recipe_json, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (file_id, owner_client_id, latest["file_name"], next_version, json.dumps(latest["recipe"]), "deleted", created_at),
        )
        conn.commit()

    latest["version"] = next_version
    latest["status"] = "deleted"
    latest["created_at"] = created_at
    return latest


def get_file(file_id: str) -> Dict:
    row = _latest_row(file_id)
    if not row:
        raise KeyError("File not found")

    return {
        "file_id": row[0],
        "owner_client_id": row[1],
        "file_name": row[2],
        "version": int(row[3]),
        "recipe": json.loads(row[4]),
        "status": row[5],
        "created_at": float(row[6]),
    }


def list_files(owner_client_id: str) -> List[Dict]:
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT fv.file_id, fv.owner_client_id, fv.file_name, fv.version, fv.recipe_json, fv.status, fv.created_at
            FROM file_versions fv
            INNER JOIN (
                SELECT file_id, MAX(version) AS max_version
                FROM file_versions
                GROUP BY file_id
            ) latest ON latest.file_id = fv.file_id AND latest.max_version = fv.version
            WHERE fv.owner_client_id = ?
            ORDER BY fv.created_at DESC
            """,
            (owner_client_id,),
        ).fetchall()

    result = []
    for row in rows:
        result.append(
            {
                "file_id": row[0],
                "owner_client_id": row[1],
                "file_name": row[2],
                "version": int(row[3]),
                "recipe": json.loads(row[4]),
                "status": row[5],
                "created_at": float(row[6]),
            }
        )
    return result


_ensure_tables()
