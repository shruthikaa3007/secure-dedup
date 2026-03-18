import sqlite3
from pathlib import Path


def resolve_db_file(raw_path: str, fallback_name: str = "telemetry.db") -> str:
    candidates = [Path(raw_path), Path(f"/tmp/{fallback_name}"), Path(fallback_name)]
    seen = set()

    for candidate in candidates:
        key = str(candidate)
        if key in seen:
            continue
        seen.add(key)

        parent = candidate.parent if str(candidate.parent) else Path(".")
        try:
            parent.mkdir(parents=True, exist_ok=True)
            with sqlite3.connect(candidate) as conn:
                conn.execute("SELECT 1")
            return str(candidate)
        except (OSError, sqlite3.Error):
            continue

    return fallback_name
