import csv
import json
import os
import sqlite3
import time
from typing import Dict, Optional

from db_utils import resolve_db_file

FILE = "detection_results.csv"
DB_FILE = resolve_db_file(os.getenv("TELEMETRY_DB", "telemetry.db"))


def _ensure_feature_table() -> None:
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS feature_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                client_id TEXT NOT NULL,
                features_json TEXT NOT NULL,
                is_anomaly INTEGER,
                attack_label TEXT,
                risk_score REAL,
                policy_action TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_feature_snapshots_client_ts
            ON feature_snapshots (client_id, timestamp)
            """
        )
        conn.commit()


def _persist_feature_snapshot(
    client_id: str,
    features: Dict,
    anomaly: Optional[bool],
    label: Optional[str],
    risk_score: Optional[float],
    policy_action: Optional[str],
) -> None:
    with sqlite3.connect(DB_FILE) as conn:
        conn.execute(
            """
            INSERT INTO feature_snapshots
                (timestamp, client_id, features_json, is_anomaly, attack_label, risk_score, policy_action)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                time.time(),
                client_id,
                json.dumps(features),
                int(bool(anomaly)) if anomaly is not None else None,
                label,
                risk_score,
                policy_action,
            ),
        )
        conn.commit()


_ensure_feature_table()


def save_features(
    client_id,
    features,
    anomaly=None,
    label=None,
    risk_score: Optional[float] = None,
    policy_action: Optional[str] = None,
):
    file_exists = os.path.isfile(FILE)

    with open(FILE, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow(
                ["client_id"] + list(features.keys()) + ["is_anomaly", "attack_label"]
            )

        writer.writerow([client_id] + list(features.values()) + [anomaly, label])

    _persist_feature_snapshot(
        client_id=client_id,
        features=features,
        anomaly=anomaly,
        label=label,
        risk_score=risk_score,
        policy_action=policy_action,
    )
