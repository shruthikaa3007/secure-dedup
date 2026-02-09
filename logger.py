import csv
import time
from collections import defaultdict, deque

# In-memory log store (for real-time)
REQUEST_LOGS = defaultdict(deque)

CSV_FILE = "request_logs.csv"

# CSV header
CSV_HEADER = [
    "timestamp",
    "client_id",
    "operation_type",
    "chunk_hash",
    "pow_result"
]

# Initialize CSV
with open(CSV_FILE, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(CSV_HEADER)


def log_request(client_id, operation_type, chunk_hash=None, pow_result=None):
    ts = time.time()

    entry = {
        "timestamp": ts,
        "client_id": client_id,
        "operation_type": operation_type,
        "chunk_hash": chunk_hash,
        "pow_result": pow_result
    }

    # Store in memory
    REQUEST_LOGS[client_id].append(entry)

    # Append to CSV
    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            ts,
            client_id,
            operation_type,
            chunk_hash,
            pow_result
        ])
