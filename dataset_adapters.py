"""
Dataset ingestion adapters that map external traces into the project's
request log schema:

timestamp,client_id,operation_type,chunk_hash,pow_result

These adapters provide deterministic, transparent mappings for initial
experimentation and can be refined per dataset specifics.
"""

import argparse
import csv
import hashlib
from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional

REQUEST_LOG_COLUMNS = [
    "timestamp",
    "client_id",
    "operation_type",
    "chunk_hash",
    "pow_result",
]


def _hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _safe_float(value: Optional[str], default: float = 0.0) -> float:
    if value is None:
        return default
    value = str(value).strip()
    if not value:
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _parse_timestamp(value: Optional[str]) -> float:
    if value is None:
        return 0.0
    raw = str(value).strip()
    if not raw:
        return 0.0

    try:
        numeric = float(raw)
        # heuristics: ms epoch
        if numeric > 1e12:
            return numeric / 1000.0
        return numeric
    except ValueError:
        pass

    for fmt in (
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%d/%m/%Y %H:%M",
        "%m/%d/%Y %H:%M",
    ):
        try:
            return datetime.strptime(raw, fmt).timestamp()
        except ValueError:
            continue
    return 0.0


def _write_request_logs(rows: Iterable[Dict], output_path: str) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=REQUEST_LOG_COLUMNS)
        writer.writeheader()
        for row in rows:
            writer.writerow({col: row.get(col, "") for col in REQUEST_LOG_COLUMNS})


def adapt_azure_functions_invocations(input_path: str, output_path: str) -> None:
    """
    Map Azure Functions invocation trace rows to dedup request events.

    Expected columns: app, func, end_timestamp, duration
    """
    events: List[Dict] = []
    seen_func_per_app = set()

    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            app = (row.get("app") or "unknown_app").strip()
            func = (row.get("func") or "unknown_func").strip()
            ts = _parse_timestamp(row.get("end_timestamp") or row.get("timestamp"))
            duration = _safe_float(row.get("duration"), default=0.0)

            chunk_hash = _hash_text(f"{app}:{func}")
            events.append(
                {
                    "timestamp": ts,
                    "client_id": app,
                    "operation_type": "hash_query",
                    "chunk_hash": chunk_hash,
                    "pow_result": "",
                }
            )

            key = (app, func)
            if key not in seen_func_per_app:
                seen_func_per_app.add(key)
                events.append(
                    {
                        "timestamp": ts + 0.0001,
                        "client_id": app,
                        "operation_type": "upload_chunk",
                        "chunk_hash": chunk_hash,
                        "pow_result": "N/A",
                    }
                )
            elif duration > 0:
                events.append(
                    {
                        "timestamp": ts + 0.0002,
                        "client_id": app,
                        "operation_type": "pow",
                        "chunk_hash": chunk_hash,
                        "pow_result": True,
                    }
                )

    events.sort(key=lambda x: (float(x["timestamp"]), str(x["client_id"])))
    _write_request_logs(events, output_path)


def adapt_block_trace(
    input_path: str,
    output_path: str,
    timestamp_col: str,
    client_col: str,
    block_col: str,
    op_col: str,
    size_col: Optional[str],
) -> None:
    """
    Generic block trace adapter for FIU/MSRC-like CSV exports.
    """
    events: List[Dict] = []
    seen_chunks = defaultdict(set)

    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            client_id = (row.get(client_col) or "trace_client").strip() or "trace_client"
            ts = _parse_timestamp(row.get(timestamp_col))
            block_addr = str(row.get(block_col) or "").strip()
            size = str(row.get(size_col) or "") if size_col else ""
            op_raw = str(row.get(op_col) or "").strip().lower()

            if not block_addr:
                continue

            chunk_hash = _hash_text(f"{block_addr}:{size}")

            if op_raw in {"w", "write", "wr", "put"}:
                if chunk_hash in seen_chunks[client_id]:
                    op_type = "pow"
                    pow_result = True
                else:
                    seen_chunks[client_id].add(chunk_hash)
                    op_type = "upload_chunk"
                    pow_result = "N/A"
            else:
                op_type = "hash_query"
                pow_result = ""

            events.append(
                {
                    "timestamp": ts,
                    "client_id": client_id,
                    "operation_type": op_type,
                    "chunk_hash": chunk_hash,
                    "pow_result": pow_result,
                }
            )

    events.sort(key=lambda x: (float(x["timestamp"]), str(x["client_id"])))
    _write_request_logs(events, output_path)


def adapt_cic_flow(input_path: str, output_path: str) -> None:
    """
    Map CIC-style network flow CSVs into dedup-like request events.
    """
    events: List[Dict] = []
    seen_dest = defaultdict(set)

    with open(input_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        cols = {c.lower(): c for c in (reader.fieldnames or [])}

        ts_col = cols.get("timestamp") or cols.get("flow start")
        src_col = cols.get("src ip") or cols.get("source ip")
        dst_col = cols.get("dst ip") or cols.get("destination ip")
        port_col = cols.get("dst port") or cols.get("destination port")
        label_col = cols.get("label")

        for row in reader:
            client_id = (row.get(src_col) if src_col else None) or "flow_client"
            ts = _parse_timestamp(row.get(ts_col) if ts_col else None)
            dst = (row.get(dst_col) if dst_col else "unknown_dst")
            dport = (row.get(port_col) if port_col else "0")
            label = (row.get(label_col) if label_col else "normal").lower()

            chunk_hash = _hash_text(f"{dst}:{dport}")
            if "dos" in label or "ddos" in label or "attack" in label:
                op_type = "pow"
                pow_result = False
            elif chunk_hash not in seen_dest[client_id]:
                seen_dest[client_id].add(chunk_hash)
                op_type = "upload_chunk"
                pow_result = "N/A"
            else:
                op_type = "hash_query"
                pow_result = ""

            events.append(
                {
                    "timestamp": ts,
                    "client_id": client_id,
                    "operation_type": op_type,
                    "chunk_hash": chunk_hash,
                    "pow_result": pow_result,
                }
            )

    events.sort(key=lambda x: (float(x["timestamp"]), str(x["client_id"])))
    _write_request_logs(events, output_path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="External dataset adapters")
    sub = parser.add_subparsers(dest="command", required=True)

    az = sub.add_parser("azure-invocations", help="Adapt Azure Functions invocation traces")
    az.add_argument("--input", required=True)
    az.add_argument("--output", default="request_logs.csv")

    blk = sub.add_parser("block-trace", help="Adapt generic block trace CSV")
    blk.add_argument("--input", required=True)
    blk.add_argument("--output", default="request_logs.csv")
    blk.add_argument("--timestamp-col", default="timestamp")
    blk.add_argument("--client-col", default="client_id")
    blk.add_argument("--block-col", default="block")
    blk.add_argument("--op-col", default="op")
    blk.add_argument("--size-col", default="size")

    cic = sub.add_parser("cic-flow", help="Adapt CIC-style flow CSV")
    cic.add_argument("--input", required=True)
    cic.add_argument("--output", default="request_logs.csv")

    return parser.parse_args()


def main() -> None:
    args = parse_args()

    if args.command == "azure-invocations":
        adapt_azure_functions_invocations(args.input, args.output)
    elif args.command == "block-trace":
        adapt_block_trace(
            args.input,
            args.output,
            timestamp_col=args.timestamp_col,
            client_col=args.client_col,
            block_col=args.block_col,
            op_col=args.op_col,
            size_col=args.size_col,
        )
    elif args.command == "cic-flow":
        adapt_cic_flow(args.input, args.output)
    else:
        raise ValueError(f"Unsupported command: {args.command}")

    print(f"Adapter output written to: {args.output}")


if __name__ == "__main__":
    main()
