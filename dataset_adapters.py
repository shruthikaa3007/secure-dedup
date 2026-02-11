"""
Dataset ingestion adapters that map external traces into the project's
request log schema:

timestamp,client_id,operation_type,chunk_hash,pow_result

These adapters provide deterministic mappings for initial experimentation.
"""

import argparse
import csv
import hashlib
import os
import tarfile
from collections import defaultdict
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

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


def _csv_writer(output_path: str):
    f = open(output_path, "w", newline="", encoding="utf-8")
    writer = csv.DictWriter(f, fieldnames=REQUEST_LOG_COLUMNS)
    writer.writeheader()
    return f, writer


def _map_read_write_to_operation(
    client_id: str,
    block_id: str,
    block_size: str,
    op_code: str,
    seen_chunks: Dict[str, set],
) -> Dict:
    chunk_hash = _hash_text(f"{block_id}:{block_size}")
    op_upper = op_code.upper()

    if op_upper.startswith("W"):
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

    return {
        "chunk_hash": chunk_hash,
        "operation_type": op_type,
        "pow_result": pow_result,
    }


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

            mapped = _map_read_write_to_operation(
                client_id=client_id,
                block_id=block_addr,
                block_size=size,
                op_code=op_raw,
                seen_chunks=seen_chunks,
            )

            events.append(
                {
                    "timestamp": ts,
                    "client_id": client_id,
                    "operation_type": mapped["operation_type"],
                    "chunk_hash": mapped["chunk_hash"],
                    "pow_result": mapped["pow_result"],
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


def _parse_revised_line(line: str) -> Optional[Tuple[float, str, str, str]]:
    # Format example:
    # 0.000003475 WS 161165712 8 seq 6.6711e-05 0.000050407 0
    parts = line.strip().split()
    if len(parts) < 4:
        return None
    try:
        ts = float(parts[0])
    except ValueError:
        return None

    op_code = parts[1]
    block_id = parts[2]
    block_size = parts[3]
    return ts, op_code, block_id, block_size


def adapt_revised_tar(
    input_path: str,
    output_path: str,
    max_files: int = 0,
    max_events: int = 0,
    max_events_per_file: int = 0,
    time_offset_sec: float = 86400.0,
) -> None:
    """
    Adapt FIU/MSRC .tar archives that contain final-trace/*.revised files.

    Args:
      max_files: 0 means all files.
      max_events: 0 means all events.
      max_events_per_file: 0 means all events per source trace file.
      time_offset_sec: offset added per trace file to avoid full overlap.
    """
    seen_chunks = defaultdict(set)
    total_events = 0
    file_count = 0
    stop = False

    out_f, writer = _csv_writer(output_path)
    try:
        with tarfile.open(input_path, mode="r") as tar:
            for member in tar:
                if not member.isfile() or not member.name.endswith(".revised"):
                    continue

                file_count += 1
                if max_files and file_count > max_files:
                    break

                client_id = os.path.basename(member.name).replace(".revised", "")
                member_file = tar.extractfile(member)
                if member_file is None:
                    continue

                ts_offset = (file_count - 1) * time_offset_sec
                file_events = 0

                for raw in member_file:
                    line = raw.decode("utf-8", errors="ignore")
                    parsed = _parse_revised_line(line)
                    if parsed is None:
                        continue

                    ts, op_code, block_id, block_size = parsed
                    mapped = _map_read_write_to_operation(
                        client_id=client_id,
                        block_id=block_id,
                        block_size=block_size,
                        op_code=op_code,
                        seen_chunks=seen_chunks,
                    )

                    writer.writerow(
                        {
                            "timestamp": ts + ts_offset,
                            "client_id": client_id,
                            "operation_type": mapped["operation_type"],
                            "chunk_hash": mapped["chunk_hash"],
                            "pow_result": mapped["pow_result"],
                        }
                    )
                    total_events += 1
                    file_events += 1

                    if max_events_per_file and file_events >= max_events_per_file:
                        break

                    if max_events and total_events >= max_events:
                        stop = True
                        break

                if stop:
                    break
    finally:
        out_f.close()

    print(
        f"Adapted revised tar: files={min(file_count, max_files) if max_files else file_count}, "
        f"events={total_events}, output={output_path}"
    )


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

    rev = sub.add_parser("revised-tar", help="Adapt FIU/MSRC revised trace tar")
    rev.add_argument("--input", required=True)
    rev.add_argument("--output", default="request_logs.csv")
    rev.add_argument("--max-files", type=int, default=0, help="0 means all")
    rev.add_argument("--max-events", type=int, default=0, help="0 means all")
    rev.add_argument(
        "--max-events-per-file",
        type=int,
        default=0,
        help="0 means all events per source .revised file",
    )
    rev.add_argument(
        "--time-offset-sec",
        type=float,
        default=86400.0,
        help="Timestamp offset added per source trace file",
    )

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
    elif args.command == "revised-tar":
        adapt_revised_tar(
            input_path=args.input,
            output_path=args.output,
            max_files=args.max_files,
            max_events=args.max_events,
            max_events_per_file=args.max_events_per_file,
            time_offset_sec=args.time_offset_sec,
        )
    else:
        raise ValueError(f"Unsupported command: {args.command}")

    print(f"Adapter output written to: {args.output}")


if __name__ == "__main__":
    main()
