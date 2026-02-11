import os
from io import BytesIO
from pathlib import Path

try:
    from minio import Minio
except Exception:
    Minio = None

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"
BUCKET = os.getenv("MINIO_BUCKET", "chunks")

_LOCAL_STORE_DIR = Path(os.getenv("LOCAL_CHUNK_DIR", "local_chunks"))

client = None
if Minio is not None:
    try:
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        if not client.bucket_exists(BUCKET):
            client.make_bucket(BUCKET)
    except Exception:
        client = None

if client is None:
    _LOCAL_STORE_DIR.mkdir(parents=True, exist_ok=True)


def upload_chunk(chunk_hash: str, data: bytes):
    """
    Store chunk in MinIO/S3-compatible backend, fallback to local filesystem.
    """
    if client is not None:
        client.put_object(
            BUCKET,
            chunk_hash,
            BytesIO(data),
            length=len(data),
            content_type="application/octet-stream",
        )
        return

    (_LOCAL_STORE_DIR / chunk_hash).write_bytes(data)


def get_chunk(chunk_hash: str) -> bytes:
    """
    Retrieve stored chunk from backend.
    """
    if client is not None:
        response = client.get_object(BUCKET, chunk_hash)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    path = _LOCAL_STORE_DIR / chunk_hash
    if not path.exists():
        raise FileNotFoundError(f"Chunk not found: {chunk_hash}")
    return path.read_bytes()
