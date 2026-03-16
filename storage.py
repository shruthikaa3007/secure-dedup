import os
from io import BytesIO
from pathlib import Path

from encryption import decrypt_chunk, encrypt_chunk

try:
    import boto3
    from botocore.config import Config as BotoConfig
except Exception:
    boto3 = None
    BotoConfig = None

try:
    from minio import Minio
except Exception:
    Minio = None

STORAGE_BACKEND = os.getenv("STORAGE_BACKEND", "auto").lower()

LOCALSTACK_ENDPOINT = os.getenv("LOCALSTACK_ENDPOINT", "http://127.0.0.1:4566")
AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID", "test")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY", "test")
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

MINIO_ENDPOINT = os.getenv("MINIO_ENDPOINT", "localhost:9000")
MINIO_ACCESS_KEY = os.getenv("MINIO_ACCESS_KEY", "minioadmin")
MINIO_SECRET_KEY = os.getenv("MINIO_SECRET_KEY", "minioadmin")
MINIO_SECURE = os.getenv("MINIO_SECURE", "false").lower() == "true"

BUCKET = os.getenv("S3_BUCKET", os.getenv("MINIO_BUCKET", "chunks"))

_LOCAL_STORE_DIR = Path(os.getenv("LOCAL_CHUNK_DIR", "local_chunks"))

_s3_client = None
if STORAGE_BACKEND in {"auto", "localstack", "s3"} and boto3 is not None:
    try:
        endpoint_url = LOCALSTACK_ENDPOINT if STORAGE_BACKEND in {"auto", "localstack"} else None
        s3_config = BotoConfig(s3={"addressing_style": "path"}) if BotoConfig is not None else None
        _s3_client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION,
            config=s3_config,
        )

        try:
            _s3_client.head_bucket(Bucket=BUCKET)
        except Exception:
            _s3_client.create_bucket(Bucket=BUCKET)
    except Exception:
        _s3_client = None

_minio_client = None
if _s3_client is None and STORAGE_BACKEND in {"auto", "minio"} and Minio is not None:
    try:
        _minio_client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        if not _minio_client.bucket_exists(BUCKET):
            _minio_client.make_bucket(BUCKET)
    except Exception:
        _minio_client = None

if _s3_client is None and _minio_client is None:
    _LOCAL_STORE_DIR.mkdir(parents=True, exist_ok=True)


def upload_chunk(chunk_hash: str, data: bytes):
    """
    Store chunk in object storage backend, fallback to local filesystem.
    """
    payload = encrypt_chunk(data, context=chunk_hash)

    if _s3_client is not None:
        _s3_client.put_object(
            Bucket=BUCKET,
            Key=chunk_hash,
            Body=payload,
            ContentType="application/octet-stream",
        )
        return

    if _minio_client is not None:
        _minio_client.put_object(
            BUCKET,
            chunk_hash,
            BytesIO(payload),
            length=len(payload),
            content_type="application/octet-stream",
        )
        return

    (_LOCAL_STORE_DIR / chunk_hash).write_bytes(payload)


def get_chunk(chunk_hash: str) -> bytes:
    """
    Retrieve stored chunk from backend.
    """
    if _s3_client is not None:
        response = _s3_client.get_object(Bucket=BUCKET, Key=chunk_hash)
        try:
            return decrypt_chunk(response["Body"].read(), context=chunk_hash)
        finally:
            response["Body"].close()

    if _minio_client is not None:
        response = _minio_client.get_object(BUCKET, chunk_hash)
        try:
            return decrypt_chunk(response.read(), context=chunk_hash)
        finally:
            response.close()
            response.release_conn()

    path = _LOCAL_STORE_DIR / chunk_hash
    if not path.exists():
        raise FileNotFoundError(f"Chunk not found: {chunk_hash}")
    return decrypt_chunk(path.read_bytes(), context=chunk_hash)



def delete_chunk(chunk_hash: str) -> None:
    """
    Delete chunk from storage backend if present.
    """
    if _s3_client is not None:
        try:
            _s3_client.delete_object(Bucket=BUCKET, Key=chunk_hash)
        except Exception:
            pass
        return

    if _minio_client is not None:
        try:
            _minio_client.remove_object(BUCKET, chunk_hash)
        except Exception:
            pass
        return

    path = _LOCAL_STORE_DIR / chunk_hash
    if path.exists():
        path.unlink()
