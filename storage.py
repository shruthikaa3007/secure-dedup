import os
import time
from io import BytesIO
from pathlib import Path

from encryption import decrypt_chunk, encrypt_chunk, payload_uses_envelope

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
_S3_RETRY_INTERVAL_SEC = float(os.getenv("S3_INIT_RETRY_INTERVAL_SEC", "2.0"))
_MINIO_RETRY_INTERVAL_SEC = float(os.getenv("MINIO_INIT_RETRY_INTERVAL_SEC", "2.0"))
_last_s3_init_attempt = 0.0
_last_minio_init_attempt = 0.0


def _init_local_store_dir() -> Path:
    preferred = _LOCAL_STORE_DIR
    fallback = Path("/tmp/local_chunks")

    for candidate in (preferred, fallback):
        try:
            candidate.mkdir(parents=True, exist_ok=True)
            return candidate
        except OSError:
            continue

    # Last-resort fallback to repository-relative path.
    final_fallback = Path("local_chunks")
    final_fallback.mkdir(parents=True, exist_ok=True)
    return final_fallback

_s3_client = None
_minio_client = None


def _now() -> float:
    return time.time()


def _init_s3_client():
    global _s3_client, _last_s3_init_attempt
    if _s3_client is not None:
        return _s3_client
    if STORAGE_BACKEND not in {"auto", "localstack", "s3"} or boto3 is None:
        return None
    if (_now() - _last_s3_init_attempt) < _S3_RETRY_INTERVAL_SEC:
        return None

    _last_s3_init_attempt = _now()
    try:
        endpoint_url = LOCALSTACK_ENDPOINT if STORAGE_BACKEND in {"auto", "localstack"} else None
        s3_config = BotoConfig(s3={"addressing_style": "path"}) if BotoConfig is not None else None
        client = boto3.client(
            "s3",
            endpoint_url=endpoint_url,
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION,
            config=s3_config,
        )

        try:
            client.head_bucket(Bucket=BUCKET)
        except Exception:
            client.create_bucket(Bucket=BUCKET)

        _s3_client = client
    except Exception:
        _s3_client = None
    return _s3_client


def _init_minio_client():
    global _minio_client, _last_minio_init_attempt
    if _minio_client is not None:
        return _minio_client
    if STORAGE_BACKEND not in {"auto", "minio"} or Minio is None:
        return None
    if (_now() - _last_minio_init_attempt) < _MINIO_RETRY_INTERVAL_SEC:
        return None

    _last_minio_init_attempt = _now()
    try:
        client = Minio(
            MINIO_ENDPOINT,
            access_key=MINIO_ACCESS_KEY,
            secret_key=MINIO_SECRET_KEY,
            secure=MINIO_SECURE,
        )
        if not client.bucket_exists(BUCKET):
            client.make_bucket(BUCKET)
        _minio_client = client
    except Exception:
        _minio_client = None
    return _minio_client


def _ensure_backend_clients():
    global _LOCAL_STORE_DIR
    _init_s3_client()
    if _s3_client is None:
        _init_minio_client()
    if _s3_client is None and _minio_client is None:
        _LOCAL_STORE_DIR = _init_local_store_dir()


_ensure_backend_clients()


def storage_status() -> dict:
    _ensure_backend_clients()
    if _s3_client is not None:
        return {
            "backend": "localstack" if STORAGE_BACKEND == "localstack" else "s3",
            "configured_backend": STORAGE_BACKEND,
            "bucket": BUCKET,
            "endpoint": LOCALSTACK_ENDPOINT if STORAGE_BACKEND == "localstack" else None,
            "local_dir": str(_LOCAL_STORE_DIR),
            "fallback_active": False,
        }
    if _minio_client is not None:
        return {
            "backend": "minio",
            "configured_backend": STORAGE_BACKEND,
            "bucket": BUCKET,
            "endpoint": MINIO_ENDPOINT,
            "local_dir": str(_LOCAL_STORE_DIR),
            "fallback_active": False,
        }
    return {
        "backend": "filesystem",
        "configured_backend": STORAGE_BACKEND,
        "bucket": None,
        "endpoint": None,
        "local_dir": str(_LOCAL_STORE_DIR),
        "fallback_active": STORAGE_BACKEND in {"auto", "localstack", "s3", "minio"},
    }


def upload_chunk(chunk_hash: str, data: bytes):
    """
    Store chunk in object storage backend, fallback to local filesystem.
    """
    _ensure_backend_clients()
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


def get_chunk_raw(chunk_hash: str) -> bytes:
    """
    Retrieve raw stored chunk from backend without decryption.
    """
    _ensure_backend_clients()
    if _s3_client is not None:
        response = _s3_client.get_object(Bucket=BUCKET, Key=chunk_hash)
        try:
            return response["Body"].read()
        finally:
            response["Body"].close()

    if _minio_client is not None:
        response = _minio_client.get_object(BUCKET, chunk_hash)
        try:
            return response.read()
        finally:
            response.close()
            response.release_conn()

    path = _LOCAL_STORE_DIR / chunk_hash
    if not path.exists():
        raise FileNotFoundError(f"Chunk not found: {chunk_hash}")
    return path.read_bytes()


def get_chunk(chunk_hash: str) -> bytes:
    """
    Retrieve stored chunk from backend.
    """
    raw = get_chunk_raw(chunk_hash)
    return decrypt_chunk(raw, context=chunk_hash)



def delete_chunk(chunk_hash: str) -> None:
    """
    Delete chunk from storage backend if present.
    """
    _ensure_backend_clients()
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


def get_chunk_envelope_info(chunk_hash: str):
    """Inspect stored payload envelope without decrypting chunk contents."""
    _ensure_backend_clients()
    if _s3_client is not None:
        response = _s3_client.get_object(Bucket=BUCKET, Key=chunk_hash)
        try:
            payload = response["Body"].read()
        except Exception as exc:
            raise FileNotFoundError(f"Chunk not found: {chunk_hash}") from exc
        finally:
            response["Body"].close()
        return {
            "backend": "s3",
            "exists": True,
            "encrypted_envelope": payload_uses_envelope(payload),
            "stored_size": len(payload),
        }

    if _minio_client is not None:
        try:
            response = _minio_client.get_object(BUCKET, chunk_hash)
        except Exception as exc:
            raise FileNotFoundError(f"Chunk not found: {chunk_hash}") from exc
        try:
            payload = response.read()
        finally:
            response.close()
            response.release_conn()
        return {
            "backend": "minio",
            "exists": True,
            "encrypted_envelope": payload_uses_envelope(payload),
            "stored_size": len(payload),
        }

    path = _LOCAL_STORE_DIR / chunk_hash
    if not path.exists():
        raise FileNotFoundError(f"Chunk not found: {chunk_hash}")
    payload = path.read_bytes()
    return {
        "backend": "filesystem",
        "exists": True,
        "encrypted_envelope": payload_uses_envelope(payload),
        "stored_size": len(payload),
    }
