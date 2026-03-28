from __future__ import annotations

try:
    import boto3
    from botocore.config import Config as BotoConfig
    from botocore.exceptions import ClientError
except Exception as exc:  # pragma: no cover - import guard for bare environments
    boto3 = None
    BotoConfig = None
    ClientError = Exception
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

from src.config import AWS_ACCESS_KEY_ID, AWS_REGION, AWS_SECRET_ACCESS_KEY, LOCALSTACK_ENDPOINT, S3_BUCKET

_S3_CLIENT = None


def _require_boto3() -> None:
    if boto3 is None:
        raise RuntimeError("boto3 is required for LocalStack S3 integration") from _IMPORT_ERROR


def get_s3_client():
    global _S3_CLIENT
    if _S3_CLIENT is not None:
        return _S3_CLIENT
    _require_boto3()
    config = None
    if BotoConfig is not None:
        config = BotoConfig(s3={"addressing_style": "path"}, connect_timeout=1, read_timeout=1, retries={"max_attempts": 0})
    _S3_CLIENT = boto3.client(
        "s3",
        endpoint_url=LOCALSTACK_ENDPOINT,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
        config=config,
    )
    return _S3_CLIENT


def ensure_bucket() -> None:
    client = get_s3_client()
    try:
        client.head_bucket(Bucket=S3_BUCKET)
    except Exception:
        client.create_bucket(Bucket=S3_BUCKET)


def upload_ciphertext(tag: str, ciphertext: bytes, metadata: dict) -> str:
    ensure_bucket()
    key = f"{tag}.bin"
    normalized_metadata = {str(name): str(value) for name, value in metadata.items()}
    get_s3_client().put_object(
        Bucket=S3_BUCKET,
        Key=key,
        Body=ciphertext,
        ContentType="application/octet-stream",
        Metadata=normalized_metadata,
    )
    return key


def download_ciphertext(tag: str) -> bytes:
    ensure_bucket()
    key = f"{tag}.bin"
    response = get_s3_client().get_object(Bucket=S3_BUCKET, Key=key)
    try:
        return response["Body"].read()
    finally:
        response["Body"].close()


def ciphertext_exists(tag: str) -> bool:
    ensure_bucket()
    key = f"{tag}.bin"
    try:
        get_s3_client().head_object(Bucket=S3_BUCKET, Key=key)
        return True
    except Exception:
        return False


def update_ciphertext(tag: str, new_ciphertext: bytes) -> None:
    upload_ciphertext(tag, new_ciphertext, metadata={"updated": "true"})
