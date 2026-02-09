from minio import Minio
from io import BytesIO

client = Minio(
    "localhost:9000",
    access_key="minioadmin",
    secret_key="minioadmin",
    secure=False
)

BUCKET = "chunks"

# Ensure bucket exists
if not client.bucket_exists(BUCKET):
    client.make_bucket(BUCKET)


def upload_chunk(chunk_hash: str, data: bytes):
    """
    Store chunk in MinIO using hash as object name
    """
    client.put_object(
        BUCKET,
        chunk_hash,
        BytesIO(data),
        length=len(data),
        content_type="application/octet-stream"
    )


def get_chunk(chunk_hash: str) -> bytes:
    """
    Retrieve stored chunk from MinIO (needed for PoW verification)
    """
    response = client.get_object(BUCKET, chunk_hash)
    try:
        return response.read()
    finally:
        response.close()
        response.release_conn()
