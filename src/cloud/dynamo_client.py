from __future__ import annotations

import base64
import time
from decimal import Decimal

try:
    import boto3
    from boto3.dynamodb.conditions import Attr
    from botocore.config import Config as BotoConfig
except Exception as exc:  # pragma: no cover - import guard for bare environments
    boto3 = None
    Attr = None
    BotoConfig = None
    _IMPORT_ERROR = exc
else:
    _IMPORT_ERROR = None

from src.config import (
    AWS_ACCESS_KEY_ID,
    AWS_REGION,
    AWS_SECRET_ACCESS_KEY,
    DYNAMO_AUDIT,
    DYNAMO_DTABLE,
    DYNAMO_EPOCH,
    DYNAMO_UTABLE,
    LOCALSTACK_ENDPOINT,
)

_DYNAMODB = None


TABLE_DEFINITIONS = {
    DYNAMO_DTABLE: "chunk_tag",
    DYNAMO_UTABLE: "user_id",
    DYNAMO_AUDIT: "session_id",
    DYNAMO_EPOCH: "epoch_id",
}


def _require_boto3() -> None:
    if boto3 is None:
        raise RuntimeError("boto3 is required for LocalStack DynamoDB integration") from _IMPORT_ERROR


def get_dynamodb_resource():
    global _DYNAMODB
    if _DYNAMODB is not None:
        return _DYNAMODB
    _require_boto3()
    config = None
    if BotoConfig is not None:
        config = BotoConfig(connect_timeout=1, read_timeout=1, retries={"max_attempts": 0})
    _DYNAMODB = boto3.resource(
        "dynamodb",
        endpoint_url=LOCALSTACK_ENDPOINT,
        region_name=AWS_REGION,
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        config=config,
    )
    return _DYNAMODB


def bootstrap_tables() -> None:
    resource = get_dynamodb_resource()
    client = resource.meta.client
    existing = set(client.list_tables().get("TableNames", []))
    for table_name, hash_key in TABLE_DEFINITIONS.items():
        if table_name in existing:
            continue
        table = resource.create_table(
            TableName=table_name,
            KeySchema=[{"AttributeName": hash_key, "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": hash_key, "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        table.wait_until_exists()


def _table(name: str):
    bootstrap_tables()
    return get_dynamodb_resource().Table(name)


def _normalize(value):
    if isinstance(value, bytes):
        return base64.b64encode(value).decode("ascii")
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, float):
        return Decimal(str(value))
    if isinstance(value, list):
        return [_normalize(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalize(item) for key, item in value.items()}
    return value


def _restore(value):
    if isinstance(value, list):
        return [_restore(item) for item in value]
    if isinstance(value, dict):
        return {key: _restore(item) for key, item in value.items()}
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def dtable_get(chunk_tag: str) -> dict | None:
    item = _table(DYNAMO_DTABLE).get_item(Key={"chunk_tag": chunk_tag}).get("Item")
    return _restore(item) if item else None


def dtable_put(chunk_tag: str, s3_key: str, epoch: int, T_M: int = 5):
    item = {
        "chunk_tag": chunk_tag,
        "s3_key": s3_key,
        "upload_count": 1,
        "T_M": T_M,
        "epoch": epoch,
        "updated_at": int(time.time()),
    }
    _table(DYNAMO_DTABLE).put_item(Item=_normalize(item))
    return item


def dtable_increment_counter(chunk_tag: str) -> dict:
    table = _table(DYNAMO_DTABLE)
    result = table.update_item(
        Key={"chunk_tag": chunk_tag},
        UpdateExpression="SET upload_count = if_not_exists(upload_count, :zero) + :inc, updated_at = :ts",
        ExpressionAttributeValues={
            ":zero": Decimal(0),
            ":inc": Decimal(1),
            ":ts": Decimal(int(time.time())),
        },
        ReturnValues="ALL_NEW",
    )
    return _restore(result["Attributes"])


def utable_add_ownership(user_id: str, chunk_tag: str, t: bytes, epoch: int):
    table = _table(DYNAMO_UTABLE)
    existing = table.get_item(Key={"user_id": user_id}).get("Item") or {"user_id": user_id, "chunks": []}
    chunks = _restore(existing.get("chunks", []))
    updated_chunks = [chunk for chunk in chunks if chunk.get("chunk_tag") != chunk_tag]
    updated_chunks.append(
        {
            "chunk_tag": chunk_tag,
            "ownership_token_t": base64.b64encode(t).decode("ascii"),
            "epoch": epoch,
            "updated_at": int(time.time()),
        }
    )
    item = {"user_id": user_id, "chunks": updated_chunks}
    table.put_item(Item=_normalize(item))
    return item


def utable_get_user_chunks(user_id: str) -> list[dict]:
    item = _table(DYNAMO_UTABLE).get_item(Key={"user_id": user_id}).get("Item")
    if not item:
        return []
    restored = _restore(item)
    chunks = restored.get("chunks", [])
    for chunk in chunks:
        token = chunk.get("ownership_token_t")
        if isinstance(token, str):
            chunk["ownership_token_t"] = base64.b64decode(token)
    return chunks


def utable_revoke_ownership(user_id: str, chunk_tag: str):
    table = _table(DYNAMO_UTABLE)
    chunks = [chunk for chunk in utable_get_user_chunks(user_id) if chunk.get("chunk_tag") != chunk_tag]
    if chunks:
        item = {"user_id": user_id, "chunks": chunks}
        table.put_item(Item=_normalize(item))
        return item
    table.delete_item(Key={"user_id": user_id})
    return {"user_id": user_id, "chunks": []}


def audit_log_write(session_id: str, user_id: str, B_vector: dict, nonce: int, anomaly_report: dict, epoch: int):
    item = {
        "session_id": session_id,
        "user_id": user_id,
        "B_vector": B_vector,
        "nonce": nonce,
        "anomaly_report": anomaly_report,
        "epoch": epoch,
        "timestamp": int(time.time()),
    }
    _table(DYNAMO_AUDIT).put_item(Item=_normalize(item))
    return item


def audit_log_get_user_history(user_id: str, limit: int = 20) -> list[dict]:
    table = _table(DYNAMO_AUDIT)
    if Attr is None:
        return []
    response = table.scan(FilterExpression=Attr("user_id").eq(user_id))
    items = [_restore(item) for item in response.get("Items", [])]
    items.sort(key=lambda item: item.get("timestamp", 0), reverse=True)
    return items[:limit]


def epoch_store(epoch_id: int, ks_public_scalar: bytes):
    item = {
        "epoch_id": str(epoch_id),
        "ks_public_scalar": base64.b64encode(ks_public_scalar).decode("ascii"),
        "created_at": int(time.time()),
        "expired": False,
    }
    _table(DYNAMO_EPOCH).put_item(Item=_normalize(item))
    return item


def epoch_expire(epoch_id: int):
    table = _table(DYNAMO_EPOCH)
    record = table.get_item(Key={"epoch_id": str(epoch_id)}).get("Item")
    item = _restore(record) if record else {"epoch_id": str(epoch_id)}
    item["expired"] = True
    item["expired_at"] = int(time.time())
    table.put_item(Item=_normalize(item))
    return item
