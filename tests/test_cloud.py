import io

from src.cloud import dynamo_client, s3_client


class FakeBody:
    def __init__(self, data: bytes):
        self._buffer = io.BytesIO(data)

    def read(self) -> bytes:
        return self._buffer.read()

    def close(self) -> None:
        self._buffer.close()


class FakeS3:
    def __init__(self):
        self.bucket_created = False
        self.objects = {}

    def head_bucket(self, Bucket):
        if not self.bucket_created:
            raise RuntimeError("missing bucket")

    def create_bucket(self, Bucket):
        self.bucket_created = True

    def put_object(self, Bucket, Key, Body, ContentType, Metadata=None):
        self.objects[Key] = Body

    def get_object(self, Bucket, Key):
        return {"Body": FakeBody(self.objects[Key])}

    def head_object(self, Bucket, Key):
        if Key not in self.objects:
            raise RuntimeError("missing object")


class FakeTable:
    def __init__(self, key_name: str):
        self.key_name = key_name
        self.items = {}

    def get_item(self, Key):
        key = Key[self.key_name]
        if key in self.items:
            return {"Item": self.items[key]}
        return {}

    def put_item(self, Item):
        self.items[Item[self.key_name]] = Item
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def update_item(self, Key, UpdateExpression, ExpressionAttributeValues, ReturnValues):
        key = Key[self.key_name]
        item = self.items.setdefault(key, {self.key_name: key})
        if "rotation_count" in UpdateExpression:
            current = item.get("rotation_count", 0)
            item["rotation_count"] = current + 1
            item["last_rotation_at"] = ExpressionAttributeValues[":ts"]
        else:
            current_uploads = item.get("upload_count", 0)
            current_owners = item.get("owner_count", 0)
            item["upload_count"] = current_uploads + 1
            item["owner_count"] = current_owners + 1
        item["updated_at"] = ExpressionAttributeValues[":ts"]
        self.items[key] = item
        return {"Attributes": item}

    def delete_item(self, Key):
        self.items.pop(Key[self.key_name], None)

    def scan(self, FilterExpression=None):
        return {"Items": list(self.items.values())}


class FakeTables:
    def __init__(self):
        self.tables = {
            dynamo_client.DYNAMO_DTABLE: FakeTable("chunk_tag"),
            dynamo_client.DYNAMO_UTABLE: FakeTable("user_id"),
            dynamo_client.DYNAMO_AUDIT: FakeTable("session_id"),
            dynamo_client.DYNAMO_EPOCH: FakeTable("epoch_id"),
        }

    def __call__(self, name: str):
        return self.tables[name]


def test_s3_client_crud(monkeypatch):
    fake = FakeS3()
    monkeypatch.setattr(s3_client, "_S3_CLIENT", fake)
    monkeypatch.setattr(s3_client, "get_s3_client", lambda: fake)
    s3_client.ensure_bucket()
    key = s3_client.upload_ciphertext("chunk-a", b"cipher", {"epoch": 1})
    assert key == "chunk-a.bin"
    assert s3_client.ciphertext_exists("chunk-a") is True
    assert s3_client.download_ciphertext("chunk-a") == b"cipher"
    s3_client.update_ciphertext("chunk-a", b"cipher-2")
    assert s3_client.download_ciphertext("chunk-a") == b"cipher-2"


def test_dynamo_client_crud(monkeypatch):
    fake_tables = FakeTables()
    monkeypatch.setattr(dynamo_client, "bootstrap_tables", lambda: None)
    monkeypatch.setattr(dynamo_client, "_table", fake_tables)

    dynamo_client.dtable_put("chunk-a", "chunk-a.bin", 1, T_M=5)
    assert dynamo_client.dtable_get("chunk-a")["s3_key"] == "chunk-a.bin"
    updated = dynamo_client.dtable_increment_counter("chunk-a")
    assert int(updated["upload_count"]) == 2
    assert int(updated["owner_count"]) == 2
    rotated = dynamo_client.dtable_mark_rotation("chunk-a")
    assert int(rotated["rotation_count"]) == 1
    assert dynamo_client.dtable_count() == 1

    dynamo_client.utable_add_ownership("user-a", "handle-a", "locator-a", b"token", 1)
    ownership = dynamo_client.utable_get_user_chunks("user-a")
    assert ownership[0]["chunk_tag"] == "handle-a"
    assert ownership[0]["chunk_locator"] == "locator-a"
    assert ownership[0]["ownership_token_t"] == b"token"

    dynamo_client.audit_log_write("session-a", "user-a", {"tau_avg": 100.0}, 5, {"is_anomalous": False}, 1)
    history = dynamo_client.audit_log_get_user_history("user-a")
    assert history[0]["session_id"] == "session-a"

    dynamo_client.epoch_store(1, b"epoch-key")
    expired = dynamo_client.epoch_expire(1)
    assert expired["expired"] is True
