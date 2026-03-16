import base64
import hashlib
import hmac
import os
import struct
from typing import Optional

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

_MAGIC = b"SDENC3"
_NONCE_LEN = 12
_TAG_LEN = 16
_SEGMENT_SIZE_DEFAULT = 4096
_LEN_STRUCT = struct.Struct(">I")


def _load_key() -> bytes:
    raw = os.getenv("CHUNK_ENCRYPTION_KEY", "").strip()
    if not raw:
        return b""

    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError("CHUNK_ENCRYPTION_KEY must be valid base64") from exc

    if len(key) not in {16, 24, 32}:
        raise ValueError("CHUNK_ENCRYPTION_KEY must decode to 16/24/32 bytes for AES")
    return key


def _strict_mode() -> bool:
    return os.getenv("CHUNK_ENCRYPTION_STRICT", "false").strip().lower() in {"1", "true", "yes", "on"}


def _segment_size() -> int:
    raw = os.getenv("CHUNK_ENCRYPTION_SEGMENT_SIZE", str(_SEGMENT_SIZE_DEFAULT)).strip()
    try:
        size = int(raw)
    except Exception as exc:
        raise ValueError("CHUNK_ENCRYPTION_SEGMENT_SIZE must be an integer") from exc
    if size < 256:
        raise ValueError("CHUNK_ENCRYPTION_SEGMENT_SIZE must be >= 256")
    return size


def _derive_content_key(master_key: bytes, context: Optional[str]) -> bytes:
    if not context:
        return master_key
    digest = hmac.new(master_key, context.encode("utf-8"), hashlib.sha256).digest()
    return digest[: len(master_key)]


def _aad_bytes(context: Optional[str], segment_index: int) -> bytes:
    prefix = f"chunk_hash:{context or ''}".encode("utf-8")
    return prefix + b"|seg:" + str(segment_index).encode("ascii")


def encryption_enabled() -> bool:
    return bool(_load_key())


def encrypt_chunk(data: bytes, context: Optional[str] = None) -> bytes:
    master_key = _load_key()
    if not master_key:
        return data

    key = _derive_content_key(master_key, context)
    seg_size = _segment_size()
    out = bytearray()
    out.extend(_MAGIC)

    segment_count = 0
    for idx, start in enumerate(range(0, len(data), seg_size)):
        segment = data[start:start + seg_size]
        nonce = get_random_bytes(_NONCE_LEN)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(_aad_bytes(context, idx))
        ciphertext, tag = cipher.encrypt_and_digest(segment)

        out.extend(_LEN_STRUCT.pack(len(ciphertext)))
        out.extend(nonce)
        out.extend(tag)
        out.extend(ciphertext)
        segment_count += 1

    if len(data) == 0:
        out.extend(_LEN_STRUCT.pack(0))

    return bytes(out)


def decrypt_chunk(data: bytes, context: Optional[str] = None) -> bytes:
    master_key = _load_key()
    if not master_key:
        return data

    if not data.startswith(_MAGIC):
        if _strict_mode():
            raise ValueError("Encrypted mode enabled but stored chunk is not encrypted with current format")
        return data

    key = _derive_content_key(master_key, context)
    pos = len(_MAGIC)
    plain = bytearray()
    seg_idx = 0

    if pos + _LEN_STRUCT.size == len(data):
        clen = _LEN_STRUCT.unpack_from(data, pos)[0]
        if clen == 0:
            return b""

    while pos < len(data):
        if pos + _LEN_STRUCT.size > len(data):
            raise ValueError("Encrypted chunk payload is malformed (missing segment length)")
        ciphertext_len = _LEN_STRUCT.unpack_from(data, pos)[0]
        pos += _LEN_STRUCT.size

        if ciphertext_len == 0 and pos == len(data):
            return bytes(plain)

        end = pos + _NONCE_LEN + _TAG_LEN + ciphertext_len
        if end > len(data):
            raise ValueError("Encrypted chunk payload is malformed (segment bounds)")

        nonce = data[pos: pos + _NONCE_LEN]
        tag = data[pos + _NONCE_LEN: pos + _NONCE_LEN + _TAG_LEN]
        ciphertext = data[pos + _NONCE_LEN + _TAG_LEN: end]
        pos = end

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(_aad_bytes(context, seg_idx))
        plain.extend(cipher.decrypt_and_verify(ciphertext, tag))
        seg_idx += 1

    return bytes(plain)


def generate_key_b64(num_bytes: int = 32) -> str:
    if num_bytes not in {16, 24, 32}:
        raise ValueError("num_bytes must be one of 16, 24, 32")
    return base64.b64encode(get_random_bytes(num_bytes)).decode("ascii")
