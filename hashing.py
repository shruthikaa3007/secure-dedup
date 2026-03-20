import base64
import hashlib
import hmac
import os

_DEMO_DEFAULT_FINGERPRINT_KEY_B64 = "c2VjdXJlLWRlZHVwLWZpbmdlcnByaW50LWtleSEhISE="


def _is_truthy(raw: str, default: bool = False) -> bool:
    if raw is None:
        return default
    return str(raw).strip().lower() in {"1", "true", "yes", "on"}


def dedup_fingerprint_mode() -> str:
    mode = os.getenv("DEDUP_FINGERPRINT_MODE", "sha256").strip().lower()
    if mode not in {"sha256", "secret_hmac"}:
        return "sha256"
    return mode


def _resolve_fingerprint_key_material() -> tuple[str, str]:
    raw = os.getenv("DEDUP_FINGERPRINT_KEY", "").strip()
    if raw:
        return raw, "env"

    demo_mode = _is_truthy(os.getenv("DEMO_MODE", "true"), default=True)
    default_on = _is_truthy(os.getenv("DEDUP_FINGERPRINT_DEFAULT_ON", "true"), default=True)
    if demo_mode and default_on:
        return _DEMO_DEFAULT_FINGERPRINT_KEY_B64, "demo_default"

    return "", "disabled"


def _load_fingerprint_key() -> bytes:
    raw, _ = _resolve_fingerprint_key_material()
    if not raw:
        return b""

    try:
        key = base64.b64decode(raw, validate=True)
    except Exception as exc:
        raise ValueError("DEDUP_FINGERPRINT_KEY must be valid base64") from exc

    if len(key) < 16:
        raise ValueError("DEDUP_FINGERPRINT_KEY must decode to at least 16 bytes")
    return key


def fingerprint_status() -> dict:
    mode = dedup_fingerprint_mode()
    try:
        _, key_source = _resolve_fingerprint_key_material()
        key = _load_fingerprint_key()
        return {
            "mode": mode,
            "key_source": key_source,
            "key_bytes": len(key) if key else 0,
        }
    except Exception as exc:
        return {
            "mode": mode,
            "key_source": "error",
            "key_bytes": 0,
            "error": str(exc),
        }


def hash_chunk(chunk: bytes) -> str:
    if dedup_fingerprint_mode() == "secret_hmac":
        key = _load_fingerprint_key()
        if not key:
            raise ValueError("DEDUP_FINGERPRINT_MODE=secret_hmac requires a fingerprint key")
        return hmac.new(key, chunk, hashlib.sha256).hexdigest()

    sha = hashlib.sha256()
    sha.update(chunk)
    return sha.hexdigest()
