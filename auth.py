import hashlib
import os
from typing import Optional

from fastapi import HTTPException

REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() == "true"
_VALID_KEYS = {
    key.strip()
    for key in os.getenv("API_KEYS", "dev-api-key").split(",")
    if key.strip()
}


def _sanitize_client_id(client_id: str) -> str:
    allowed = "-_"
    cleaned = "".join(ch for ch in client_id if ch.isalnum() or ch in allowed)
    return cleaned[:64] if cleaned else ""


def validate_api_key(x_api_key: Optional[str]) -> str:
    """
    Validate API key and return the normalized key.
    """
    if not REQUIRE_API_KEY:
        return x_api_key.strip() if x_api_key else ""

    if not x_api_key:
        raise HTTPException(status_code=401, detail={"error": "Missing X-API-Key header"})

    key = x_api_key.strip()
    if key not in _VALID_KEYS:
        raise HTTPException(status_code=401, detail={"error": "Invalid API key"})

    return key


def resolve_client_id(
    x_client_id: Optional[str],
    filename: Optional[str],
    api_key: str,
) -> str:
    """
    Resolve stable client identity. Priority:
    1) explicit X-Client-ID header,
    2) stable derivation from API key + filename fallback.
    """
    if x_client_id:
        cleaned = _sanitize_client_id(x_client_id.strip())
        if cleaned:
            return cleaned

    if api_key:
        digest = hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:12]
        return f"client_{digest}"

    file_source = filename or "anonymous-file"
    digest = hashlib.sha256(file_source.encode("utf-8")).hexdigest()[:12]
    return f"client_{digest}"
