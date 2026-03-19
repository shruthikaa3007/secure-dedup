import os
from typing import Dict

try:
    import redis
except Exception:
    redis = None

REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))

r = None
if redis is not None:
    try:
        r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True,
        )
    except Exception:
        r = None

# Local fallback when Redis is unavailable.
_IN_MEMORY_REF_COUNTS: Dict[str, int] = {}


def _use_redis() -> bool:
    if r is None:
        return False
    try:
        r.ping()
        return True
    except Exception:
        return False


def chunk_exists(chunk_hash: str) -> bool:
    """
    Check if a chunk hash exists and is stored as a HASH.
    """
    if _use_redis():
        return r.type(chunk_hash) == "hash"
    return chunk_hash in _IN_MEMORY_REF_COUNTS


def register_chunk(chunk_hash: str):
    """
    Register a chunk or increase its reference count.
    """
    if _use_redis():
        key_type = r.type(chunk_hash)

        if key_type == "hash":
            r.hincrby(chunk_hash, "ref_count", 1)
        elif key_type == "none":
            r.hset(chunk_hash, mapping={"ref_count": 1})
        else:
            r.delete(chunk_hash)
            r.hset(chunk_hash, mapping={"ref_count": 1})
        return

    _IN_MEMORY_REF_COUNTS[chunk_hash] = _IN_MEMORY_REF_COUNTS.get(chunk_hash, 0) + 1


def get_ref_count(chunk_hash: str) -> int:
    """
    Get reference count of a chunk safely.
    """
    if _use_redis():
        if r.type(chunk_hash) != "hash":
            return 0

        count = r.hget(chunk_hash, "ref_count")
        return int(count) if count else 0

    return int(_IN_MEMORY_REF_COUNTS.get(chunk_hash, 0))



def decrement_chunk_ref(chunk_hash: str) -> int:
    """
    Decrease chunk reference count and return resulting count.
    Removes the index entry when count reaches zero.
    """
    if _use_redis():
        if r.type(chunk_hash) != "hash":
            return 0

        count = r.hget(chunk_hash, "ref_count")
        current = int(count) if count else 0
        if current <= 1:
            r.delete(chunk_hash)
            return 0

        r.hincrby(chunk_hash, "ref_count", -1)
        return current - 1

    current = int(_IN_MEMORY_REF_COUNTS.get(chunk_hash, 0))
    if current <= 1:
        _IN_MEMORY_REF_COUNTS.pop(chunk_hash, None)
        return 0

    _IN_MEMORY_REF_COUNTS[chunk_hash] = current - 1
    return current - 1
