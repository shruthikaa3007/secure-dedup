import redis

# Connect to Redis
r = redis.Redis(
    host="localhost",
    port=6379,
    db=0,
    decode_responses=True
)

def chunk_exists(chunk_hash: str) -> bool:
    """
    Check if a chunk hash exists and is stored as a HASH
    """
    return r.type(chunk_hash) == "hash"


def register_chunk(chunk_hash: str):
    """
    Register a chunk or increase its reference count.
    Ensures chunk metadata is stored as a HASH.
    """
    key_type = r.type(chunk_hash)

    if key_type == "hash":
        # 🔁 Chunk already exists → increment ref_count
        r.hincrby(chunk_hash, "ref_count", 1)

    elif key_type == "none":
        # 🆕 New chunk → create hash
        r.hset(
            chunk_hash,
            mapping={
                "ref_count": 1
            }
        )

    else:
        # ⚠️ Old / incorrect key type (STRING etc.)
        # Delete and recreate properly
        r.delete(chunk_hash)
        r.hset(
            chunk_hash,
            mapping={
                "ref_count": 1
            }
        )


def get_ref_count(chunk_hash: str) -> int:
    """
    Get reference count of a chunk safely
    """
    if r.type(chunk_hash) != "hash":
        return 0

    count = r.hget(chunk_hash, "ref_count")
    return int(count) if count else 0
