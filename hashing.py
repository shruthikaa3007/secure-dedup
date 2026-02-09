import hashlib

def hash_chunk(chunk: bytes) -> str:
    sha = hashlib.sha256()
    sha.update(chunk)
    return sha.hexdigest()
