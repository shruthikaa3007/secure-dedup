try:
    import pyfastcdc  # type: ignore
except Exception:
    pyfastcdc = None


def _fixed_chunks(data: bytes, chunk_size: int):
    chunks = []
    for i in range(0, len(data), chunk_size):
        chunk = data[i : i + chunk_size]
        if chunk:
            chunks.append(chunk)
    return chunks


def chunk_file(
    data: bytes,
    avg_size: int = 8 * 1024,
    min_size: int = 2 * 1024,
    max_size: int = 16 * 1024,
):
    """
    Content-defined chunking (FastCDC) with fixed-size fallback.
    """
    if not data:
        return []

    if pyfastcdc is None:
        return _fixed_chunks(data, chunk_size=avg_size)

    chunks = []
    for chunk in pyfastcdc.fastcdc(
        data,
        min_size=min_size,
        avg_size=avg_size,
        max_size=max_size,
    ):
        if chunk.data:
            chunks.append(chunk.data)

    if not chunks:
        return [data]
    return chunks
