# import pyfastcdc

# def chunk_file(data: bytes, avg_size=8192):
#     """
#     Content-defined chunking using FastCDC.
#     avg_size = expected average chunk size (8 KB default)
#     """
#     chunks = []

#     for chunk in pyfastcdc.fastcdc(data, avg_size=avg_size):
#         chunk_data = chunk.data
#         if chunk_data:
#             chunks.append(chunk_data)

#     # Safety fallback (should rarely happen)
#     if not chunks and data:
#         chunks = [data]

#     return chunks

def chunk_file(data: bytes, chunk_size: int = 8 * 1024):
    """
    Split file into fixed-size chunks (default: 8 KB)
    """
    chunks = []

    for i in range(0, len(data), chunk_size):
        chunk = data[i:i + chunk_size]
        if len(chunk) > 0:
            chunks.append(chunk)

    return chunks
