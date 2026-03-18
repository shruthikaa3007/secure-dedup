import os

import uvicorn


def _port() -> int:
    raw = os.getenv("PORT", "8080").strip()
    try:
        return int(raw)
    except Exception:
        return 8080


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=_port())
