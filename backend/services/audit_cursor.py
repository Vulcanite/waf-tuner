"""Atomic persistent cursor for the ModSecurity serial JSON audit log."""
import base64
import json
import os
from pathlib import Path

from services.runtime_config import data_dir


def cursor_path() -> Path:
    return Path(os.environ.get("AUDIT_CURSOR_PATH") or data_dir() / "audit_cursor.json")


def load_cursor() -> dict:
    path = cursor_path()
    try:
        data = json.loads(path.read_text())
        if not isinstance(data, dict) or not isinstance(data.get("offset"), int) or data["offset"] < 0:
            raise ValueError("invalid audit cursor")
        data["pending"] = base64.b64decode(data.pop("pending_b64", ""), validate=True)
        # Older cursors used the same buffer for EOF retries and partial input.
        data.setdefault("retry_pending", bool(data["pending"]))
        # Event lines now come from the database.
        data.pop("next_event_line", None)
        return data
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return {
            "device": None,
            "inode": None,
            "offset": 0,
            "pending": b"",
        }


def save_cursor(cursor: dict) -> None:
    path = cursor_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    serializable = {key: value for key, value in cursor.items() if key != "pending"}
    serializable["pending_b64"] = base64.b64encode(cursor.get("pending", b"")).decode("ascii")
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w") as handle:
        json.dump(serializable, handle, separators=(",", ":"))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)
