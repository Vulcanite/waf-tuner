"""Atomic persistent cursor for the ModSecurity serial JSON audit log."""
import base64
import json
import os
from pathlib import Path


def cursor_path() -> Path:
    default = Path(os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")).parent / "audit_cursor.json"
    return Path(os.environ.get("AUDIT_CURSOR_PATH", default))


def count_lines(path: str) -> int:
    try:
        with open(path, "rb") as handle:
            return sum(chunk.count(b"\n") for chunk in iter(lambda: handle.read(1024 * 1024), b""))
    except FileNotFoundError:
        return 0


def load_cursor(events_path: str) -> dict:
    path = cursor_path()
    try:
        data = json.loads(path.read_text())
        data["pending"] = base64.b64decode(data.pop("pending_b64", ""))
        data.setdefault("next_event_line", count_lines(events_path))
        return data
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return {
            "device": None,
            "inode": None,
            "offset": 0,
            "pending": b"",
            "next_event_line": count_lines(events_path),
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
