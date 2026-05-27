"""
Offset Tracker — Phase 2

Manages tracker.json which records the byte offset in events.jsonl up to
which the agent has processed. Uses atomic write (tmp + rename).
"""
import json
import os
import logging

logger = logging.getLogger(__name__)

TRACKER_PATH = os.environ.get("TRACKER_PATH", "/app/data/tracker.json")


def _tracker_path() -> str:
    return os.environ.get("TRACKER_PATH", TRACKER_PATH)


def ensure_tracker() -> None:
    """Create tracker.json with initial offset 0 if it doesn't exist."""
    path = _tracker_path()
    if not os.path.exists(path):
        _write(path, {"last_offset": 0})
        logger.info("Created tracker.json at %s", path)


def get_last_offset() -> int:
    path = _tracker_path()
    try:
        with open(path) as f:
            data = json.load(f)
        return int(data.get("last_offset", 0))
    except (FileNotFoundError, json.JSONDecodeError, ValueError):
        return 0


def set_last_offset(n: int) -> None:
    path = _tracker_path()
    _write(path, {"last_offset": n})


def _write(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def count_lines_to_offset(path: str, offset: int) -> int:
    """
    Return the 0-based line number of the line that ENDS at `offset`.

    `offset` is f.tell() after readline(), meaning it points to the START of
    the next line.  The chunk [0:offset] contains exactly N newlines for N
    lines that have been read, so subtracting 1 gives the 0-based index of
    the line we just consumed.
    """
    if offset <= 0:
        return 0
    try:
        with open(path, "rb") as f:
            chunk = f.read(offset)
        return max(0, chunk.count(b"\n") - 1)
    except OSError:
        return 0
