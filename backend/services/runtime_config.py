"""Runtime operator config persisted on the shared data volume.

Allows the tailer to be pointed at a ModSecurity JSON audit log without
rebuilding the image. Values live in runtime_config.json next to the SQLite DB
and can be set from the frontend on first start / Settings.
"""
from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)



def _data_dir() -> Path:
    events = os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")
    return Path(events).expanduser().resolve().parent


def config_path() -> Path:
    override = os.environ.get("RUNTIME_CONFIG_PATH")
    if override:
        return Path(override).expanduser().resolve()
    return _data_dir() / "runtime_config.json"


def default_audit_log_path() -> str:
    return (
        os.environ.get("MODSEC_AUDIT_LOG")
        or str(_data_dir() / "modsec" / "audit.log")
    )


def _read() -> dict[str, Any]:
    path = config_path()
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                return data
        except (OSError, json.JSONDecodeError) as exc:
            logger.warning("Could not read runtime config %s: %s", path, exc)
    return {}


def load() -> dict[str, Any]:
    return dict(_read())


def save(updates: dict[str, Any]) -> dict[str, Any]:
    """Merge updates into runtime config and persist. Returns full config."""
    current = _read()
    for key, value in updates.items():
        if value is None:
            current.pop(key, None)
        else:
            current[key] = value
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(current, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)
    logger.info("Runtime config updated at %s", path)
    return dict(current)


def get_audit_log_path() -> str:
    """Active audit log path: runtime override, then env, then default."""
    data = _read()
    configured = (data.get("modsec_audit_log") or "").strip()
    if configured:
        return configured
    return default_audit_log_path()


def is_audit_log_configured() -> bool:
    """True if operator explicitly set a path or the default/env file exists."""
    data = _read()
    if (data.get("modsec_audit_log") or "").strip():
        return True
    path = default_audit_log_path()
    return bool(path) and os.path.exists(path)


def audit_log_status() -> dict[str, Any]:
    path = get_audit_log_path()
    exists = os.path.exists(path) if path else False
    size = os.path.getsize(path) if exists else 0
    data = _read()
    explicit = bool((data.get("modsec_audit_log") or "").strip())
    return {
        "modsec_audit_log": path,
        "explicitly_configured": explicit,
        "configured": is_audit_log_configured(),
        "exists": exists,
        "size_bytes": size,
        "readable": exists and os.access(path, os.R_OK),
        "source": "runtime_config" if explicit else "env_or_default",
        "config_file": str(config_path()),
    }


def set_audit_log_path(path: str) -> dict[str, Any]:
    cleaned = (path or "").strip()
    if not cleaned:
        raise ValueError("modsec_audit_log must be a non-empty path")
    if "\x00" in cleaned:
        raise ValueError("invalid path")
    # Absolute path preferred inside containers; allow relative resolved against data dir
    p = Path(cleaned).expanduser()
    if not p.is_absolute():
        p = (_data_dir() / p).resolve()
    else:
        p = p.resolve()

    # Path traversal validation: restrict to whitelisted roots
    import tempfile
    allowed_dirs = [
        _data_dir().resolve(),
        Path("/shared").resolve(),
        Path("/var/log").resolve(),
        Path(tempfile.gettempdir()).resolve(),
        Path.cwd().resolve(),
    ]
    is_allowed = False
    for allowed in allowed_dirs:
        try:
            if allowed == p or allowed in p.parents:
                is_allowed = True
                break
        except Exception:
            continue
    if not is_allowed:
        raise ValueError(
            "Access denied: Audit log path must reside under /shared, /var/log, "
            "temporary temp directories, or the application directory."
        )

    save({"modsec_audit_log": str(p)})
    # Keep process env in sync for any code that still reads it once
    os.environ["MODSEC_AUDIT_LOG"] = str(p)
    return audit_log_status()
