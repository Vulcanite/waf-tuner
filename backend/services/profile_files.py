"""Read application profile JSON files (standard library only).

The backend loads `PROFILES_DIR/*.json` at startup (services/profile_loader.py).
eval/ reads the lab profiles in lab/profiles/ through `profiles_from_dir`, so it
sees the same profile data without SQLAlchemy or Pydantic. The format is
documented in docs/profiles.md.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

# Size bounds shared by the profile API, profile files and the OpenAPI import.
MAX_DOCUMENT_BYTES = 2_000_000
MAX_ROUTES = 1000
MAX_ROUTE_PARAMETERS = 200
MAX_TEXT_CHARS = 2000

LAB_PROFILES_DIR = Path(__file__).resolve().parents[2] / "lab" / "profiles"


def profile_paths(directory: str | Path) -> list[Path]:
    """The `*.json` files in a directory, in name order (ids follow this order)."""
    directory = Path(directory)
    if not directory.is_dir():
        return []
    return sorted(path for path in directory.glob("*.json") if path.is_file())


def read_profile_file(path: str | Path) -> tuple[dict, str]:
    """The profile document and the sha256 of the file bytes. Raises ValueError on a bad file."""
    path = Path(path)
    data = path.read_bytes()
    if len(data) > MAX_DOCUMENT_BYTES:
        raise ValueError(f"file is larger than {MAX_DOCUMENT_BYTES} bytes")
    try:
        document = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"not valid UTF-8 JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise ValueError("the file must hold one JSON object")
    return document, hashlib.sha256(data).hexdigest()


def profiles_from_dir(directory: str | Path = LAB_PROFILES_DIR) -> list[SimpleNamespace]:
    """The profiles in a directory as a fresh database holds them after loading (ids in file
    order, version 1), without the loader's source_metadata file marker. Used by eval/ and
    tests; no validation beyond JSON."""
    profiles = []
    for index, path in enumerate(profile_paths(directory), start=1):
        document, _ = read_profile_file(path)
        profiles.append(SimpleNamespace(
            id=index,
            name=document["name"],
            version=1,
            active=True,
            host_patterns=list(document.get("host_patterns") or []),
            context=document.get("context") or {},
            routes=document.get("routes") or [],
            source_metadata=document.get("source_metadata") or {},
        ))
    return profiles
