"""Load application profiles from `PROFILES_DIR/*.json` at startup.

Each file is validated with the profile API's rules (routers/profiles.py ProfileBody)
and upserted by name through the API's versioning path:
- a new name creates version 1;
- a changed file creates the next version of that name;
- an unchanged file does nothing, so a version created in the UI after the file was
  loaded is kept until the file changes;
- a file whose content an existing version already holds does nothing (for example
  the lab profiles seeded before profile files existed).
Profiles with names no file uses are never touched. A bad file is logged and skipped.
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

from sqlalchemy import select

from db.models import ApplicationProfile, get_session_factory
from services.profile_files import profile_paths, read_profile_file
from services.runtime_config import data_dir

logger = logging.getLogger(__name__)

# source_metadata key that marks a file-sourced profile version.
FILE_MARKER = "profile_file"


def profiles_dir() -> Path:
    """PROFILES_DIR, default <DATA_DIR>/profiles."""
    configured = os.environ.get("PROFILES_DIR")
    return Path(configured).expanduser().resolve() if configured else data_dir() / "profiles"


def _content(profile) -> tuple:
    metadata = {key: value for key, value in (profile.source_metadata or {}).items() if key != FILE_MARKER}
    return list(profile.host_patterns or []), profile.context or {}, profile.routes or [], metadata


def _unchanged(versions: list[ApplicationProfile], body, digest: str) -> bool:
    """versions: newest first. Once a file has been loaded, only a change to its bytes counts,
    so a version made in the UI afterwards is kept until the file changes. Before that
    (profiles seeded or created by name), the file counts as new only if no version holds its content."""
    from_file = next((item for item in versions if FILE_MARKER in (item.source_metadata or {})), None)
    if from_file is not None:
        return from_file.source_metadata[FILE_MARKER].get("sha256") == digest or _content(versions[0]) == _content(body)
    return any(_content(item) == _content(body) for item in versions)


async def load_profile_files(directory: str | Path | None = None) -> list[tuple[str, int]]:
    """Upsert every profile file; returns the (name, version) pairs created."""
    # routers.profiles imports services.application_context, so import it late.
    from routers.profiles import ProfileBody, _create_version

    directory = Path(directory) if directory else profiles_dir()
    paths = profile_paths(directory)
    if not paths:
        logger.info("No application profile files in %s", directory)
        return []
    factory = get_session_factory()
    created: list[tuple[str, int]] = []
    names: set[str] = set()
    for path in paths:
        try:
            document, digest = read_profile_file(path)
            body = ProfileBody.model_validate(document)
        except (OSError, ValueError) as exc:  # pydantic's ValidationError is a ValueError
            logger.error("Skipping application profile file %s: %s", path, exc)
            continue
        if body.name in names:
            logger.error("Skipping application profile file %s: another file already defines %r", path, body.name)
            continue
        names.add(body.name)
        body = body.model_copy(update={
            "source_metadata": {**body.source_metadata, FILE_MARKER: {"name": path.name, "sha256": digest}},
        })
        try:
            async with factory() as session:
                versions = (await session.scalars(
                    select(ApplicationProfile)
                    .where(ApplicationProfile.name == body.name)
                    .order_by(ApplicationProfile.version.desc())
                )).all()
                if versions and _unchanged(versions, body, digest):
                    continue
                profile = await _create_version(session, body, versions[0].version + 1 if versions else 1)
                created.append((profile.name, profile.version))
        except Exception as exc:  # a version race (HTTP 409) or a database error; keep starting up
            logger.error("Skipping application profile file %s: %s", path, getattr(exc, "detail", exc))
            continue
        logger.info("Loaded application profile %s v%d from %s", *created[-1], path)
    return created
