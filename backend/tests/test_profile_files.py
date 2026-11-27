import asyncio
import hashlib
import json
import logging
import shutil

import pytest
from sqlalchemy import select

from db import models
from db.models import ApplicationProfile
from services.application_context import select_application_context
from services.profile_files import LAB_PROFILES_DIR, profiles_from_dir
from services.profile_loader import FILE_MARKER, load_profile_files

# sha256 of json.dumps([vars(p) for p in seeded_profiles()]) from the removed
# services/lab_profiles.py, so the JSON files are exactly the old profile dicts
# (key order included, which keeps eval/requests.jsonl byte-identical).
OLD_SEEDED_PROFILES_SHA256 = "fe9288cc4fc8f3861d997b27eb54966ef02904afd2feec5508ed2e2c97ad7d4d"


def test_lab_profile_files_are_the_old_python_profiles():
    profiles = [vars(profile) for profile in profiles_from_dir(LAB_PROFILES_DIR)]
    assert [profile["name"] for profile in profiles] == ["default-lab", "shop-lab"]
    digest = hashlib.sha256(json.dumps(profiles, ensure_ascii=False).encode()).hexdigest()
    assert digest == OLD_SEEDED_PROFILES_SHA256


@pytest.fixture
def database(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "profiles.db"))
    monkeypatch.setattr(models, "_async_engine", None)
    monkeypatch.setattr(models, "_async_session_factory", None)

    def run(coroutine_function):
        async def wrapper():
            try:
                await models.init_db()
                return await coroutine_function()
            finally:
                await models._async_engine.dispose()
        return asyncio.run(wrapper())
    return run


async def _rows():
    async with models.get_session_factory()() as session:
        rows = (await session.scalars(
            select(ApplicationProfile).order_by(ApplicationProfile.name, ApplicationProfile.version)
        )).all()
        return [(row.name, row.version, row.active, row.source_metadata) for row in rows]


async def _context(uri, host=None, method="GET"):
    headers = {"Host": host} if host else {}
    async with models.get_session_factory()() as session:
        return await select_application_context(
            session, {"method": method, "uri": uri, "raw_request": {"headers": headers}})


def test_lab_files_load_once_and_select_by_host_and_route(database, monkeypatch):
    monkeypatch.setenv("PROFILES_DIR", str(LAB_PROFILES_DIR))

    async def scenario():
        first = await load_profile_files()
        again = await load_profile_files()
        rows = await _rows()
        dvwa, dvwa_context = await _context("/vulnerabilities/sqli/?id=select+all", "localhost")
        _, fallback = await _context("/some/other/app/path", method="POST")
        shop, shop_context = await _context("/download?name=user-guide.v2.pdf", "shop.lab:8080")
        _, shop_fallback = await _context("/unknown", "shop.lab")
        return first, again, rows, dvwa, dvwa_context, fallback, shop, shop_context, shop_fallback

    first, again, rows, dvwa, dvwa_context, fallback, shop, shop_context, shop_fallback = database(scenario)
    assert first == [("default-lab", 1), ("shop-lab", 1)]
    assert again == []
    assert [row[:3] for row in rows] == [("default-lab", 1, True), ("shop-lab", 1, True)]
    assert rows[1][3][FILE_MARKER]["name"] == "shop.json"
    assert rows[1][3]["seeded"] is True
    assert (dvwa.id, dvwa.name, dvwa_context["route"]["path"]) == (1, "default-lab", "/vulnerabilities/sqli/")
    # The catch-all keeps REQUIRE_APPLICATION_CONTEXT satisfied for any lab path, even without a Host.
    assert fallback["route"]["path"] == "/*"
    assert (shop.name, shop_context["application"]["languages"]) == ("shop-lab", ["python"])
    assert shop_context["route"]["path"] == "/download" and "name" in shop_context["route"]["parameters"]
    assert (shop_fallback["profile_name"], shop_fallback["route"]["path"]) == ("shop-lab", "/*")


def _write(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")


def test_changed_files_version_and_bad_files_are_skipped(database, tmp_path, monkeypatch, caplog):
    directory = tmp_path / "profiles"
    directory.mkdir()
    monkeypatch.setenv("DATA_DIR", str(tmp_path))  # default PROFILES_DIR is <DATA_DIR>/profiles
    monkeypatch.delenv("PROFILES_DIR", raising=False)
    app = {"name": "catalog", "host_patterns": ["catalog.test"], "context": {"languages": ["go"]},
           "routes": [{"path": "/search", "methods": ["GET"], "parameters": {"q": "search text"}}]}
    _write(directory / "catalog.json", app)
    (directory / "broken.json").write_text("{not json", encoding="utf-8")
    _write(directory / "relative.json", {"name": "relative", "routes": [{"path": "search"}]})
    _write(directory / "zz-duplicate.json", {**app, "host_patterns": ["other.test"]})
    (directory / "notes.txt").write_text("ignored", encoding="utf-8")

    async def scenario():
        # An operator profile from the API, under a name no file uses.
        async with models.get_session_factory()() as session:
            session.add(ApplicationProfile(name="operator", version=1, active=True, host_patterns=["*"],
                                           context={}, routes=[], source_metadata={"type": "manual"}))
            await session.commit()
        results = [await load_profile_files()]
        results.append(await load_profile_files())  # unchanged
        _write(directory / "catalog.json", {**app, "context": {"languages": ["go"], "notes": "v2"}})
        results.append(await load_profile_files())  # changed
        return results, await _rows()

    with caplog.at_level(logging.ERROR, logger="services.profile_loader"):
        (first, unchanged, changed), rows = database(scenario)
    assert (first, unchanged, changed) == ([("catalog", 1)], [], [("catalog", 2)])
    assert [row[:3] for row in rows] == [("catalog", 1, False), ("catalog", 2, True), ("operator", 1, True)]
    assert rows[1][3][FILE_MARKER]["name"] == "catalog.json"
    assert rows[2][3] == {"type": "manual"}
    errors = " ".join(record.getMessage() for record in caplog.records)
    for name in ("broken.json", "relative.json", "zz-duplicate.json"):
        assert name in errors


def test_an_api_version_is_kept_until_the_file_changes(database, tmp_path, monkeypatch):
    directory = tmp_path / "profiles"
    shutil.copytree(LAB_PROFILES_DIR, directory)
    monkeypatch.setenv("PROFILES_DIR", str(directory))

    async def scenario():
        # A profile seeded before profile files existed: same content, no file marker.
        seeded = vars(profiles_from_dir(directory)[0])
        async with models.get_session_factory()() as session:
            session.add(ApplicationProfile(**{key: seeded[key] for key in (
                "name", "version", "active", "host_patterns", "context", "routes", "source_metadata")}))
            await session.commit()
        upgraded = await load_profile_files()
        # An operator edits default-lab in the UI: v3 has no file marker.
        async with models.get_session_factory()() as session:
            session.add(ApplicationProfile(name="default-lab", version=3, active=False, host_patterns=["*"],
                                           context={}, routes=[], source_metadata={"type": "manual"}))
            await session.commit()
        kept = await load_profile_files()
        document = json.loads((directory / "dvwa.json").read_text())
        document["context"]["notes"] = "edited file"
        _write(directory / "dvwa.json", document)
        reloaded = await load_profile_files()
        return upgraded, kept, reloaded

    upgraded, kept, reloaded = database(scenario)
    assert upgraded == [("shop-lab", 1)]  # default-lab already held the file's content
    assert kept == []
    assert reloaded == [("default-lab", 4)]
