import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from routers.profiles import ProfileBody
from services.audit_event import normalize_audit_event
from services.inference_context import match_target, split_request_uri
from services.openapi_profile import MAX_MEANING_CHARS, OpenAPIError, load_spec, openapi_to_profile
from services.profile_files import LAB_PROFILES_DIR, MAX_DOCUMENT_BYTES, MAX_ROUTES, profiles_from_dir
from services.profile_match import application_context_for, route_supports_exception

ROOT = Path(__file__).resolve().parents[2]
FLASK_SPEC = ROOT / "lab" / "flask-app" / "openapi.json"


def spec(paths, components=None, **extra):
    return {"openapi": "3.0.3", "info": {"title": "Demo", "version": "2"}, "paths": paths,
            "components": components or {}, **extra}


def test_parameters_are_keyed_by_location_and_body_type():
    document = spec({
        "/items/{item_id}": {
            "parameters": [{"name": "item_id", "in": "path", "schema": {"type": "integer"}}],
            "get": {"parameters": [
                {"name": "q", "in": "query", "description": "search text", "schema": {"type": "string"}},
                {"name": "X-Trace", "in": "header", "schema": {"type": "string", "format": "uuid"}},
                {"name": "theme", "in": "cookie", "schema": {"enum": ["dark", "light"]}, "example": "dark"},
            ]},
            "put": {"requestBody": {"content": {"application/json; charset=utf-8": {
                "schema": {"$ref": "#/components/schemas/Item"}}}}},
            "post": {"requestBody": {"content": {
                "multipart/form-data": {"schema": {"properties": {"upload_note": {"type": "string"}}}},
                "application/x-www-form-urlencoded": {"schema": {"properties": {"title": {"type": "string"}}}},
                "text/plain": {"schema": {"properties": {"ignored": {"type": "string"}}}},
            }}},
        },
    }, components={"schemas": {
        "Item": {"allOf": [{"$ref": "#/components/schemas/Base"}, {"properties": {"price": {"type": "number"}}}]},
        "Base": {"properties": {"name": {"type": "string", "description": "item name"}}},
    }})
    profile = openapi_to_profile(document, name="demo", host_patterns=["demo.test"],
                                 context={"languages": ["go"]}, catch_all=False)
    [route] = profile["routes"]
    assert route["path"] == "/items/{item_id}" and route["methods"] == ["GET", "PUT", "POST"]
    parameters = route["parameters"]
    assert set(parameters) == {"item_id", "q", "REQUEST_HEADERS:X-Trace", "REQUEST_COOKIES:theme",
                               "json.name", "json.price", "upload_note", "title"}
    assert parameters["item_id"] == "type integer (path segment)"
    assert parameters["q"] == "search text; type string"
    assert parameters["REQUEST_HEADERS:X-Trace"] == "header: type string uuid"
    assert parameters["REQUEST_COOKIES:theme"] == "cookie: one of dark, light; example dark"
    assert parameters["json.name"] == "item name; type string"
    assert profile["context"] == {"languages": ["go"], "purpose": "Demo"}
    assert profile["source_metadata"] == {"type": "openapi", "verified": False,
                                          "openapi_title": "Demo", "openapi_version": "2"}
    ProfileBody.model_validate(profile)


def test_server_base_path_and_catch_all():
    document = spec({"/": {"get": {}}, "/users": {"get": {}}, "/empty": {}},
                    servers=[{"url": "https://api.example.com/v1/"}])
    paths = [route["path"] for route in openapi_to_profile(document, name="demo")["routes"]]
    assert paths == ["/v1", "/v1/users", "/*"]
    assert [route["path"] for route in openapi_to_profile(document, name="demo", base_path="")["routes"]][:2] == [
        "/", "/users"]


def test_untrusted_specs_are_bounded():
    long = "x" * 5000
    document = spec({"/a": {"get": {"parameters": [
        {"name": "q", "in": "query", "description": f"line\x00one\n{long}"},
        {"name": "n" * 300, "in": "query"},
        {"name": "body", "in": "body"},
    ]}}})
    parameters = openapi_to_profile(document, name="demo")["routes"][0]["parameters"]
    assert list(parameters) == ["q"]
    assert len(parameters["q"]) <= MAX_MEANING_CHARS and "\x00" not in parameters["q"]
    loop = spec({"/a": {"$ref": "#/components/pathItems/a"}}, {"pathItems": {"a": {"$ref": "#/components/pathItems/a"}}})
    with pytest.raises(OpenAPIError, match="deeper"):
        openapi_to_profile(loop, name="demo")
    with pytest.raises(OpenAPIError, match="local"):
        openapi_to_profile(spec({"/a": {"$ref": "https://example.com/spec.json#/a"}}), name="demo")
    with pytest.raises(OpenAPIError, match="Unresolved"):
        openapi_to_profile(spec({"/a": {"$ref": "#/components/missing"}}), name="demo")
    with pytest.raises(OpenAPIError, match="paths"):
        openapi_to_profile(spec({f"/p{index}": {"get": {}} for index in range(MAX_ROUTES + 1)}), name="demo")
    with pytest.raises(OpenAPIError, match="parameters"):
        openapi_to_profile(spec({"/a": {"get": {"parameters": [
            {"name": f"p{index}", "in": "query"} for index in range(201)]}}}), name="demo")
    # Fan-out through allOf is capped by the schema node budget.
    schemas = {f"S{level}": {"allOf": [{"$ref": f"#/components/schemas/S{level + 1}"}] * 10} for level in range(8)}
    schemas["S8"] = {"properties": {"a": {}}}
    fanout = spec({"/a": {"post": {"requestBody": {"content": {"application/json": {
        "schema": {"$ref": "#/components/schemas/S0"}}}}}}}, {"schemas": schemas})
    with pytest.raises(OpenAPIError, match="too many"):
        openapi_to_profile(fanout, name="demo")


def test_load_spec_accepts_only_bounded_openapi3_json():
    assert load_spec(json.dumps(spec({})))["openapi"] == "3.0.3"
    for text in ("openapi: 3.0.0\npaths: {}\n", json.dumps({"swagger": "2.0", "paths": {}}),
                 json.dumps({"openapi": "3.1.0"}), " " * (MAX_DOCUMENT_BYTES + 1)):
        with pytest.raises(OpenAPIError):
            load_spec(text)


def _flask_profiles():
    hand = next(profile for profile in profiles_from_dir(LAB_PROFILES_DIR) if profile.name == "shop-lab")
    generated = openapi_to_profile(load_spec(FLASK_SPEC.read_text()), name="shop-openapi",
                                   host_patterns=["shop.lab"], context={"languages": ["python"]})
    ProfileBody.model_validate(generated)
    generated = SimpleNamespace(id=1, version=1, **generated)
    return hand, generated


def test_flask_spec_profile_matches_the_hand_profile_on_every_eval_match():
    hand, generated = _flask_profiles()
    records = [json.loads(line) for line in (ROOT / "eval" / "requests.jsonl").read_text().splitlines()]
    compared = supported = 0
    for record in records:
        if record["app"] != "flask":
            continue
        event = normalize_audit_event(record["modsec_audit"])
        host = event["raw_request"]["headers"].get("Host")
        path = split_request_uri(event["uri"]).path or "/"
        _, hand_context = application_context_for([hand], host, event["method"], path)
        _, generated_context = application_context_for([generated], host, event["method"], path)
        hand_route, generated_route = hand_context["route"], generated_context["route"]
        assert hand_route["path"] == generated_route["path"], record["id"]
        if hand_route["path"] != "/*":
            assert hand_route["methods"] == generated_route["methods"], record["id"]
        for label in record["labels"]:
            collection, parameter = match_target(event["matches"][label["match_index"]])
            expected = route_supports_exception(hand_context, collection, parameter)
            assert route_supports_exception(generated_context, collection, parameter) == expected, (
                record["id"], collection, parameter)
            compared += 1
            supported += expected
    assert compared > 400 and supported > 300


def test_flask_spec_documents_the_same_inputs_as_the_hand_profile():
    hand, generated = _flask_profiles()
    assert {route["path"]: set(route["parameters"]) for route in generated.routes} == {
        route["path"]: set(route["parameters"]) for route in hand.routes}


def test_import_endpoint_creates_versions_and_rejects_bad_specs(tmp_path, monkeypatch):
    import asyncio

    import httpx
    from fastapi import FastAPI

    from db import models
    from routers import profiles

    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "import.db"))
    monkeypatch.setattr(models, "_async_engine", None)
    monkeypatch.setattr(models, "_async_session_factory", None)
    app = FastAPI()
    app.include_router(profiles.router)
    body = {"spec": FLASK_SPEC.read_text(), "name": "shop-openapi", "host_patterns": ["shop.lab"],
            "context": {"languages": ["python"], "frameworks": ["flask"]}}

    async def scenario():
        await models.init_db()
        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                url = "/api/application-profiles/import-openapi"
                return [await client.post(url, json=payload) for payload in (
                    body, body, {**body, "spec": "openapi: 3.0.0"},
                    {**body, "spec": json.dumps(spec({"/a": {"get": {"parameters": [
                        {"name": "q", "in": "query", "schema": {"$ref": "http://evil.test/x"}}]}}}))},
                    {**body, "spec": "x" * (MAX_DOCUMENT_BYTES + 1)},
                )]
        finally:
            await models._async_engine.dispose()

    first, second, yaml, remote_ref, too_big = asyncio.run(scenario())
    assert first.status_code == 200, first.text
    assert (first.json()["version"], second.json()["version"]) == (1, 2)
    profile = first.json()
    assert profile["context"]["frameworks"] == ["flask"] and profile["source_metadata"]["type"] == "openapi"
    assert len(profile["routes"]) == 11 and profile["routes"][-1]["path"] == "/*"
    assert yaml.status_code == 400 and "YAML" in yaml.json()["detail"]
    assert remote_ref.status_code == 400 and "local $ref" in remote_ref.json()["detail"]
    assert too_big.status_code == 422


def test_cli_writes_a_loadable_profile_file(tmp_path):
    import subprocess
    import sys

    output = tmp_path / "shop.json"
    result = subprocess.run(
        [sys.executable, "-I", str(ROOT / "scripts" / "openapi_to_profile.py"), str(FLASK_SPEC), "--name", "shop",
         "--host", "shop.lab", "--language", "python", "--framework", "flask", "--output", str(output)],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stderr
    [profile] = profiles_from_dir(tmp_path)
    assert (profile.name, profile.host_patterns, profile.context["frameworks"]) == ("shop", ["shop.lab"], ["flask"])
    ProfileBody.model_validate(json.loads(output.read_text()))
