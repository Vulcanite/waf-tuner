"""Convert an OpenAPI 3.x JSON document into an application profile (standard library only).

The spec is untrusted input: its size, the number of routes and parameters, the length
of every text, the `$ref` depth and the number of schema nodes visited are all bounded.
Only local `$ref`s (`#/...`) are followed. YAML is not supported.

OpenAPI does not describe the stack, so `languages`, `frameworks` and so on, and the
host patterns, come from the caller.
"""
from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlsplit

from services.profile_files import MAX_DOCUMENT_BYTES, MAX_ROUTE_PARAMETERS, MAX_ROUTES, MAX_TEXT_CHARS

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
MAX_REF_DEPTH = 16
MAX_SCHEMA_NODES = 20_000
MAX_MEANING_CHARS = 300
MAX_NAME_CHARS = 256
MAX_ENUM_VALUES = 12

# ModSecurity names JSON body fields ARGS:json.<field>; form and multipart fields keep their name.
_JSON_MEDIA = re.compile(r"^application/(?:[\w.+-]+\+)?json$")
_FORM_MEDIA = {"application/x-www-form-urlencoded", "multipart/form-data"}
_LOCATION_PREFIX = {"query": "", "path": "", "header": "REQUEST_HEADERS:", "cookie": "REQUEST_COOKIES:"}
_CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


class OpenAPIError(ValueError):
    """The document is not a usable OpenAPI 3.x JSON spec."""


def load_spec(text: str | bytes) -> dict:
    """Parse OpenAPI 3.x JSON text, bounded by MAX_DOCUMENT_BYTES."""
    data = text.encode("utf-8") if isinstance(text, str) else text
    if len(data) > MAX_DOCUMENT_BYTES:
        raise OpenAPIError(f"The OpenAPI document is larger than {MAX_DOCUMENT_BYTES} bytes")
    try:
        spec = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise OpenAPIError(f"The OpenAPI document is not valid JSON (YAML is not supported): {exc}") from exc
    if not isinstance(spec, dict) or not str(spec.get("openapi", "")).startswith("3."):
        raise OpenAPIError("Only OpenAPI 3.x documents are supported")
    if not isinstance(spec.get("paths"), dict):
        raise OpenAPIError("The OpenAPI document has no paths object")
    return spec


def _text(value: Any, limit: int) -> str:
    text = " ".join(_CONTROL.sub(" ", str(value)).split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


class _Resolver:
    def __init__(self, spec: dict):
        self.spec = spec
        self.nodes = 0

    def resolve(self, node: Any, depth: int = 0) -> Any:
        """Follow `$ref` chains within the document."""
        self.nodes += 1
        if self.nodes > MAX_SCHEMA_NODES:
            raise OpenAPIError("The OpenAPI document references too many schemas")
        while isinstance(node, dict) and "$ref" in node:
            depth += 1
            if depth > MAX_REF_DEPTH:
                raise OpenAPIError(f"$ref chain deeper than {MAX_REF_DEPTH}")
            node = self._lookup(node["$ref"])
        return node

    def _lookup(self, ref: Any) -> Any:
        if not isinstance(ref, str) or not ref.startswith("#/"):
            raise OpenAPIError(f"Only local $ref values (#/...) are supported: {_text(ref, 80)}")
        node: Any = self.spec
        for part in ref[2:].split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if isinstance(node, dict) and part in node:
                node = node[part]
            elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
                node = node[int(part)]
            else:
                raise OpenAPIError(f"Unresolved $ref: {_text(ref, 80)}")
        return node

    def properties(self, schema: Any, depth: int = 0) -> dict[str, Any]:
        """Top-level properties of an object schema, merging allOf/oneOf/anyOf branches."""
        schema = self.resolve(schema, depth)
        if not isinstance(schema, dict) or depth > MAX_REF_DEPTH:
            return {}
        found = dict(schema["properties"]) if isinstance(schema.get("properties"), dict) else {}
        for key in ("allOf", "oneOf", "anyOf"):
            branches = schema.get(key) if isinstance(schema.get(key), list) else []
            for branch in branches:
                for name, value in self.properties(branch, depth + 1).items():
                    found.setdefault(name, value)
        return found


def _meaning(resolver: _Resolver, item: dict, schema: Any, label: str = "", suffix: str = "") -> str:
    """description, type/format, enum and example as one short string."""
    schema = resolver.resolve(schema)
    schema = schema if isinstance(schema, dict) else {}
    parts = []
    description = item.get("description") or schema.get("description") or item.get("summary") or schema.get("title")
    if description:
        parts.append(_text(description, 200))
    kind = schema.get("type")
    if isinstance(kind, list):
        kind = "/".join(str(value) for value in kind[:4])
    if kind or schema.get("format"):
        parts.append("type " + " ".join(_text(value, 40) for value in (kind, schema.get("format")) if value))
    enum = schema.get("enum")
    if isinstance(enum, list) and enum:
        values = ", ".join(_text(value, 40) for value in enum[:MAX_ENUM_VALUES])
        parts.append(f"one of {values}{', …' if len(enum) > MAX_ENUM_VALUES else ''}")
    example = item.get("example", schema.get("example"))
    if example is None and isinstance(schema.get("examples"), list) and schema["examples"]:
        example = schema["examples"][0]
    if example is not None and not isinstance(example, (dict, list)):
        parts.append(f"example {_text(example, 60)}")
    meaning = "; ".join(parts) or "documented in the OpenAPI spec"
    return _text(f"{label}{meaning}", MAX_MEANING_CHARS - len(suffix)) + suffix


def _base_path(spec: dict, base_path: str | None) -> str:
    """The URL path the API is served under: the argument, else the first server's path."""
    if base_path is None:
        servers = spec.get("servers")
        url = servers[0].get("url") if isinstance(servers, list) and servers and isinstance(servers[0], dict) else ""
        base_path = "" if not isinstance(url, str) or "{" in url else urlsplit(url).path
    base_path = "/" + str(base_path).strip("/")
    return "" if base_path == "/" else base_path


def _operation_parameters(resolver: _Resolver, shared: list, operation: dict) -> list[dict]:
    """Path-level parameters overridden by operation-level ones with the same name and location."""
    merged: dict[tuple, dict] = {}
    for raw in [*shared, *(operation.get("parameters") or [])]:
        parameter = resolver.resolve(raw)
        if isinstance(parameter, dict) and isinstance(parameter.get("name"), str):
            merged[(parameter["name"], parameter.get("in"))] = parameter
    return list(merged.values())


def openapi_to_profile(
    spec: dict,
    *,
    name: str,
    host_patterns: list[str] | None = None,
    context: dict | None = None,
    base_path: str | None = None,
    catch_all: bool = True,
) -> dict:
    """A profile document (see docs/profiles.md) for the spec's paths and parameters."""
    if not isinstance(spec.get("paths"), dict):
        raise OpenAPIError("The OpenAPI document has no paths object")
    if len(spec["paths"]) > MAX_ROUTES:
        raise OpenAPIError(f"The OpenAPI document has more than {MAX_ROUTES} paths")
    resolver = _Resolver(spec)
    prefix = _base_path(spec, base_path)
    routes = []
    for path, item in spec["paths"].items():
        item = resolver.resolve(item)
        if not isinstance(path, str) or not path.startswith("/") or not isinstance(item, dict):
            raise OpenAPIError(f"Invalid path entry: {_text(path, 80)}")
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        methods, parameters, notes = [], {}, []
        for method in HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, dict):
                continue
            methods.append(method.upper())
            if operation.get("summary"):
                notes.append(f"{method.upper()}: {_text(operation['summary'], 200)}")
            for parameter in _operation_parameters(resolver, shared, operation):
                location = parameter.get("in")
                if location not in _LOCATION_PREFIX or not 0 < len(parameter["name"]) <= MAX_NAME_CHARS:
                    continue
                label = {"header": "header: ", "cookie": "cookie: "}.get(location, "")
                suffix = " (path segment)" if location == "path" else ""
                parameters.setdefault(_LOCATION_PREFIX[location] + parameter["name"],
                                      _meaning(resolver, parameter, parameter.get("schema"), label, suffix))
            body = resolver.resolve(operation.get("requestBody"))
            content = body.get("content") if isinstance(body, dict) else None
            for media_type, media in (content.items() if isinstance(content, dict) else []):
                media_type = str(media_type).split(";", 1)[0].strip().lower()
                if _JSON_MEDIA.match(media_type):
                    field_prefix = "json."
                elif media_type in _FORM_MEDIA:
                    field_prefix = ""
                else:
                    continue
                schema = media.get("schema") if isinstance(media, dict) else None
                for field, field_schema in resolver.properties(schema).items():
                    if isinstance(field, str) and field and len(field) <= MAX_NAME_CHARS:
                        parameters.setdefault(field_prefix + field, _meaning(resolver, {}, field_schema))
            if len(parameters) > MAX_ROUTE_PARAMETERS:
                raise OpenAPIError(f"{_text(path, 80)} has more than {MAX_ROUTE_PARAMETERS} parameters")
        if not methods:
            continue
        route = {"path": prefix + path if path != "/" else prefix or "/", "methods": methods,
                 "parameters": parameters}
        if notes:
            route["notes"] = _text(" ".join(notes), MAX_TEXT_CHARS)
        routes.append(route)
    if catch_all:
        routes.append({"path": "/*", "parameters": {},
                       "notes": "General context for paths the OpenAPI document does not describe."})
    context = dict(context or {})
    info = spec.get("info") if isinstance(spec.get("info"), dict) else {}
    if "purpose" not in context and info.get("title"):
        context["purpose"] = _text(info["title"], 200)
    source = {"type": "openapi", "verified": False}
    for key in ("title", "version"):
        if info.get(key):
            source[f"openapi_{key}"] = _text(info[key], 200)
    return {
        "name": name,
        "host_patterns": list(host_patterns or []),
        "context": context,
        "routes": routes,
        "source_metadata": source,
    }
