"""Shared pieces for the Phase 4 benchmark capture (standard library only).

A request is built once and sent byte-for-byte through two WAFs: the CRS-only
front end and the CRS + plugin front end for that app. Both copies carry the
same X-Request-ID, which pairs the two audit records afterwards.

The match-target helpers below are small copies of backend/services code so
this directory does not import backend/ (see README.md, "Copied code").
"""
from __future__ import annotations

import base64
import fnmatch
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
BENCH_DIR = Path(__file__).resolve().parent
COMPOSE_FILE = ROOT / "lab" / "bench" / "docker-compose.yml"
PROJECT = "waftuner-bench"
REQUEST_ID_HEADER = "X-Request-ID"

# Host header, CRS-only WAF port, CRS + plugin WAF port and service names.
APPS = {
    "wordpress": {"host": "wp.bench", "base": 18280, "plugin": 18281,
                  "base_service": "waf-base", "plugin_service": "waf-wp"},
    "nextcloud": {"host": "nc.bench", "base": 18280, "plugin": 18282,
                  "base_service": "waf-base", "plugin_service": "waf-nc"},
}

# Throwaway lab credentials (same defaults as lab/bench/setup.sh).
CREDENTIALS = {
    "wp_user": os.environ.get("BENCH_WP_ADMIN_USER", "benchadmin"),
    "wp_password": os.environ.get("BENCH_WP_ADMIN_PASSWORD", "bench-wp-admin-pass"),
    "nc_user": os.environ.get("BENCH_NC_ADMIN_USER", "benchadmin"),
    "nc_password": os.environ.get("BENCH_NC_ADMIN_PASSWORD", "bench-nc-admin-pass"),
    "nc_second_password": os.environ.get("BENCH_NC_SECOND_PASSWORD", "bench-nc-bea-pass"),
}

FIREFOX = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

# Session cookies whose values are replaced in stored records.
SESSION_COOKIE = re.compile(r"^(?:wordpress_(?:sec_|logged_in_)?[0-9a-f]{32}|nc_session_id|nc_token|oc_sessionPassphrase|oc[0-9a-z]{10,})$")


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


class Response:
    def __init__(self, status: int, headers: list[tuple[str, str]], body: bytes):
        self.status = status
        self.headers = headers
        self.body = body

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", "replace")

    def header(self, name: str) -> str:
        return next((value for key, value in self.headers if key.lower() == name.lower()), "")

    def json(self) -> Any:
        try:
            return json.loads(self.body)
        except (ValueError, UnicodeDecodeError):
            return None


def _http(port: int, method: str, path: str, headers: dict[str, str], body: bytes | None) -> Response:
    request = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=body, headers=headers, method=method)
    try:
        with _OPENER.open(request, timeout=60) as response:
            return Response(response.status, list(response.headers.items()), response.read())
    except urllib.error.HTTPError as exc:
        return Response(exc.code, list(exc.headers.items()) if exc.headers else [], exc.read() or b"")
    except (urllib.error.URLError, TimeoutError, OSError):
        return Response(0, [], b"")


def multipart(fields: list[tuple[str, str]], files: list[tuple[str, str, str, bytes]]) -> tuple[bytes, str]:
    """Encode form fields and (field, filename, content_type, data) files like a browser."""
    boundary = "----geckoformboundary" + uuid.uuid4().hex[:24]
    chunks: list[bytes] = []
    for name, value in fields:
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n'.encode())
        chunks.append(value.encode() + b"\r\n")
    for name, filename, content_type, data in files:
        chunks.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                      f"Content-Type: {content_type}\r\n\r\n".encode())
        chunks.append(data + b"\r\n")
    chunks.append(f"--{boundary}--\r\n".encode())
    return b"".join(chunks), f"multipart/form-data; boundary={boundary}"


class Actor:
    """One browser (or API client) for one app, with its own cookie jar.

    Only the CRS-only WAF's response updates the jar and is returned, so both
    WAFs always see the same request bytes.
    """

    def __init__(self, bench: "Bench", app: str, headers: dict[str, str] | None = None):
        self.bench = bench
        self.app = app
        self.conf = APPS[app]
        self.browser = headers is None
        self.headers = dict(FIREFOX if headers is None else headers)
        self.cookies: dict[str, tuple[str, str]] = {}

    def set_cookie(self, name: str, value: str, path: str = "/") -> None:
        self.cookies[name] = (value, path)

    def _cookie_header(self, path: str) -> str:
        return "; ".join(f"{name}={value}" for name, (value, cpath) in self.cookies.items()
                         if path.startswith(cpath.rstrip("/") or "/"))

    def _absorb(self, response: Response) -> None:
        for key, value in response.headers:
            if key.lower() != "set-cookie":
                continue
            pair, _, attrs = value.partition(";")
            name, _, cvalue = pair.strip().partition("=")
            attributes = {k.strip().lower(): v.strip() for k, _, v in (a.partition("=") for a in attrs.split(";"))}
            max_age = attributes.get("max-age", "")
            expired = cvalue in ("", "deleted") or max_age == "0" or max_age.startswith("-") \
                or bool(re.search(r"\b(?:19[0-9]{2}|20[01][0-9])\b", attributes.get("expires", "")))
            if expired:
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = (cvalue, attributes.get("path") or "/")
                if SESSION_COOKIE.match(name):
                    self.bench.secrets.add(cvalue)

    def get(self, path: str, **kwargs) -> Response:
        return self.send("GET", path, **kwargs)

    def send(self, method: str, path: str, *, query: dict | list | None = None, form: dict | list | None = None,
             json_body: Any = None, body: bytes | str | None = None, content_type: str | None = None,
             headers: dict[str, str] | None = None, record: dict | None = None) -> Response:
        """Send one request through both WAFs. `record` holds id, kind, category, target and notes."""
        if query:
            path += ("&" if "?" in path else "?") + urllib.parse.urlencode(query, quote_via=urllib.parse.quote)
        req_headers = {"Host": self.conf["host"], **self.headers}
        if self.browser and method not in ("GET", "HEAD"):
            req_headers["Origin"] = f"http://{self.conf['host']}"
        data: bytes | None = None
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            req_headers["Content-Type"] = "application/x-www-form-urlencoded; charset=UTF-8"
        elif json_body is not None:
            data = json.dumps(json_body, ensure_ascii=False).encode()
            req_headers["Content-Type"] = "application/json"
        elif body is not None:
            data = body.encode() if isinstance(body, str) else body
        if content_type:
            req_headers["Content-Type"] = content_type
        cookie = self._cookie_header(urllib.parse.urlsplit(path).path)
        if cookie:
            req_headers["Cookie"] = cookie
        req_headers.update(headers or {})
        request_id = uuid.uuid4().hex
        req_headers[REQUEST_ID_HEADER] = request_id
        base = _http(self.conf["base"], method, path, req_headers, data)
        plugin = _http(self.conf["plugin"], method, path, req_headers, data)
        if record is None:
            slug = re.sub(r"[^a-z0-9]+", "-", urllib.parse.urlsplit(path).path.lower()).strip("-")[:60]
            record = {"id": f"{'wp' if self.app == 'wordpress' else 'nc'}-nav-{method.lower()}-{slug or 'root'}", "kind": "benign",
                      "category": "navigation", "target": None, "notes": f"page or API load: {method} {urllib.parse.urlsplit(path).path}"}
        self.bench.add(request_id, self.app, record, method, path, base.status, plugin.status)
        self._absorb(base)
        time.sleep(0.03)
        return base


class Bench:
    def __init__(self):
        self.sent: list[dict[str, Any]] = []
        self.secrets: set[str] = {CREDENTIALS["wp_password"], CREDENTIALS["nc_password"],
                                  CREDENTIALS["nc_second_password"]}
        self._ids: set[str] = set()

    def actor(self, app: str, headers: dict[str, str] | None = None) -> Actor:
        return Actor(self, app, headers)

    def add(self, request_id: str, app: str, record: dict, method: str, path: str, base_status: int,
            plugin_status: int) -> None:
        rid = record["id"]
        n = 2
        while rid in self._ids:
            rid = f"{record['id']}-{n}"
            n += 1
        self._ids.add(rid)
        self.sent.append({**record, "id": rid, "app": app, "request_id": request_id, "method": method,
                          "path": path, "status": [base_status, plugin_status]})

    def basic_auth(self, user: str, password: str) -> str:
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        self.secrets.add(token)
        return "Basic " + token


# --- audit logs -------------------------------------------------------------

def compose(*args: str, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE_FILE), *args],
                          cwd=ROOT, check=check, capture_output=capture)


def read_audit_log(service: str) -> dict[str, dict]:
    """Every audit record in one WAF's log, keyed by X-Request-ID."""
    out = compose("exec", "-T", service, "cat", "/var/log/modsec/audit.log").stdout.decode("utf-8", "replace")
    events = {}
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        headers = ((event.get("transaction") or {}).get("request") or {}).get("headers") or {}
        rid = next((str(v) for k, v in headers.items() if str(k).lower() == REQUEST_ID_HEADER.lower()), "")
        if rid:
            events[rid] = event
    return events


def scrub(value: Any, secrets: set[str]) -> Any:
    """Replace lab passwords, Basic tokens and session cookie values in every string."""
    variants = set()
    for secret in secrets:
        if len(secret) >= 6:
            variants |= {secret, urllib.parse.quote(secret, safe=""), urllib.parse.quote_plus(secret)}
    ordered = sorted(variants, key=len, reverse=True)

    def walk(item):
        if isinstance(item, str):
            for secret in ordered:
                if secret in item:
                    item = item.replace(secret, "REDACTED")
            return item
        if isinstance(item, list):
            return [walk(v) for v in item]
        if isinstance(item, dict):
            return {walk(k): walk(v) for k, v in item.items()}
        return item

    return walk(value)


# --- match helpers (copied from backend/services/inference_context.py) -----

AGGREGATE_IDS = frozenset({
    "949060", "949061", "949062", "949063", "949100", "949110",
    "959060", "959061", "959062", "959063", "959100",
    "980100", "980110", "980115", "980120", "980130", "980140", "980145", "980150",
})
_NATIVE_TARGET = re.compile(r"""\bagainst\s+variable\s+[`'"](?P<collection>[A-Z_]+)(?::(?P<parameter>[^`'"\r\n]+))?[`'"]\s+\(Value:""", re.I)
_MATCH_TARGET_SUFFIX = re.compile(r"""\b(?:within|variable)\s+[`'"]?(?P<collection>[A-Z_]+)(?::(?P<parameter>[^\s,;`'"\)]+))?""", re.I)
_WRAPPED_TARGET = re.compile(
    r"(?:^|_)(ARGS(?:_GET|_POST|_NAMES)?|REQUEST_HEADERS|REQUEST_COOKIES(?:_NAMES)?|REQUEST_BODY|REQUEST_URI(?:_RAW)?"
    r"|REQUEST_FILENAME|REQUEST_BASENAME|QUERY_STRING|FILES(?:_NAMES)?)(?::(.+))?$"
)


def extract_match_target(text: str) -> tuple[str | None, str | None]:
    if not isinstance(text, str):
        return None, None
    native = _NATIVE_TARGET.search(text)
    if native:
        parameter = native.group("parameter")
        return native.group("collection").upper(), parameter[:512] if parameter else None
    if text.startswith("Matched Data:"):
        marker = text.find(" found within ")
        if marker < 0:
            return None, None
        text = text[marker + len(" found "):]
    match = _MATCH_TARGET_SUFFIX.search(text)
    if not match:
        return None, None
    parameter = match.group("parameter")
    return match.group("collection").upper(), parameter.rstrip(":,.")[:512] if parameter else None


def audit_matches(event: dict) -> list[dict]:
    """Matches in the order backend/services/audit_event.normalize_audit_event lists them."""
    matches = []
    for message in (event.get("transaction") or {}).get("messages") or []:
        if not isinstance(message, dict):
            continue
        details = message.get("details") or {}
        rule_id = str(message.get("ruleId") or details.get("ruleId") or details.get("id") or "")
        if not rule_id:
            continue
        description = details.get("match") or ""
        data = message.get("data") or details.get("data") or ""
        collection, parameter = extract_match_target(description)
        if not collection:
            collection, parameter = extract_match_target(data)
        matches.append({"rule_id": rule_id, "collection": collection, "parameter": parameter,
                        "data": data, "description": description, "file": details.get("file") or "", "tags": details.get("tags") or [],
                        "message": message.get("message") or ""})
    return matches


def unwrap_target(collection: str | None, parameter: str | None) -> tuple[str | None, str | None]:
    """MATCHED_VARS:MATCHED_VARS:ARGS:x or TX:rfi_parameter_ARGS:x -> (ARGS, x)."""
    for _ in range(4):
        if collection not in {"MATCHED_VARS", "MATCHED_VAR", "TX"} or not parameter:
            break
        inner, _, name = parameter.partition(":")
        if collection.startswith("MATCHED") and name:
            collection, parameter = inner.upper(), name
            continue
        wrapped = _WRAPPED_TARGET.search(parameter)
        if not wrapped:
            break
        collection, parameter = wrapped.group(1), wrapped.group(2)
    return collection, parameter


# --- profiles (route ranking copied from backend/services/profile_match.py) ---

def load_profiles() -> dict[str, dict]:
    return {path.stem: json.loads(path.read_text()) for path in sorted((BENCH_DIR / "profiles").glob("*.json"))}


def _route_score(route: dict, method: str, path: str) -> int:
    methods = [str(item).upper() for item in (route.get("methods") or [])]
    if methods and method.upper() not in methods:
        return -1
    pattern = str(route.get("path") or "")
    if not pattern:
        return -1
    if pattern.endswith("/*") and path.startswith(pattern[:-1]):
        return 100 + len(pattern)
    if "{" in pattern:
        expression = re.sub(r"\\\{[^/{}]+\\\}", r"[^/]+", re.escape(pattern))
        if re.fullmatch(expression, path):
            return 500 + len(pattern.replace("{", "").replace("}", ""))
        return -1
    return 1000 + len(pattern) if pattern == path else -1


def application_context(profile: dict, host: str, method: str, path: str) -> dict:
    if not any(fnmatch.fnmatchcase(host, pattern) for pattern in profile["host_patterns"]):
        return {}
    best, best_score = None, -1
    for route in profile["routes"]:
        score = _route_score(route, method, path)
        if score > best_score:
            best, best_score = route, score
    return {
        "application": profile["context"],
        "route": best,
        "profile_name": profile["name"],
        "profile_version": profile.get("version", 1),
        "fact_provenance": {"seeded": True, "seed": profile["name"], "replace_with_operator_profile": True},
    }


# --- HTML forms -------------------------------------------------------------

from html.parser import HTMLParser  # noqa: E402


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms: list[dict] = []
        self._form: dict | None = None
        self._textarea: str | None = None
        self._select: str | None = None
        self._buffer = ""

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self._form = {"attrs": attrs, "fields": []}
            self.forms.append(self._form)
        if self._form is None:
            return
        if tag == "input" and attrs.get("name"):
            kind = (attrs.get("type") or "text").lower()
            if kind in ("checkbox", "radio") and "checked" not in attrs:
                return
            if kind in ("submit", "button", "image", "file", "reset"):
                return
            self._form["fields"].append((attrs["name"], attrs.get("value") or ""))
        elif tag == "textarea" and attrs.get("name"):
            self._textarea, self._buffer = attrs["name"], ""
        elif tag == "select" and attrs.get("name"):
            self._select = attrs["name"]
            self._form["fields"].append((self._select, ""))
        elif tag == "option" and self._select and "selected" in attrs:
            self._form["fields"][-1] = (self._select, attrs.get("value") or "")

    def handle_data(self, data):
        if self._textarea is not None:
            self._buffer += data

    def handle_endtag(self, tag):
        if tag == "textarea" and self._textarea is not None and self._form is not None:
            self._form["fields"].append((self._textarea, self._buffer))
            self._textarea = None
        elif tag == "select":
            self._select = None
        elif tag == "form":
            self._form = None


def html_forms(html: str) -> list[dict]:
    parser = _FormParser()
    try:
        parser.feed(html)
    except Exception:  # malformed markup: keep whatever was parsed
        pass
    return parser.forms


def find_form(html: str, **attrs: str) -> dict | None:
    for form in html_forms(html):
        if all(form["attrs"].get(key) == value for key, value in attrs.items()):
            return form
    return None


def form_fields(form: dict | None, overrides: dict[str, str] | None = None, drop: tuple[str, ...] = ()) -> list:
    """The form's own fields in page order, with overrides replacing (or appending) values."""
    overrides = dict(overrides or {})
    fields = []
    for name, value in (form or {}).get("fields", []):
        if name in drop:
            continue
        if name in overrides:
            if overrides[name] is None:
                continue
            value = overrides.pop(name)
        fields.append((name, value))
    fields.extend((name, value) for name, value in overrides.items() if value is not None)
    return fields
