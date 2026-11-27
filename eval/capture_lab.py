#!/usr/bin/env python3
"""Drive the Docker lab (or synthesize) to produce labeled eval data.

Request-level set (`--requests`): replay eval/corpus.py request_cases() against
DVWA and the Flask Lab Shop through the isolated capture lab
(lab/docker-compose.capture.yml) and write eval/requests.jsonl with the raw
ModSecurity audit record and per-match labels.

Fixture path:
  1. Optionally `docker compose up -d`
  2. Log into DVWA and crawl legitimate flows (benign)
  3. Replay CRS-category attack requests (optionally via go-ftw)
  4. Parse ModSecurity JSON Serial audit logs
  5. Append labeled match-level records to --output (default eval/fixtures.jsonl;
     the committed eval set is eval/requests.jsonl)

If Docker or the lab WAF is unavailable, `--synthesize` (the default fallback)
writes fixtures from eval/corpus.py with cited CRS rule IDs.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "backend"))

from corpus import CorpusCase, RequestCase, all_cases, request_cases, to_ftw_tests  # noqa: E402
from services.audit_event import normalize_audit_event  # noqa: E402
from services.inference_context import (  # noqa: E402
    application_host,
    extract_match_target,
    is_aggregate_match,
    split_request_uri,
)
from services.profile_files import profiles_from_dir  # noqa: E402
from services.profile_match import application_context_for  # noqa: E402
from fixtures import (  # noqa: E402
    FIXTURES_PATH,
    audit_event_to_fixture,
    case_to_fixture,
    load_fixtures,
    merge_fixtures,
    write_fixtures,
)


def _docker_available() -> bool:
    return shutil.which("docker") is not None


def _compose(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    command = ["docker", "compose", *args]
    return subprocess.run(command, cwd=ROOT, check=check, text=True, capture_output=True)


def wait_for_url(url: str, timeout: float = 90.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=3)
            return True
        except (urllib.error.URLError, TimeoutError, OSError):
            time.sleep(2)
    return False


def _extract_token(html: str) -> str:
    import re

    match = re.search(r"name=['\"]user_token['\"]\s+value=['\"]([^'\"]+)['\"]", html, re.I)
    if not match:
        match = re.search(r"value=['\"]([^'\"]+)['\"]\s+name=['\"]user_token['\"]", html, re.I)
    return match.group(1) if match else ""


class LabClient:
    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        data: dict[str, str] | None = None,
        eval_id: str | None = None,
    ) -> int:
        url = self.base_url + path
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params)
        body = None
        req_headers = {"User-Agent": "waf-tuner-eval", **(headers or {})}
        if eval_id:
            req_headers["X-Waf-Tuner-Eval-Id"] = eval_id
        if data is not None:
            body = urllib.parse.urlencode(data).encode()
            req_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        request = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        try:
            with self.opener.open(request, timeout=15) as response:
                return int(getattr(response, "status", 200))
        except urllib.error.HTTPError as exc:
            return int(exc.code)
        except (urllib.error.URLError, TimeoutError, OSError):
            return 0

    def login(self) -> None:
        login_html = self.opener.open(self.base_url + "/login.php", timeout=15).read().decode("utf-8", "replace")
        token = _extract_token(login_html)
        if not token:
            return
        self.request(
            "POST",
            "/login.php",
            data={"username": "admin", "password": "password", "Login": "Login", "user_token": token},
        )
        security_html = self.opener.open(self.base_url + "/security.php", timeout=15).read().decode("utf-8", "replace")
        sec_token = _extract_token(security_html)
        if sec_token:
            self.request(
                "POST",
                "/security.php",
                data={"security": "low", "seclev_submit": "Submit", "user_token": sec_token},
            )


def send_case(client: LabClient, case: CorpusCase) -> int:
    params = None
    data = None
    if case.collection not in {"REQUEST_HEADERS", "REQUEST_COOKIES", "REQUEST_FILENAME"} and case.parameter:
        if case.method == "GET":
            params = {case.parameter: case.payload}
        else:
            data = {case.parameter: case.payload}
    return client.request(
        case.method,
        case.path,
        params=params,
        data=data,
        headers=case.headers,
        eval_id=case.id,
    )


def crawl_benign(client: LabClient) -> None:
    """Hit DVWA's legitimate pages so CRS sees real login/nav/form traffic."""
    for path in (
        "/",
        "/login.php",
        "/index.php",
        "/security.php",
        "/instructions.php",
        "/vulnerabilities/sqli/",
        "/vulnerabilities/xss_r/",
        "/vulnerabilities/xss_s/",
        "/vulnerabilities/exec/",
        "/vulnerabilities/fi/?page=include.php",
    ):
        client.request("GET", path, eval_id=f"crawl-get-{path}")
    client.request(
        "GET",
        "/vulnerabilities/sqli/",
        params={"id": "1", "Submit": "Submit"},
        eval_id="crawl-sqli-numeric",
    )
    client.request(
        "GET",
        "/vulnerabilities/xss_r/",
        params={"name": "Amish"},
        eval_id="crawl-xss-name",
    )
    client.request(
        "POST",
        "/vulnerabilities/xss_s/",
        data={"txtName": "reviewer", "mtxMessage": "Nice lab.", "btnSign": "Sign Guestbook"},
        eval_id="crawl-guestbook",
    )
    client.request(
        "POST",
        "/vulnerabilities/exec/",
        data={"ip": "127.0.0.1", "Submit": "Submit"},
        eval_id="crawl-ping",
    )


def parse_audit_log(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    events = []
    pending = ""
    for line in path.read_text(errors="replace").splitlines():
        pending += line
        try:
            events.append(json.loads(pending))
            pending = ""
        except json.JSONDecodeError:
            pending += "\n"
    return events


def _event_eval_id(event: dict[str, Any]) -> str:
    headers = ((event.get("transaction") or {}).get("request") or {}).get("headers") or {}
    for key, value in headers.items():
        if str(key).lower() == "x-waf-tuner-eval-id":
            return str(value)
    return ""


def write_ftw_yaml_json(path: Path) -> None:
    """Stdlib YAML-ish dump so we do not require PyYAML in CI."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(to_ftw_tests(), indent=2) + "\n")


def maybe_run_go_ftw(base_url: str, tests_path: Path) -> str | None:
    binary = shutil.which("go-ftw") or shutil.which("ftw")
    if binary is None:
        gobin = Path(os.environ.get("GOPATH", str(Path.home() / "go"))) / "bin" / "go-ftw"
        binary = str(gobin) if gobin.exists() else None
    if not binary:
        return "go-ftw not installed"
    parsed = urllib.parse.urlparse(base_url)
    command = [
        binary,
        "run",
        "-d",
        str(tests_path.parent),
        "--host",
        parsed.hostname or "127.0.0.1",
        "--port",
        str(parsed.port or 8080),
    ]
    try:
        completed = subprocess.run(command, cwd=ROOT, check=False, text=True, capture_output=True, timeout=180)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return f"go-ftw failed: {exc}"
    if completed.returncode != 0:
        return f"go-ftw exited {completed.returncode}: {completed.stderr[-500:]}"
    return None


def capture_live(args: argparse.Namespace) -> tuple[list[dict[str, Any]], str]:
    if args.compose:
        if not _docker_available():
            raise RuntimeError("docker is not available")
        _compose(["up", "-d", "--build"])
    if not wait_for_url(args.base_url, timeout=args.timeout):
        raise RuntimeError(f"lab WAF not reachable at {args.base_url}")
    client = LabClient(args.base_url)
    try:
        client.login()
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise RuntimeError(f"DVWA login failed: {exc}") from exc
    crawl_benign(client)
    ftw_dir = ROOT / "eval" / "ftw"
    write_ftw_yaml_json(ftw_dir / "waf-tuner-eval.json")
    ftw_error = maybe_run_go_ftw(args.base_url, ftw_dir / "waf-tuner-eval.json")
    cases = all_cases()
    for case in cases:
        send_case(client, case)
        time.sleep(0.02)
    time.sleep(1.0)
    events = parse_audit_log(Path(args.audit_log))
    events_by_id: dict[str, dict[str, Any]] = {}
    for event in events:
        eval_id = _event_eval_id(event)
        if eval_id:
            events_by_id[eval_id] = event
    fixtures = []
    for case in cases:
        event = events_by_id.get(case.id)
        if event is None:
            fixtures.append(case_to_fixture(case, source="synthesized-missing-audit"))
        else:
            fixtures.append(audit_event_to_fixture(case, event))
    note = f"live capture: {len(events_by_id)}/{len(cases)} cases matched audit events"
    if ftw_error:
        note += f"; {ftw_error}"
    return fixtures, note


REQUESTS_PATH = ROOT / "eval" / "requests.jsonl"
CAPTURE_COMPOSE = ROOT / "lab" / "docker-compose.capture.yml"
CAPTURE_PROJECT = "waftuner-capture"
REQUEST_ID_HEADER = "X-Request-ID"
BROWSER_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}
DEFAULT_COOKIES = {"flask": {"currency": "USD"}, "dvwa": {}}
_ARGS = {"ARGS", "ARGS_GET", "ARGS_POST"}
_URI = {"REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME", "REQUEST_LINE", "QUERY_STRING"}
_WRAPPED_TARGET = re.compile(
    r"(?:^|_)(ARGS(?:_GET|_POST)?|REQUEST_HEADERS|REQUEST_COOKIES|REQUEST_BODY|REQUEST_URI(?:_RAW)?"
    r"|REQUEST_FILENAME|REQUEST_BASENAME|QUERY_STRING)(?::(.+))?$"
)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # A followed redirect would resend the request id and shadow the real audit record.
    def redirect_request(self, *args, **kwargs):
        return None


class ReplayClient:
    """Browser-like client for one lab app, addressed by Host header."""

    def __init__(self, base_url: str, app: str, host: str):
        self.base_url = base_url.rstrip("/")
        self.app = app
        self.host = host
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPCookieProcessor(self.jar))

    def send(self, method: str, path: str, *, fields: dict | None = None, json_body: bool = False,
             headers: dict | None = None, cookies: dict | None = None, request_id: str | None = None) -> tuple[int, str]:
        url = self.base_url + path
        body = None
        req_headers = {"Host": self.host, **BROWSER_HEADERS}
        if fields and method == "GET":
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(fields)
        elif fields is not None and method != "GET":
            if json_body:
                body = json.dumps(fields).encode()
                req_headers["Content-Type"] = "application/json"
            else:
                body = urllib.parse.urlencode(fields).encode()
                req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        jar_cookies = {cookie.name: cookie.value for cookie in self.jar}
        merged = {**jar_cookies, **DEFAULT_COOKIES.get(self.app, {}), **(cookies or {})}
        if merged:
            req_headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in merged.items())
        req_headers.update(headers or {})
        if request_id:
            req_headers[REQUEST_ID_HEADER] = request_id
        request = urllib.request.Request(url, data=body, headers=req_headers, method=method)
        try:
            with self.opener.open(request, timeout=20) as response:
                return int(getattr(response, "status", 200)), response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            return int(exc.code), exc.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError):
            return 0, ""


def prepare_dvwa(client: ReplayClient, timeout: float = 120.0) -> bool:
    """Create the DVWA database, log in and select the low security level."""
    deadline = time.time() + timeout
    status, html = 0, ""
    while time.time() < deadline:
        status, html = client.send("GET", "/setup.php")
        if status == 200 and _extract_token(html):
            break
        time.sleep(3)
    else:
        return False
    client.send("POST", "/setup.php", fields={"create_db": "Create / Reset Database", "user_token": _extract_token(html)})
    for _ in range(10):
        _, html = client.send("GET", "/login.php")
        token = _extract_token(html)
        status, _ = client.send("POST", "/login.php", fields={
            "username": "admin", "password": "password", "Login": "Login", "user_token": token})
        status, html = client.send("GET", "/security.php")
        if status == 200 and _extract_token(html):
            client.send("POST", "/security.php", fields={
                "security": "low", "seclev_submit": "Submit", "user_token": _extract_token(html)})
            return True
        time.sleep(3)
    return False


def send_request_case(client: ReplayClient, case: RequestCase, request_id: str) -> int:
    status, _ = client.send(
        case.method, case.path, fields=case.fields if case.target != "path" else None,
        json_body=case.target == "json" or (case.app == "flask" and case.path == "/api/cart"),
        headers=case.headers, cookies=case.cookies, request_id=request_id,
    )
    return status


def _match_targets(match: dict) -> list[tuple[str, str | None]]:
    """Every way the audit record names the input a match inspected.

    CRS reports some matches through MATCHED_VARS or a TX copy of the input
    (e.g. TX:rfi_parameter_ARGS:name); unwrap those to the original input.
    """
    found = [(match.get("collection"), match.get("parameter"))]
    found.append(extract_match_target(match.get("matched_data") or ""))
    targets = []
    for collection, parameter in found:
        if not collection:
            continue
        collection = collection.upper()
        if collection in {"MATCHED_VARS", "MATCHED_VAR", "TX"} and parameter:
            wrapped = _WRAPPED_TARGET.search(parameter)
            if wrapped:
                collection, parameter = wrapped.group(1), wrapped.group(2)
        targets.append((collection, parameter))
    return targets


def _hits_payload(case: RequestCase, collection: str, parameter: str | None) -> bool:
    target = case.payload_target
    if case.target in {"query", "form", "json"}:
        if collection in _ARGS:
            return parameter == target["parameter"]
        if collection in _URI:
            return case.method == "GET"
        return collection == "REQUEST_BODY" and case.method != "GET"
    if case.target == "header":
        return collection == "REQUEST_HEADERS" and (parameter or "").lower() == case.parameter.lower()
    if case.target == "cookie":
        return collection == "REQUEST_COOKIES" and parameter == case.parameter
    # Path payloads: the URI collections (and the extension CRS copies from the path into
    # TX:EXTENSION), plus ARGS parsed from a query string inside the payload.
    if collection == "TX" and (parameter or "").upper() == "EXTENSION":
        return True
    query_names = {name for name, _ in urllib.parse.parse_qsl(urllib.parse.urlsplit(case.payload).query, keep_blank_values=True)}
    return collection in _URI or (collection in _ARGS and parameter in query_names)


def label_request_matches(case: RequestCase, normalized: dict) -> list[dict[str, Any]]:
    """Label the matches that inspected the payload; aggregates and other inputs stay unlabeled."""
    labels = []
    for index, match in enumerate(normalized["matches"]):
        if is_aggregate_match(match):
            continue
        if any(_hits_payload(case, collection, parameter) for collection, parameter in _match_targets(match)):
            labels.append({"match_index": index, "expected": case.label})
    return labels


def request_record(case: RequestCase, event: dict[str, Any]) -> dict[str, Any] | None:
    normalized = normalize_audit_event(event)
    if normalized is None:
        return None
    labels = label_request_matches(case, normalized)
    if not labels:
        return None
    path = split_request_uri(normalized["uri"]).path or "/"
    _, context = application_context_for(profiles_from_dir(), application_host(normalized), normalized["method"], path)
    stack = {"dvwa": "PHP", "flask": "Python/Flask"}[case.app]
    notes = case.notes or (f"wrong-stack {case.category} payload sent to the {stack} app" if case.wrong_stack else "")
    return {
        "id": case.id,
        "app": case.app,
        "source": "lab-capture",
        "expected_request": case.label,
        "modsec_audit": event,
        "labels": labels,
        "application_context": context,
        "payload_target": case.payload_target,
        "category": case.category,
        "wrong_stack": case.wrong_stack,
        "notes": notes,
    }


def read_audit_log_from(path: Path, offset: int) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    with path.open("rb") as handle:
        handle.seek(offset)
        text = handle.read().decode("utf-8", "replace")
    events = []
    for line in text.splitlines():
        if line.strip():
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def _event_request_id(event: dict[str, Any]) -> str:
    headers = ((event.get("transaction") or {}).get("request") or {}).get("headers") or {}
    return next((str(value) for key, value in headers.items() if str(key).lower() == REQUEST_ID_HEADER.lower()), "")


def capture_requests(args: argparse.Namespace) -> int:
    if args.compose:
        if not os.environ.get("CAPTURE_DIR"):
            raise RuntimeError("set CAPTURE_DIR to a scratch directory for the capture lab")
        subprocess.run(["docker", "compose", "-p", CAPTURE_PROJECT, "-f", str(CAPTURE_COMPOSE), "up", "-d", "--build"],
                       cwd=ROOT, check=True)
    audit_log = Path(args.audit_log)
    if not wait_for_url(args.base_url + "/healthz", timeout=args.timeout):
        raise RuntimeError(f"capture WAF not reachable at {args.base_url}")
    clients = {app: ReplayClient(args.base_url, app, host) for app, host in (("dvwa", "localhost"), ("flask", "shop.lab"))}
    if not prepare_dvwa(clients["dvwa"], timeout=args.timeout):
        print("warning: DVWA setup/login failed; DVWA requests will be redirected to login.php", file=sys.stderr)
    cases = request_cases()
    offset = audit_log.stat().st_size if audit_log.exists() else 0
    ids: dict[str, RequestCase] = {}
    for case in cases:
        request_id = uuid.uuid4().hex
        ids[request_id] = case
        send_request_case(clients[case.app], case, request_id)
        time.sleep(0.02)
    time.sleep(2.0)
    events = {}
    for event in read_audit_log_from(audit_log, offset):
        request_id = _event_request_id(event)
        if request_id in ids:
            events[request_id] = event
    records, missing, unlabeled = [], [], []
    for request_id, case in ids.items():
        event = events.get(request_id)
        if event is None:
            missing.append(case.id)
            continue
        record = request_record(case, event)
        if record is None:
            unlabeled.append(case.id)
        else:
            records.append(record)
    output = Path(args.requests_output)
    output.write_text("".join(json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n" for record in records))
    print(f"sent {len(cases)} requests; {len(events)} audit records; wrote {len(records)} to {output}")
    print(f"dropped {len(unlabeled)} with no labeled match: {', '.join(unlabeled) or '-'}")
    if missing:
        print(f"missing audit record for {len(missing)}: {', '.join(missing)}")
    print_request_stats(records)
    return 0


def print_request_stats(records: list[dict[str, Any]]) -> None:
    by_app = Counter(record["app"] for record in records)
    by_label = Counter((record["app"], record["expected_request"]) for record in records)
    multi = sum(len(record["labels"]) > 1 for record in records)
    header_cookie = 0
    for record in records:
        matches = normalize_audit_event(record["modsec_audit"])["matches"]
        header_cookie += any(matches[label["match_index"]]["collection"] in {"REQUEST_HEADERS", "REQUEST_COOKIES"}
                             or record["payload_target"]["collection"] in {"REQUEST_HEADERS", "REQUEST_COOKIES"}
                             for label in record["labels"])
    print(f"per app: {dict(by_app)}; per app/label: {dict(by_label)}")
    print(f"labeled matches: {sum(len(r['labels']) for r in records)}; records with >1 labeled match: {multi}")
    print(f"records with labeled header/cookie matches: {header_cookie}; wrong-stack: {sum(r['wrong_stack'] for r in records)}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=None,
                        help="WAF URL (default $WAF_BASE_URL, else :8080, or :18080 with --requests)")
    parser.add_argument("--audit-log", default=None,
                        help="audit log (default lab-data/modsec/audit.log, or $CAPTURE_DIR/modsec/audit.log with --requests)")
    parser.add_argument("--output", default=str(FIXTURES_PATH))
    parser.add_argument("--compose", action="store_true",
                        help="run docker compose up -d --build first (the isolated capture lab with --requests)")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--synthesize", action="store_true", help="do not contact the lab")
    parser.add_argument("--requests", action="store_true",
                        help="capture the request-level set (DVWA + Flask) into --requests-output")
    parser.add_argument("--requests-output", default=str(REQUESTS_PATH))
    args = parser.parse_args()
    if args.requests:
        args.base_url = args.base_url or os.environ.get("WAF_BASE_URL", "http://127.0.0.1:18080")
        if args.audit_log is None:
            if not os.environ.get("CAPTURE_DIR"):
                parser.error("--requests needs --audit-log or CAPTURE_DIR")
            args.audit_log = str(Path(os.environ["CAPTURE_DIR"]) / "modsec" / "audit.log")
        return capture_requests(args)
    args.base_url = args.base_url or os.environ.get("WAF_BASE_URL", "http://127.0.0.1:8080")
    args.audit_log = args.audit_log or str(ROOT / "lab-data" / "modsec" / "audit.log")
    output = Path(args.output)

    if args.synthesize:
        generated = [case_to_fixture(case) for case in all_cases()]
        note = "synthesized from eval/corpus.py (lab not contacted)"
    else:
        try:
            generated, note = capture_live(args)
        except (RuntimeError, subprocess.CalledProcessError) as exc:
            generated = [case_to_fixture(case) for case in all_cases()]
            note = f"lab capture failed ({exc}); synthesized from eval/corpus.py"

    merged = merge_fixtures(load_fixtures(output), generated)
    write_fixtures(merged, output)
    ftw_path = ROOT / "eval" / "corpus" / "requests.json"
    write_ftw_yaml_json(ftw_path)
    print(note)
    print(f"Wrote {len(merged)} fixtures to {output}")
    print(f"Request set: {ftw_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
