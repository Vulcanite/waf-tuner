#!/usr/bin/env python3
"""Drive the Docker DVWA lab (or synthesize) to produce labeled eval fixtures.

Live path:
  1. Optionally `docker compose up -d`
  2. Log into DVWA and crawl legitimate flows (benign)
  3. Replay CRS-category attack requests (optionally via go-ftw)
  4. Parse ModSecurity JSON Serial audit logs
  5. Append labeled records to eval/fixtures.jsonl

If Docker or the lab WAF is unavailable, `--synthesize` (the default fallback)
writes fixtures from eval/corpus.py with cited CRS rule IDs.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

from corpus import CorpusCase, all_cases, to_ftw_tests  # noqa: E402
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", default=os.environ.get("WAF_BASE_URL", "http://127.0.0.1:8080"))
    parser.add_argument("--audit-log", default=str(ROOT / "lab-data" / "modsec" / "audit.log"))
    parser.add_argument("--output", default=str(FIXTURES_PATH))
    parser.add_argument("--compose", action="store_true", help="run docker compose up -d --build first")
    parser.add_argument("--timeout", type=float, default=90.0)
    parser.add_argument("--synthesize", action="store_true", help="do not contact the lab")
    args = parser.parse_args()
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
