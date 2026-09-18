"""Convert corpus cases and live audit events into eval fixture records."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import parse_qs, urlsplit

from corpus import CorpusCase, all_cases, to_request_record


ROOT = Path(__file__).resolve().parents[1]
FIXTURES_PATH = ROOT / "eval" / "fixtures.jsonl"


def load_fixtures(path: Path | None = None) -> list[dict[str, Any]]:
    target = path or FIXTURES_PATH
    if not target.exists():
        return []
    return [json.loads(line) for line in target.read_text().splitlines() if line.strip()]


def write_fixtures(records: Iterable[dict[str, Any]], path: Path | None = None) -> None:
    target = path or FIXTURES_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(record, ensure_ascii=False, separators=(",", ":")) for record in records]
    target.write_text("\n".join(lines) + "\n")


def enrich_legacy(record: dict[str, Any]) -> dict[str, Any]:
    """Add label and crs_rule_ids to the original 19-fixture schema."""
    updated = dict(record)
    updated.setdefault("label", record.get("expected", "attack"))
    incident = (record.get("context") or {}).get("incident") or {}
    rule_id = str(incident.get("rule_id") or "")
    existing = record.get("crs_rule_ids") or ([rule_id] if rule_id else [])
    updated["crs_rule_ids"] = [str(item) for item in existing]
    return updated


def case_to_fixture(case: CorpusCase, *, source: str = "synthesized") -> dict[str, Any]:
    query: dict[str, str] = {}
    body: Any = ""
    header_collections = {"REQUEST_HEADERS", "REQUEST_COOKIES", "REQUEST_FILENAME"}
    if case.collection not in header_collections and case.parameter:
        if case.method == "GET":
            query = {case.parameter: case.payload}
        else:
            body = {case.parameter: case.payload}
    headers = dict(case.headers)
    if case.method != "GET" and case.parameter and case.collection not in header_collections:
        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    request: dict[str, Any] = {"headers": headers, "body": body}
    return {
        "id": case.id,
        "expected": case.expected,
        "label": case.label,
        "crs_rule_ids": list(case.crs_rule_ids),
        "source": source,
        "context": {
            "incident": {
                "method": case.method,
                "uri": {"path": case.path, "query": query},
                "path": case.path,
                "rule_id": case.crs_rule_ids[0],
                "collection": case.collection,
                "parameter": case.parameter,
                "matched_data": case.matched_data,
                "other_matches": [
                    {"rule_id": rule_id} for rule_id in case.crs_rule_ids[1:]
                ],
            },
            "request": request,
            "application_context": case.application_context or {},
            "redaction": {"fields": []},
        },
        "notes": case.notes,
    }


def audit_event_to_fixture(
    case: CorpusCase,
    event: dict[str, Any],
    *,
    source: str = "lab-capture",
) -> dict[str, Any]:
    """Overlay observed ModSecurity messages onto a corpus case."""
    transaction = event.get("transaction") or event
    request = transaction.get("request") or {}
    uri = str(request.get("uri") or case.path)
    split = urlsplit(uri)
    query = {key: values[-1] for key, values in parse_qs(split.query).items()}
    messages = transaction.get("messages") or []
    rule_ids: list[str] = []
    primary = None
    other_matches = []
    for message in messages:
        details = message.get("details") or {}
        rule_id = str(details.get("ruleId") or details.get("id") or "")
        if not rule_id or not rule_id.isdigit() or rule_id.startswith("9") is False:
            continue
        if rule_id.startswith("9") and int(rule_id) < 900000:
            continue
        if rule_id in rule_ids:
            continue
        rule_ids.append(rule_id)
        match = {
            "rule_id": rule_id,
            "matched_data": details.get("data") or details.get("match") or message.get("message"),
            "collection": None,
            "parameter": None,
        }
        if primary is None:
            primary = {**match, "message": message.get("message")}
        else:
            other_matches.append(match)
    if not rule_ids:
        rule_ids = list(case.crs_rule_ids)
    fixture = case_to_fixture(case, source=source)
    incident = fixture["context"]["incident"]
    incident["uri"] = {"path": split.path or case.path, "query": query}
    incident["path"] = split.path or case.path
    incident["rule_id"] = (primary or {}).get("rule_id") or rule_ids[0]
    incident["matched_data"] = (primary or {}).get("matched_data") or case.matched_data
    incident["other_matches"] = other_matches
    fixture["crs_rule_ids"] = rule_ids
    fixture["context"]["request"]["headers"] = request.get("headers") or fixture["context"]["request"]["headers"]
    return fixture


def merge_fixtures(
    existing: list[dict[str, Any]],
    generated: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    by_id = {record["id"]: enrich_legacy(record) for record in existing}
    for record in generated:
        current = by_id.get(record["id"])
        if current is None:
            by_id[record["id"]] = record
            continue
        # Preserve original 19 contexts; only fill the new schema fields.
        if current.get("source") in {None, "legacy"} and record["id"].startswith(("benign-", "attack-")) and "context" in current:
            current["label"] = current.get("label") or record["label"]
            if not current.get("crs_rule_ids"):
                current["crs_rule_ids"] = record["crs_rule_ids"]
            current.setdefault("source", "legacy")
        else:
            by_id[record["id"]] = record
    return list(by_id.values())


def synthesize_fixtures() -> list[dict[str, Any]]:
    return [case_to_fixture(case) for case in all_cases()]


def write_request_jsonl(path: Path | None = None) -> Path:
    target = path or (ROOT / "eval" / "corpus" / "requests.jsonl")
    target.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(to_request_record(case), ensure_ascii=False) for case in all_cases()]
    target.write_text("\n".join(lines) + "\n")
    return target
