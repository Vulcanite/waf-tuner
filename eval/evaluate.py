#!/usr/bin/env python3
"""Live or recorded classifier gate for sanitized JSONL fixtures.

Recorded mode reads eval/recordings/<model>.jsonl and never contacts a provider.
Use --record during a live run to append responses for later CI replay.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlencode


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))
sys.path.insert(0, str(ROOT / "backend"))

from scoring import per_rule_matrix, summary_from_counts  # noqa: E402
from services.audit_event import normalize_audit_event  # noqa: E402
from services.crs_index import get_rule, initialize_crs_index  # noqa: E402
from services.inference_context import bound_repair_input, build_inference_context  # noqa: E402
from services.llm_options import (  # noqa: E402
    ESCALATION_EFFORT_REJECTED, is_escalation_effort_rejection, request_payload, request_settings,
)
from services.model_contract import (  # noqa: E402
    CompletionOutputError,
    PROMPT_SHA256,
    PROMPT_VERSION,
    classify_repair_response,
    classify_response,
    completion_text,
    false_positive_threshold,
    repair_messages,
    response_messages,
)


RECORDINGS_DIR = ROOT / "eval" / "recordings"


def fingerprint(value) -> str:
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest()


def fixture_context(fixture: dict) -> dict:
    event = fixture.get("audit_event")
    match_index = fixture.get("match_index", 0)
    if event is None and "modsec_audit" in fixture:
        event = normalize_audit_event(fixture["modsec_audit"])
        if event is None:
            raise ValueError(f"fixture {fixture['id']} has no usable ModSecurity audit evidence")
    if event is None:
        legacy = fixture["context"]
        incident = legacy["incident"]
        uri = incident.get("uri") or {}
        if isinstance(uri, dict):
            path = uri.get("path") or incident.get("path") or "/"
            query = uri.get("query") or {}
            uri = path + ("?" + urlencode(query, doseq=True) if query else "")
        match_index = 0
        event = {
            "method": incident.get("method"),
            "uri": uri or incident.get("path") or "/",
            "raw_request": legacy.get("request"),
            "anomaly_score": incident.get("anomaly_score"),
            "matches": [incident, *(incident.get("other_matches") or [])],
        }
    else:
        legacy = fixture.get("context") or {}
    if type(match_index) is not int or not 0 <= match_index < len(event.get("matches") or []):
        raise ValueError(f"fixture {fixture['id']} has an invalid match_index")
    match = event["matches"][match_index]
    return build_inference_context(
        event,
        match,
        match_index=match_index,
        crs_rule=get_rule(match.get("rule_id")) or legacy.get("crs_rule"),
        application_context=fixture.get("application_context") or legacy.get("application_context"),
        collection=match.get("collection"),
        parameter=match.get("parameter"),
    )


def request(messages, settings, attempt_type="initial"):
    body = json.dumps(request_payload(settings, messages, attempt_type), ensure_ascii=False).encode()
    req = urllib.request.Request(
        settings["base_url"].rstrip("/") + "/chat/completions",
        data=body,
        headers={
            "Authorization": "Bearer " + settings["api_key"],
            "Content-Type": "application/json",
            **settings["headers"],
        },
        method="POST",
    )
    started = time.perf_counter()
    tls = ssl._create_unverified_context() if not settings["verify_ssl"] else None
    with urllib.request.urlopen(req, timeout=settings["timeout"], context=tls) as response:
        payload = json.load(response)
    latency = round((time.perf_counter() - started) * 1000)
    choices = payload.get("choices") or []
    choice = choices[0] if choices else {}
    return choice, latency, payload.get("usage") or {}


def merge_usage(first, second):
    merged = {}
    for key in set(first) | set(second):
        left, right = first.get(key), second.get(key)
        if isinstance(left, (int, float)) or isinstance(right, (int, float)):
            merged[key] = (left if isinstance(left, (int, float)) else 0) + (right if isinstance(right, (int, float)) else 0)
        elif isinstance(left, dict) and isinstance(right, dict):
            merged[key] = merge_usage(left, right)
        else:
            merged[key] = right if right is not None else left
    return merged


def recording_path(model: str, recordings_dir: Path | None = None) -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]+", "_", model).strip("_") or "model"
    return (recordings_dir or RECORDINGS_DIR) / f"{safe}.jsonl"


def load_recordings(path: Path) -> dict[str, dict]:
    if not path.exists():
        return {}
    records = {}
    for line in path.read_text().splitlines():
        if not line.strip():
            continue
        item = json.loads(line)
        records[item["id"]] = item
    return records


def write_recordings(path: Path, records: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(item, ensure_ascii=False) + "\n" for item in records))


def oracle_response(expected: str) -> dict:
    classification = "true_positive" if expected == "attack" else "false_positive"
    return {
        "classification": classification,
        "confidence": 0.99,
        "verdict": "Recorded oracle label matching the fixture expected class.",
        "context_factors": ["recorded-oracle"],
        "uncertainty_factors": [],
    }


def classify_recorded(fixture: dict, recording: dict | None) -> dict:
    if recording is None:
        return {
            "id": fixture["id"],
            "expected": fixture.get("expected") or fixture.get("label"),
            "valid": False,
            "repaired": False,
            "classification": None,
            "latency_ms": 0,
            "token_usage": {},
            "finish_reason": "missing_recording",
        }
    raw = recording.get("raw") or ""
    repaired = bool(recording.get("repaired"))
    parsed = None
    finish = recording.get("finish_reason")
    expected_digest = recording.get("fixture_sha256")
    if expected_digest and expected_digest != fingerprint(fixture):
        finish = "fixture_mismatch"
    else:
        try:
            text = completion_text({"finish_reason": finish, "message": {"content": raw}})
            threshold = recording.get("false_positive_threshold")
            repair_input = recording.get("repair_input")
            if repair_input:
                parsed = classify_repair_response(text, repair_input, threshold=threshold)
            else:
                parsed = classify_response(text, threshold=threshold)
        except ValueError:
            pass
    return {
        "id": fixture["id"],
        "expected": fixture.get("expected") or fixture.get("label"),
        "valid": parsed is not None,
        "repaired": repaired,
        "classification": parsed.get("classification") if parsed else None,
        "latency_ms": recording.get("latency_ms") or 0,
        "token_usage": recording.get("token_usage") or {},
        "finish_reason": finish,
        "escalated": bool(recording.get("escalated")),
        "crs_rule_ids": recording.get("crs_rule_ids") or [],
        "crs_rule_available": recording.get("crs_rule_available"),
        "recording_provenance": {
            key: recording[key] for key in (
                "prompt_version", "prompt_sha256", "settings", "fixture_sha256", "input_sha256", "false_positive_threshold"
            ) if key in recording
        },
    }


def classify_live(fixture: dict, settings: dict) -> tuple[dict, dict]:
    context = fixture_context(fixture)
    messages = response_messages(context)
    choice, latency, usage = request(messages, settings)
    finish = choice.get("finish_reason")
    raw = ""
    repaired = False
    final_repair_input = None
    escalated = False
    parsed = None
    try:
        raw = completion_text(choice)
    except CompletionOutputError as exc:
        raw = exc.raw_response
        finish = "length" if exc.code == "truncated_output" else exc.code
    else:
        try:
            parsed = classify_response(raw)
        except ValueError:
            repair_input = bound_repair_input(raw, context)
            if repair_input:
                repaired = True
                choice, repair_latency, repair_usage = request(repair_messages(repair_input), settings, "repair")
                latency += repair_latency
                usage = merge_usage(usage, repair_usage)
                finish = choice.get("finish_reason")
                try:
                    raw = completion_text(choice)
                    final_repair_input = repair_input
                    parsed = classify_repair_response(raw, repair_input)
                except CompletionOutputError as exc:
                    raw = exc.raw_response
                    finish = "length" if exc.code == "truncated_output" else exc.code
                except ValueError:
                    pass
    if (
        parsed and parsed["classification"] == "uncertain"
        and settings.get("escalation_effort") and not settings.get("escalation_error")
    ):
        escalated = True
        try:
            choice, extra_latency, extra_usage = request(messages, settings, "escalation")
            latency += extra_latency
            usage = merge_usage(usage, extra_usage)
            escalated_raw = completion_text(choice)
            parsed = classify_response(escalated_raw)
        except urllib.error.HTTPError as exc:
            details = ""
            try:
                with exc:
                    if exc.code in (400, 422):
                        details = exc.read(4096).decode("utf-8", errors="replace")
            except OSError:
                pass
            if is_escalation_effort_rejection(exc.code, details):
                settings["escalation_error"] = ESCALATION_EFFORT_REJECTED
                print(ESCALATION_EFFORT_REJECTED, file=sys.stderr)
        except (ValueError, urllib.error.URLError, TimeoutError):
            pass
        else:
            raw, finish = escalated_raw, choice.get("finish_reason")
            final_repair_input = None
    recording = {
        "id": fixture["id"],
        "raw": raw,
        "repaired": repaired,
        "escalated": escalated,
        "latency_ms": latency,
        "token_usage": usage,
        "finish_reason": finish,
        "classification": parsed["classification"] if parsed else None,
        "fixture_sha256": fingerprint(fixture),
        "input_sha256": fingerprint(messages),
        "crs_rule_ids": [context["incident"]["rule_id"]] if (context.get("incident") or {}).get("rule_id") else [],
        "crs_rule_available": bool(context.get("crs_rule")),
        "prompt_version": PROMPT_VERSION,
        "prompt_sha256": PROMPT_SHA256,
        "settings": public_settings(settings),
        "false_positive_threshold": false_positive_threshold(),
    }
    if final_repair_input:
        candidate = json.loads(final_repair_input)
        recording["repair_input"] = json.dumps({
            key: candidate[key] for key in ("classification", "confidence") if key in candidate
        })
    return classify_recorded(fixture, recording), recording


def public_settings(settings):
    return {
        key: value for key, value in settings.items()
        if key in {"model", "max_tokens", "temperature", "timeout", "structured_output", "verify_ssl",
                   "escalation_effort", "escalation_error", "thinking", "reasoning_effort", "mode", "crs_ruleset_digest"}
    }


def build_report(fixtures, results, settings, model: str) -> dict:
    matrix = per_rule_matrix(fixtures, results)
    counts = matrix["overall"]["counts"]
    latencies = sorted(row["latency_ms"] for row in results if row.get("latency_ms"))
    provenances = [row.get("recording_provenance") or {} for row in results]
    prompts = {(p.get("prompt_version"), p.get("prompt_sha256")) for p in provenances}
    prompt_version, prompt_sha256 = next(iter(prompts)) if len(prompts) == 1 else (None, None)
    summary = summary_from_counts(counts)
    summary["latency_ms"] = {
        f"p{p}": latencies[math.ceil(p * len(latencies) / 100) - 1] if latencies else None
        for p in (50, 95, 100)
    }
    known_crs_coverage = [row["crs_rule_available"] for row in results if row.get("crs_rule_available") is not None]
    summary["crs_evidence"] = (
        {"available": sum(known_crs_coverage), "measured": len(known_crs_coverage)} if known_crs_coverage else None
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "prompt_version": prompt_version,
        "prompt_sha256": prompt_sha256,
        "settings": public_settings(settings),
        "fixtures_sha256": fingerprint(fixtures),
        "summary": summary,
        "confusion": matrix,
        "results": results,
    }


def load_fixture_rows(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    ids = set()
    for row in rows:
        fixture_id = row.get("id")
        if not isinstance(fixture_id, str) or not fixture_id or fixture_id in ids:
            raise ValueError("evaluation fixture IDs must be nonempty and unique")
        if (row.get("expected") or row.get("label")) not in {"attack", "true_positive", "false_positive", "benign"}:
            raise ValueError(f"fixture {fixture_id} requires an attack or false_positive label")
        ids.add(fixture_id)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", default=str(ROOT / "eval/fixtures.jsonl"))
    parser.add_argument("--output", default=str(ROOT / "eval/report.json"))
    parser.add_argument("--mode", choices=["live", "recorded"], default="live")
    parser.add_argument("--model", default=os.getenv("LLM_MODEL", "Foundation-Sec-1.1-8B-Instruct"))
    parser.add_argument("--recordings-dir", default=str(RECORDINGS_DIR))
    parser.add_argument("--crs-rules-dir", default=os.getenv("CRS_RULES_DIR") or str(ROOT / "lab-data" / "crs-rules"))
    parser.add_argument("--record", action="store_true", help="save live responses after all calls complete")
    parser.add_argument("--record-as", help="alternate recording name for a model/settings comparison")
    args = parser.parse_args(argv)
    fixtures = load_fixture_rows(Path(args.fixtures))
    if not fixtures:
        raise ValueError("evaluation requires at least one fixture")
    results = []
    recordings_file = recording_path(args.record_as or args.model, Path(args.recordings_dir))
    if args.mode == "recorded":
        settings = {"model": args.model, "mode": "recorded"}
        stored = load_recordings(recordings_file)
        for fixture in fixtures:
            results.append(classify_recorded(fixture, stored.get(fixture["id"])))
            print(f"{fixture['id']}: {results[-1]['classification'] or 'INVALID'}")
    else:
        ruleset = initialize_crs_index(args.crs_rules_dir)
        if not ruleset["rules"]:
            raise ValueError("live eval requires CRS .conf files or a verified snapshot via --crs-rules-dir")
        settings = {**request_settings(model=args.model), "mode": "live", "crs_ruleset_digest": ruleset["digest"]}
        recordings = []
        for fixture in fixtures:
            result, recording = classify_live(fixture, settings)
            results.append(result)
            if args.record:
                recordings.append(recording)
            print(f"{fixture['id']}: {result['classification'] or 'INVALID'}{' (repaired)' if result['repaired'] else ''}")
        if args.record:
            write_recordings(recordings_file, recordings)
    report = build_report(fixtures, results, settings, args.model)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    failed = report["summary"]["schema_valid"] != len(results) or report["summary"]["attack_false_positives"] > 0
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Provider request failed: {exc}", file=sys.stderr)
        sys.exit(2)
    except (RuntimeError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
