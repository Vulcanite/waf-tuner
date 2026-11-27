#!/usr/bin/env python3
"""Live or recorded classifier gate for sanitized JSONL fixtures.

Two fixture shapes are accepted, one per line:
- request-level (eval/requests.jsonl, the default): a raw `modsec_audit` record plus `labels`,
  a list of {match_index, expected}. Only labeled matches are scored;
- match-level: one match per fixture with `expected`/`label` and an optional `match_index`.

Each labeled match gets one model call, built exactly as the backend worker builds it.

Recorded mode reads eval/recordings/<name>.jsonl and never contacts a provider. Use --record
during a live run to write responses for later replay.
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

from scoring import expected_class, per_rule_matrix, run_metrics, summary_from_counts, token_totals  # noqa: E402
from services.audit_event import normalize_audit_event  # noqa: E402
from services.crs_index import get_rule_at, initialize_crs_index  # noqa: E402
from services.inference_context import (  # noqa: E402
    bound_repair_input, build_inference_context, is_aggregate_match, match_evidence_withheld, match_target,
)
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
from services.profile_match import route_supports_exception  # noqa: E402


RECORDINGS_DIR = ROOT / "eval" / "recordings"
DEFAULT_FIXTURES = ROOT / "eval" / "requests.jsonl"
PROVENANCE_KEYS = (
    "prompt_version", "prompt_sha256", "settings", "fixture_sha256", "input_sha256", "false_positive_threshold",
)


def fingerprint(value) -> str:
    data = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(data).hexdigest()


def is_request_fixture(fixture: dict) -> bool:
    return "labels" in fixture


def fixture_event(fixture: dict) -> tuple[dict, int, dict]:
    """(normalized audit event, the match-level fixture's match_index, legacy context)."""
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
    return event, match_index, legacy


def _event_or_none(fixture: dict):
    """Recorded mode only needs match metadata, so a fixture without evidence still scores."""
    try:
        return fixture_event(fixture)
    except (KeyError, TypeError, ValueError):
        return None, fixture.get("match_index", 0), {}


def fixture_labels(fixture: dict) -> list[dict]:
    """The scored matches of a fixture: row id, match_index, expected label, optional wrong_stack."""
    if not is_request_fixture(fixture):
        label = {"row_id": fixture["id"], "match_index": fixture.get("match_index", 0),
                 "expected": expected_class(fixture)}
        if isinstance(fixture.get("wrong_stack"), bool):
            label["wrong_stack"] = fixture["wrong_stack"]
        return [label]
    labels = []
    for item in fixture["labels"]:
        label = {"row_id": f"{fixture['id']}#{item['match_index']}", "match_index": item["match_index"],
                 "expected": expected_class(item)}
        wrong_stack = item.get("wrong_stack", fixture.get("wrong_stack"))
        if isinstance(wrong_stack, bool):
            label["wrong_stack"] = wrong_stack
        labels.append(label)
    return sorted(labels, key=lambda label: label["match_index"])


def check_match_indexes(fixture: dict, event: dict, indexes: list[int]) -> None:
    matches = event.get("matches") or []
    for index in indexes:
        if type(index) is not int or not 0 <= index < len(matches):
            raise ValueError(f"fixture {fixture['id']} has an invalid match_index {index!r}")
    if is_request_fixture(fixture):
        aggregate = [index for index in indexes if is_aggregate_match(matches[index])]
        if aggregate:
            # The worker never queues anomaly-score matches.
            raise ValueError(f"fixture {fixture['id']} labels aggregate (anomaly-score) match {aggregate[0]}")


def _crs_rule(event: dict, match: dict, legacy: dict):
    # Same lookup as the worker: the ruleset pinned when the alert was ingested, else the current one.
    return get_rule_at(match.get("rule_id"), event.get("crs_ruleset_digest")) or legacy.get("crs_rule")


def _application_context(fixture: dict, legacy: dict):
    return fixture.get("application_context") or legacy.get("application_context")


def match_context(fixture: dict, event: dict, legacy: dict, match_index: int) -> dict:
    """Exactly the worker's build_inference_context call for one match."""
    match = event["matches"][match_index]
    return build_inference_context(
        event,
        match,
        match_index=match_index,
        crs_rule=_crs_rule(event, match, legacy),
        application_context=_application_context(fixture, legacy),
        collection=match.get("collection"),
        parameter=match.get("parameter"),
    )


def gate_inputs(view: dict) -> dict:
    """The worker's per-match evidence gate (agent._finalize_case) on a per-match context."""
    redaction = view.get("redaction") or {}
    return {
        "evidence_withheld": match_evidence_withheld(view),
        "target_hidden": bool(redaction.get("target_hidden")),
        "truncated": bool(redaction.get("truncated")),
    }


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


def _safe_name(name: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("_") or "model"


def recording_path(model: str, recordings_dir: Path | None = None) -> Path:
    return (recordings_dir or RECORDINGS_DIR) / f"{_safe_name(model)}.jsonl"


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


def oracle_recordings(fixtures: list[dict]) -> list[dict]:
    """One recording per labeled match that answers with the label, so CI can replay without a provider."""
    records = []
    for fixture in fixtures:
        digest = fingerprint(fixture)
        for label in fixture_labels(fixture):
            parsed = oracle_response(label["expected"])
            records.append({
                "id": label["row_id"], "raw": json.dumps(parsed), "repaired": False, "latency_ms": 0,
                "token_usage": {}, "finish_reason": "stop", "classification": parsed["classification"],
                "fixture_sha256": digest, "source": "oracle",
            })
    return records


def parse_recording(recording: dict, digest: str):
    """Validate a stored response exactly as the worker would: (verdict or None, finish_reason).

    An escalated recording stores the escalation in `raw`, which is final, as in the worker.
    """
    finish = recording.get("finish_reason")
    expected_digest = recording.get("fixture_sha256")
    if expected_digest and expected_digest != digest:
        return None, "fixture_mismatch"
    threshold = recording.get("false_positive_threshold")
    repair_input = recording.get("repair_input")
    try:
        # A cut-off, refused, or empty completion is never parsed.
        text = completion_text({"finish_reason": finish, "message": {"content": recording.get("raw") or ""}})
        if repair_input:
            return classify_repair_response(text, repair_input, threshold=threshold), finish
        return classify_response(text, threshold=threshold), finish
    except (ValueError, TypeError, KeyError):
        return None, finish


def _finish_code(exc: CompletionOutputError) -> str:
    return "length" if exc.code == "truncated_output" else exc.code


def call_live(messages, settings: dict, context: dict) -> dict:
    """One match against the provider with the worker's rules (agent._call_model): at most one
    repair, a repair keeps the classification, escalation only for an unrepaired valid uncertain
    first pass, cut-off output never parsed."""
    state = {"calls": 0, "latency": 0, "usage": {}}

    def send(msgs, attempt_type):
        state["calls"] += 1
        choice, latency, usage = request(msgs, settings, attempt_type)
        state["latency"] += latency
        state["usage"] = merge_usage(state["usage"], usage)
        return choice

    choice = send(messages, "initial")
    finish = choice.get("finish_reason")
    raw = ""
    initial_raw = None
    repaired = False
    escalated = False
    final_repair_input = None
    parsed = None
    try:
        raw = completion_text(choice)
    except CompletionOutputError as exc:
        raw, finish = exc.raw_response, _finish_code(exc)
    else:
        try:
            parsed = classify_response(raw)
        except (ValueError, TypeError):
            repair_input = bound_repair_input(raw, context)
            if repair_input:
                repaired = True
                choice = send(repair_messages(repair_input), "repair")
                finish = choice.get("finish_reason")
                try:
                    raw = completion_text(choice)
                    final_repair_input = repair_input
                    parsed = classify_repair_response(raw, repair_input)
                except CompletionOutputError as exc:
                    raw, finish = exc.raw_response, _finish_code(exc)
                except (ValueError, TypeError, KeyError):
                    pass
    # Same rule as the backend worker: a repaired verdict is final, so only a first-pass "uncertain" escalates.
    if (
        parsed and not repaired and parsed["classification"] == "uncertain"
        and settings.get("escalation_effort") and not settings.get("escalation_error")
    ):
        escalated = True
        try:
            choice = send(messages, "escalation")
            escalated_raw = completion_text(choice)
            escalated_verdict = classify_response(escalated_raw)
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
        except (ValueError, TypeError, urllib.error.URLError, TimeoutError):
            pass
        else:
            parsed = escalated_verdict
            initial_raw, raw, finish = raw, escalated_raw, choice.get("finish_reason")
            final_repair_input = None
    recording = {
        "raw": raw,
        **({"initial_raw": initial_raw} if initial_raw is not None else {}),
        "repaired": repaired,
        "escalated": escalated,
        "model_calls": state["calls"],
        "latency_ms": state["latency"],
        "token_usage": state["usage"],
        "finish_reason": finish,
        "input_sha256": fingerprint(messages),
        "prompt_version": PROMPT_VERSION,
        "prompt_sha256": PROMPT_SHA256,
        "settings": public_settings(settings),
        "false_positive_threshold": false_positive_threshold(),
    }
    recording["classification"] = parsed["classification"] if parsed else None
    if final_repair_input:
        # Keep only the candidate label the repair was bound to, never the evidence.
        candidate = json.loads(final_repair_input)
        recording["repair_input"] = json.dumps(
            {key: candidate[key] for key in ("classification", "confidence") if key in candidate}
        )
    return recording


def _model_calls(recording: dict | None) -> int:
    if recording is None:
        return 0
    if isinstance(recording.get("model_calls"), int):
        return recording["model_calls"]
    return 1 + bool(recording.get("repaired")) + bool(recording.get("escalated"))


def _route_supported(fixture: dict, legacy: dict, event: dict | None, match: dict) -> bool | None:
    """The worker's route gate (route_supports_exception): the fixture's specific route documents
    this exact target. The worker also needs a captured host; that is left to the live scope."""
    if event is None or not match:
        return None
    collection, parameter = match_target(match)
    return route_supports_exception(_application_context(fixture, legacy) or {}, collection, parameter)


def _row(fixture, label, event, legacy, recording, verdict, finish) -> dict:
    index = label["match_index"]
    matches = (event or {}).get("matches") or []
    match = matches[index] if type(index) is int and 0 <= index < len(matches) else {}
    rule_ids = [str(match["rule_id"])] if match.get("rule_id") else list((recording or {}).get("crs_rule_ids") or [])
    available = (recording or {}).get("crs_rule_available")
    # Recorded at live time from the exact context sent; absent in older recordings.
    gate = ((recording or {}).get("gate_inputs") or {}).get(str(index)) or {}
    row = {
        "id": label["row_id"],
        "request_id": fixture["id"],
        "match_index": index,
        "rule_id": rule_ids[0] if rule_ids else None,
        "collection": match.get("collection"),
        "parameter": match.get("parameter"),
        "expected": label["expected"],
        "valid": verdict is not None,
        "repaired": bool((recording or {}).get("repaired")),
        "escalated": bool((recording or {}).get("escalated")),
        "classification": verdict["classification"] if verdict else None,
        "applies_to_stack": verdict.get("applies_to_stack") if verdict else None,
        "finish_reason": finish,
        "crs_rule_ids": rule_ids,
        "crs_rule_available": available,
        "evidence_withheld": gate.get("evidence_withheld"),
        "route_supports_exception": _route_supported(fixture, legacy, event, match),
    }
    if "wrong_stack" in label:
        row["wrong_stack"] = label["wrong_stack"]
    if recording is not None:
        row["recording_provenance"] = {key: recording[key] for key in PROVENANCE_KEYS if key in recording}
    return row


def evaluate_fixture(fixture: dict, *, stored: dict | None = None, settings: dict | None = None):
    """Score one fixture. Live when `settings` is given, else replay from `stored`.

    Returns (rows, calls, recordings): per labeled match one row, one call entry with its token
    usage and, when live, one recording.
    """
    live = settings is not None
    labels = fixture_labels(fixture)
    indexes = [label["match_index"] for label in labels]
    if live:
        event, _, legacy = fixture_event(fixture)
        check_match_indexes(fixture, event, indexes)
    else:
        event, _, legacy = _event_or_none(fixture)
    digest = fingerprint(fixture)
    rows, calls, recordings = [], [], []
    for label in labels:
        call_id, index = label["row_id"], label["match_index"]
        if live:
            context = match_context(fixture, event, legacy, index)
            rule_id = event["matches"][index].get("rule_id")
            recording = {"id": call_id, "request_id": fixture["id"],
                         **call_live(response_messages(context), settings, context),
                         "fixture_sha256": digest, "crs_rule_available": bool(context.get("crs_rule")),
                         "gate_inputs": {str(index): gate_inputs(context)},
                         "crs_rule_ids": [str(rule_id)] if rule_id else []}
            recordings.append(recording)
        else:
            recording = (stored or {}).get(call_id)
        if recording is None:
            verdict, finish = None, "missing_recording"
        else:
            verdict, finish = parse_recording(recording, digest)
        rows.append(_row(fixture, label, event, legacy, recording, verdict, finish))
        calls.append({
            "id": call_id,
            "request_id": fixture["id"],
            "model_calls": _model_calls(recording),
            "latency_ms": (recording or {}).get("latency_ms") or 0,
            "token_usage": (recording or {}).get("token_usage") or {},
            "finish_reason": finish,
        })
    return rows, calls, recordings


def public_settings(settings):
    return {
        key: value for key, value in settings.items()
        if key in {"model", "max_tokens", "temperature", "timeout", "structured_output", "verify_ssl",
                   "escalation_effort", "escalation_error", "thinking", "reasoning_effort", "mode", "crs_ruleset_digest"}
    }


def build_report(fixtures, results, settings, model: str, calls: list[dict]) -> dict:
    matrix = per_rule_matrix(fixtures, results)
    counts = matrix["overall"]["counts"]
    latencies = sorted(call["latency_ms"] for call in calls if call.get("latency_ms"))
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
    metrics = run_metrics(results)
    summary.update(metrics)
    summary["tokens"] = token_totals(calls, metrics["requests"], metrics["scored_matches"])
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
        "calls": calls,
    }


def _check_request_fixture(row: dict) -> None:
    fixture_id = row["id"]
    labels = row.get("labels")
    if not isinstance(labels, list) or not labels:
        raise ValueError(f"request fixture {fixture_id} needs a nonempty labels list")
    if row.get("expected_request") not in (None, "attack", "false_positive"):
        raise ValueError(f"request fixture {fixture_id} has an unknown expected_request")
    indexes = []
    for label in labels:
        if not isinstance(label, dict) or label.get("expected") not in {"attack", "false_positive"}:
            raise ValueError(f"request fixture {fixture_id} labels need expected attack or false_positive")
        indexes.append(label.get("match_index"))
    if len(set(map(repr, indexes))) != len(indexes):
        raise ValueError(f"request fixture {fixture_id} labels a match_index twice")
    if "modsec_audit" not in row and "audit_event" not in row:
        raise ValueError(f"request fixture {fixture_id} needs a modsec_audit record")
    event, _, _ = fixture_event(row)
    check_match_indexes(row, event, indexes)


def load_fixture_rows(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    ids = set()
    for row in rows:
        fixture_id = row.get("id")
        if not isinstance(fixture_id, str) or not fixture_id or fixture_id in ids:
            raise ValueError("evaluation fixture IDs must be nonempty and unique")
        if is_request_fixture(row):
            _check_request_fixture(row)
        elif (row.get("expected") or row.get("label")) not in {"attack", "true_positive", "false_positive", "benign"}:
            raise ValueError(f"fixture {fixture_id} requires an attack or false_positive label")
        ids.add(fixture_id)
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", default=str(DEFAULT_FIXTURES))
    parser.add_argument("--output", default=str(ROOT / "eval/report.json"))
    parser.add_argument("--mode", choices=["live", "recorded"], default="live")
    parser.add_argument("--model", default=os.getenv("LLM_MODEL", "Foundation-Sec-1.1-8B-Instruct"))
    parser.add_argument("--recordings-dir", default=str(RECORDINGS_DIR))
    parser.add_argument("--crs-rules-dir", default=os.getenv("CRS_RULES_DIR") or str(ROOT / "lab-data" / "crs-rules"))
    parser.add_argument("--record", action="store_true", help="save live responses after all calls complete")
    parser.add_argument(
        "--min-attack-detection", type=float,
        default=float(os.getenv("EVAL_MIN_ATTACK_DETECTION", "0.5")),
        help="fail when fewer attacks than this share are classified true_positive (default 0.5)",
    )
    parser.add_argument("--record-as", help="recording name instead of the model (file <name>.jsonl)")
    parser.add_argument("--write-oracle", action="store_true",
                        help="write recordings/oracle.jsonl from the fixture labels and exit")
    args = parser.parse_args(argv)
    fixtures = load_fixture_rows(Path(args.fixtures))
    if not fixtures:
        raise ValueError("evaluation requires at least one fixture")
    name = args.record_as or args.model
    recordings_dir = Path(args.recordings_dir)
    if args.write_oracle:
        write_recordings(recording_path("oracle", recordings_dir), oracle_recordings(fixtures))
        return 0
    results, calls, recordings = [], [], []
    if args.mode == "recorded":
        settings = {"model": args.model, "mode": "recorded"}
        path = recording_path(name, recordings_dir)
        if not path.exists():
            raise ValueError(f"no recordings for {name} at {path}")
        stored = load_recordings(path)
    else:
        ruleset = initialize_crs_index(args.crs_rules_dir)
        if not ruleset["rules"]:
            raise ValueError("live eval requires CRS .conf files or a verified snapshot via --crs-rules-dir")
        settings = {**request_settings(model=args.model), "mode": "live", "crs_ruleset_digest": ruleset["digest"]}
        stored = None
    for fixture in fixtures:
        if stored is None:
            rows, fixture_calls, fixture_recordings = evaluate_fixture(fixture, settings=settings)
        else:
            rows, fixture_calls, fixture_recordings = evaluate_fixture(fixture, stored=stored)
        results.extend(rows)
        calls.extend(fixture_calls)
        recordings.extend(fixture_recordings)
        for row in rows:
            print(f"{row['id']}: {row['classification'] or 'INVALID'}{' (repaired)' if row['repaired'] else ''}")
    if args.mode == "live" and args.record:
        write_recordings(recording_path(name, recordings_dir), recordings)
    report = build_report(fixtures, results, settings, args.model, calls)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    summary = report["summary"]
    failed = summary["schema_valid"] != len(results) or summary["attack_false_positives"] > 0
    detection = summary["attack_detection"]
    # Safety alone is not enough: a model that answers "uncertain" to everything would otherwise pass.
    if detection is not None and detection < args.min_attack_detection:
        print(f"Attack detection {detection:.0%} is below the {args.min_attack_detection:.0%} floor", file=sys.stderr)
        failed = True
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
