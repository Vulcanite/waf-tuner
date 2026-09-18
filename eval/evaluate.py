#!/usr/bin/env python3
"""Live or recorded classifier gate for sanitized JSONL fixtures.

Recorded mode reads eval/recordings/<model>.jsonl and never contacts a provider.
Use --record during a live run to append responses for later CI replay.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

from scoring import per_rule_matrix, summary_from_counts  # noqa: E402


def constant(name):
    tree = ast.parse((ROOT / "backend/services/agent.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise RuntimeError(f"Could not load {name} from backend/services/agent.py")


SYSTEM_PROMPT = constant("SYSTEM_PROMPT")
REPAIR_PROMPT = constant("JSON_REPAIR_PROMPT")
EXPECTED_KEYS = {"classification", "confidence", "verdict", "context_factors", "uncertainty_factors"}
RECORDINGS_DIR = ROOT / "eval" / "recordings"


def extract(raw):
    clean = (raw or "").strip().replace("</assistant>", "").strip()
    candidates = [clean]
    candidates.extend(reversed(re.findall(r"```(?:json)?\s*(.*?)```", clean, re.I | re.S)))
    decoder = json.JSONDecoder()
    candidates.extend(clean[index:] for index, char in enumerate(clean) if char == "{")
    for candidate in candidates:
        try:
            value, _ = decoder.raw_decode(candidate.strip())
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and set(value) == EXPECTED_KEYS and value.get("classification") in {"false_positive", "true_positive", "uncertain"}:
            return value
    raise ValueError("no valid response object")


def request(messages, settings):
    if not settings.get("api_key"):
        raise RuntimeError("LLM_API_KEY is empty; use --mode recorded")
    body = json.dumps({
        "model": settings["model"], "messages": messages,
        "max_tokens": settings["max_tokens"], "temperature": settings["temperature"],
    }).encode()
    req = urllib.request.Request(
        settings["base_url"].rstrip("/") + "/chat/completions",
        data=body,
        headers={"Authorization": "Bearer " + settings["api_key"], "Content-Type": "application/json"},
        method="POST",
    )
    started = time.perf_counter()
    with urllib.request.urlopen(req, timeout=settings["timeout"]) as response:
        payload = json.load(response)
    latency = round((time.perf_counter() - started) * 1000)
    choice = payload["choices"][0]
    raw = choice.get("message", {}).get("content") or choice.get("message", {}).get("reasoning_content") or ""
    return raw, latency, payload.get("usage") or {}, choice.get("finish_reason")


def merge_usage(first, second):
    merged = {}
    for key in set(first) | set(second):
        left, right = first.get(key), second.get(key)
        if isinstance(left, (int, float)) or isinstance(right, (int, float)):
            merged[key] = (left if isinstance(left, (int, float)) else 0) + (right if isinstance(right, (int, float)) else 0)
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


def append_recording(path: Path, record: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + "\n")


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
    try:
        parsed = extract(raw)
    except ValueError:
        parsed = None
        if recording.get("classification") in {"false_positive", "true_positive", "uncertain"}:
            parsed = {
                "classification": recording["classification"],
                "confidence": 0.5,
                "verdict": "classification taken from recording metadata",
                "context_factors": ["recorded"],
                "uncertainty_factors": [],
            }
    return {
        "id": fixture["id"],
        "expected": fixture.get("expected") or fixture.get("label"),
        "valid": parsed is not None,
        "repaired": repaired,
        "classification": parsed.get("classification") if parsed else None,
        "latency_ms": recording.get("latency_ms") or 0,
        "token_usage": recording.get("token_usage") or {},
        "finish_reason": recording.get("finish_reason"),
    }


def classify_live(fixture: dict, settings: dict) -> tuple[dict, dict]:
    raw, latency, usage, finish = request([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": json.dumps(fixture["context"], ensure_ascii=False, indent=2)},
    ], settings)
    repaired = False
    try:
        parsed = extract(raw)
    except ValueError:
        repaired = True
        raw, repair_latency, repair_usage, finish = request([
            {"role": "system", "content": REPAIR_PROMPT}, {"role": "user", "content": raw},
        ], settings)
        latency += repair_latency
        usage = merge_usage(usage, repair_usage)
        try:
            parsed = extract(raw)
        except ValueError:
            parsed = None
    result = {
        "id": fixture["id"],
        "expected": fixture.get("expected") or fixture.get("label"),
        "valid": parsed is not None,
        "repaired": repaired,
        "classification": parsed.get("classification") if parsed else None,
        "latency_ms": latency,
        "token_usage": usage,
        "finish_reason": finish,
    }
    recording = {
        "id": fixture["id"],
        "raw": raw,
        "repaired": repaired,
        "latency_ms": latency,
        "token_usage": usage,
        "finish_reason": finish,
        "classification": result["classification"],
    }
    return result, recording


def build_report(fixtures, results, settings, model: str) -> dict:
    matrix = per_rule_matrix(fixtures, results)
    counts = matrix["overall"]["counts"]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "prompt_version": "offpath-v5-classify",
        "prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
        "settings": {key: value for key, value in settings.items() if key != "api_key"},
        "summary": summary_from_counts(counts),
        "confusion": matrix,
        "results": results,
    }


def load_fixture_rows(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", default=str(ROOT / "eval/fixtures.jsonl"))
    parser.add_argument("--output", default=str(ROOT / "eval/report.json"))
    parser.add_argument("--mode", choices=["live", "recorded"], default="live")
    parser.add_argument("--model", default=os.getenv("LLM_MODEL", "Foundation-Sec-1.1-8B-Instruct"))
    parser.add_argument("--recordings-dir", default=str(RECORDINGS_DIR))
    parser.add_argument("--record", action="store_true", help="write live responses into recordings/<model>.jsonl")
    args = parser.parse_args(argv)
    settings = {
        "base_url": os.getenv("LLM_API_BASE_URL", "http://127.0.0.1:8001/v1"),
        "api_key": os.getenv("LLM_API_KEY", "local"),
        "model": args.model,
        "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "1200")),
        "temperature": float(os.getenv("LLM_TEMPERATURE", "0.01")),
        "timeout": float(os.getenv("LLM_TIMEOUT_SECONDS", "180")),
    }
    fixtures = load_fixture_rows(Path(args.fixtures))
    results = []
    recordings_file = recording_path(args.model, Path(args.recordings_dir))
    if args.mode == "recorded":
        stored = load_recordings(recordings_file)
        for fixture in fixtures:
            results.append(classify_recorded(fixture, stored.get(fixture["id"])))
            print(f"{fixture['id']}: {results[-1]['classification'] or 'INVALID'}")
    else:
        if args.record:
            recordings_file.write_text("")
        for fixture in fixtures:
            result, recording = classify_live(fixture, settings)
            results.append(result)
            if args.record:
                append_recording(recordings_file, recording)
            print(f"{fixture['id']}: {result['classification'] or 'INVALID'}{' (repaired)' if result['repaired'] else ''}")
    report = build_report(fixtures, results, settings, args.model)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2) + "\n")
    reports_dir = ROOT / "eval" / "reports"
    if args.mode == "recorded":
        from report import write_reports

        write_reports({args.model: report}, reports_dir)
    failed = report["summary"]["schema_valid"] != len(results) or report["summary"]["attack_false_positives"] > 0
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Provider request failed: {exc}", file=sys.stderr)
        sys.exit(2)
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        sys.exit(2)
