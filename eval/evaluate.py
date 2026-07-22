#!/usr/bin/env python3
"""Dependency-free live classifier gate for sanitized JSONL fixtures."""
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


def constant(name):
    tree = ast.parse((ROOT / "backend/services/agent.py").read_text())
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == name for target in node.targets):
            return ast.literal_eval(node.value)
    raise RuntimeError(f"Could not load {name} from backend/services/agent.py")


SYSTEM_PROMPT = constant("SYSTEM_PROMPT")
REPAIR_PROMPT = constant("JSON_REPAIR_PROMPT")
EXPECTED_KEYS = {"classification", "confidence", "verdict", "context_factors", "uncertainty_factors"}


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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", default=str(ROOT / "eval/fixtures.jsonl"))
    parser.add_argument("--output", default=str(ROOT / "eval/report.json"))
    args = parser.parse_args()
    settings = {
        "base_url": os.getenv("LLM_API_BASE_URL", "http://127.0.0.1:8001/v1"),
        "api_key": os.getenv("LLM_API_KEY", "local"),
        "model": os.getenv("LLM_MODEL", "Foundation-Sec-1.1-8B-Instruct"),
        "max_tokens": int(os.getenv("LLM_MAX_TOKENS", "1200")),
        "temperature": float(os.getenv("LLM_TEMPERATURE", "0.01")),
        "timeout": float(os.getenv("LLM_TIMEOUT_SECONDS", "180")),
    }
    fixtures = [json.loads(line) for line in Path(args.fixtures).read_text().splitlines() if line.strip()]
    results = []
    for fixture in fixtures:
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
        results.append({
            "id": fixture["id"], "expected": fixture["expected"], "valid": parsed is not None,
            "repaired": repaired, "classification": parsed.get("classification") if parsed else None,
            "latency_ms": latency, "token_usage": usage, "finish_reason": finish,
        })
        print(f"{fixture['id']}: {results[-1]['classification'] or 'INVALID'}{' (repaired)' if repaired else ''}")
    attacks = [row for row in results if row["expected"] == "attack"]
    benign = [row for row in results if row["expected"] == "false_positive"]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "model": settings["model"],
        "prompt_version": "offpath-v5-classify",
        "prompt_sha256": hashlib.sha256(SYSTEM_PROMPT.encode()).hexdigest(),
        "settings": {key: value for key, value in settings.items() if key != "api_key"},
        "summary": {
            "fixtures": len(results), "schema_valid": sum(row["valid"] for row in results),
            "repair_rate": sum(row["repaired"] for row in results) / len(results),
            "attack_false_positives": sum(row["classification"] == "false_positive" for row in attacks),
            "attack_uncertain": sum(row["classification"] == "uncertain" for row in attacks),
            "benign_accuracy": sum(row["classification"] == "false_positive" for row in benign) / len(benign),
        },
        "results": results,
    }
    Path(args.output).write_text(json.dumps(report, indent=2) + "\n")
    failed = report["summary"]["schema_valid"] != len(results) or report["summary"]["attack_false_positives"] > 0
    return 1 if failed else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (urllib.error.URLError, TimeoutError) as exc:
        print(f"Provider request failed: {exc}", file=sys.stderr)
        sys.exit(2)
