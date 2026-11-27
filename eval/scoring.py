"""Confusion-matrix scoring for recorded or live eval results."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Iterable


CLASSIFICATIONS = ("true_positive", "false_positive", "uncertain", "invalid")


def expected_class(record: dict[str, Any]) -> str:
    label = record.get("expected") or record.get("label")
    if label in {"attack", "true_positive"}:
        return "attack"
    return "false_positive"


def rule_ids(record: dict[str, Any]) -> list[str]:
    ids = [str(item) for item in record.get("crs_rule_ids") or [] if item]
    incident = (record.get("context") or {}).get("incident") or {}
    primary = str(incident.get("rule_id") or "")
    if primary and primary not in ids:
        ids.insert(0, primary)
    return ids


def confusion_counts(rows: Iterable[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "n": 0,
        "schema_valid": 0,
        "repaired": 0,
        "attack": 0,
        "benign": 0,
        "attack_true_positive": 0,
        "attack_false_positive": 0,
        "attack_uncertain": 0,
        "attack_invalid": 0,
        "benign_true_positive": 0,
        "benign_false_positive": 0,
        "benign_uncertain": 0,
        "benign_invalid": 0,
    }
    for row in rows:
        counts["n"] += 1
        expected = row["expected"]
        predicted = row.get("classification") if row.get("valid") else "invalid"
        if row.get("valid"):
            counts["schema_valid"] += 1
        if row.get("repaired"):
            counts["repaired"] += 1
        bucket = "attack" if expected == "attack" else "benign"
        counts[bucket] += 1
        key = f"{bucket}_{predicted}"
        if key in counts:
            counts[key] += 1
        elif predicted is None:
            counts[f"{bucket}_invalid"] += 1
    return counts


def per_rule_matrix(fixtures: list[dict[str, Any]], results: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {item["id"]: item for item in fixtures}
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    combined_rows = []
    for result in results:
        fixture = by_id.get(result["id"], {})
        expected = expected_class(fixture) if fixture else result.get("expected")
        row = {**result, "expected": expected, "crs_rule_ids": rule_ids(fixture) or rule_ids(result)}
        combined_rows.append(row)
        for rule_id in row["crs_rule_ids"] or ["unknown"]:
            grouped[rule_id].append(row)

    def pack(rows: list[dict[str, Any]]) -> dict[str, Any]:
        counts = confusion_counts(rows)
        benign = max(counts["benign"], 1)
        return {
            "counts": counts,
            "benign_accuracy": counts["benign_false_positive"] / benign if counts["benign"] else None,
            "attack_miss_rate": counts["attack_false_positive"] / counts["attack"] if counts["attack"] else None,
        }

    return {
        "overall": pack(combined_rows),
        "by_rule_id": {rule_id: pack(rows) for rule_id, rows in sorted(grouped.items())},
    }


def summary_from_counts(counts: dict[str, int]) -> dict[str, Any]:
    n = max(counts["n"], 1)
    return {
        "fixtures": counts["n"],
        "schema_valid": counts["schema_valid"],
        "repair_rate": counts["repaired"] / n,
        "attack_false_positives": counts["attack_false_positive"],
        "attack_uncertain": counts["attack_uncertain"],
        "benign_accuracy": counts["benign_false_positive"] / counts["benign"] if counts["benign"] else None,
    }


def _predicted(row: dict[str, Any]) -> str:
    return row.get("classification") if row.get("valid") and row.get("classification") else "invalid"


def _rate(num: int, den: int) -> float | None:
    return num / den if den else None


def exclusion_metrics(attacks: list[dict[str, Any]], harmless: list[dict[str, Any]]) -> dict[str, Any]:
    """A false positive identified (the model cleared a harmless match) is not yet an exclusion: the
    server's draft gates must also pass (row `draft_status` == "valid", from evaluate.draft_status).
    Exclusion counts are None when no row carries gate inputs (for example the oracle recording)."""
    identified = [row for row in harmless if _predicted(row) == "false_positive"]
    cleared = [row for row in attacks + harmless if _predicted(row) == "false_positive"]
    measured = [row for row in cleared if row.get("draft_status") is not None]
    known = bool(measured) or not cleared
    withheld = Counter(
        row["draft_status"] for row in identified if row.get("draft_status") not in (None, "valid")
    )
    produced = sum(row.get("draft_status") == "valid" for row in harmless)
    return {
        "false_positives_identified": len(identified),
        "exclusions_produced": produced if known else None,
        "attack_exclusions_produced": sum(row.get("draft_status") == "valid" for row in attacks) if known else None,
        "exclusions_measured": len(measured),
        "exclusion_rate": _rate(produced, len(harmless)) if known else None,
        "draft_withheld": dict(sorted(withheld.items())),
    }


def run_metrics(rows: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Per-run headline metrics over scored match rows."""
    rows = list(rows)
    attacks = [row for row in rows if expected_class(row) == "attack"]
    harmless = [row for row in rows if expected_class(row) != "attack"]
    stack: dict[str, Counter] = {"attack": Counter(), "false_positive": Counter()}
    for row in rows:
        value = row.get("applies_to_stack") if _predicted(row) != "invalid" else "invalid"
        stack[expected_class(row)][value or "unknown"] += 1
    wrong_stack_rows = [row for row in attacks if row.get("wrong_stack") is True]
    has_wrong_stack = any(isinstance(row.get("wrong_stack"), bool) for row in rows)
    wrong_stack = None
    if has_wrong_stack:
        predicted = Counter(_predicted(row) for row in wrong_stack_rows)
        wrong_stack = {
            "attacks": len(wrong_stack_rows),
            **{key: predicted.get(key, 0) for key in ("true_positive", "false_positive", "uncertain", "invalid")},
            "detection": _rate(predicted.get("true_positive", 0), len(wrong_stack_rows)),
            "applies_to_stack": dict(Counter(
                (row.get("applies_to_stack") or "unknown") if _predicted(row) != "invalid" else "invalid"
                for row in wrong_stack_rows
            )),
        }
    return {
        "requests": len({row.get("request_id", row["id"]) for row in rows}),
        "scored_matches": len(rows),
        "attacks": len(attacks),
        "harmless": len(harmless),
        "invalid": sum(_predicted(row) == "invalid" for row in rows),
        "attacks_classified_false_positive": sum(_predicted(row) == "false_positive" for row in attacks),
        "attack_detection": _rate(sum(_predicted(row) == "true_positive" for row in attacks), len(attacks)),
        "harmless_cleared_rate": _rate(sum(_predicted(row) == "false_positive" for row in harmless), len(harmless)),
        "uncertain_rate": _rate(sum(_predicted(row) == "uncertain" for row in rows), len(rows)),
        **exclusion_metrics(attacks, harmless),
        "explanation_rate": _rate(sum(row.get("explanation_complete") is True for row in rows), len(rows)),
        "applies_to_stack": {label: dict(counts) for label, counts in stack.items()},
        "wrong_stack_attacks": wrong_stack,
    }


def _count(value: Any) -> int:
    return value if isinstance(value, int) and not isinstance(value, bool) else 0


def usage_tokens(usage: dict[str, Any]) -> dict[str, int]:
    """Normalize one call's OpenAI-compatible usage.

    Cached prompt tokens come only from `prompt_tokens_details.cached_tokens`; provider-specific
    top-level fields are ignored.
    """
    usage = usage or {}
    prompt_details = usage.get("prompt_tokens_details") or {}
    completion_details = usage.get("completion_tokens_details") or {}
    cached = prompt_details.get("cached_tokens") if isinstance(prompt_details, dict) else None
    reasoning = completion_details.get("reasoning_tokens") if isinstance(completion_details, dict) else None
    return {
        "prompt_tokens": _count(usage.get("prompt_tokens")),
        "cached_prompt_tokens": _count(cached),
        "completion_tokens": _count(usage.get("completion_tokens")),
        "reasoning_tokens": _count(reasoning),
    }


TOKEN_FIELDS = ("prompt_tokens", "cached_prompt_tokens", "completion_tokens", "reasoning_tokens")


def token_totals(calls: Iterable[dict[str, Any]], requests: int, scored_matches: int) -> dict[str, Any]:
    """Token totals over model calls, one entry per scored match."""
    totals = {field: 0 for field in TOKEN_FIELDS}
    model_calls = 0
    for call in calls:
        model_calls += _count(call.get("model_calls"))
        for field, value in usage_tokens(call.get("token_usage") or {}).items():
            totals[field] += value
    return {
        "model_calls": model_calls,
        **totals,
        "calls_per_request": model_calls / requests if requests else None,
        "per_request": {field: totals[field] / requests if requests else None for field in TOKEN_FIELDS},
        "per_scored_match": {
            field: totals[field] / scored_matches if scored_matches else None for field in TOKEN_FIELDS
        },
    }
