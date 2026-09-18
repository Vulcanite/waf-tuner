"""Confusion-matrix scoring for recorded or live eval results."""
from __future__ import annotations

from collections import defaultdict
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
