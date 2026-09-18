#!/usr/bin/env python3
"""Write recorded-mode JSONL files for CI (oracle) and the historical MiniMax run."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

from evaluate import oracle_response, recording_path, write_recordings  # noqa: E402
from fixtures import load_fixtures  # noqa: E402


def oracle_record(fixture: dict) -> dict:
    parsed = oracle_response(fixture.get("expected") or fixture.get("label"))
    return {
        "id": fixture["id"],
        "raw": json.dumps(parsed, ensure_ascii=False),
        "repaired": False,
        "latency_ms": 0,
        "token_usage": {},
        "finish_reason": "stop",
        "classification": parsed["classification"],
        "source": "oracle",
    }


def minimax_records() -> list[dict]:
    report_path = ROOT / "eval" / "reports" / "v0.1.0-minimax-m3.json"
    if not report_path.exists():
        return []
    report = json.loads(report_path.read_text())
    records = []
    for row in report.get("results") or []:
        classification = row.get("classification")
        if classification not in {"false_positive", "true_positive", "uncertain"}:
            continue
        parsed = {
            "classification": classification,
            "confidence": 0.9,
            "verdict": "Historical MiniMax-M3 classification from the v0.1.0 eval report.",
            "context_factors": ["recorded-minimax-m3"],
            "uncertainty_factors": [],
        }
        records.append({
            "id": row["id"],
            "raw": json.dumps(parsed, ensure_ascii=False),
            "repaired": bool(row.get("repaired")),
            "latency_ms": row.get("latency_ms") or 0,
            "token_usage": row.get("token_usage") or {},
            "finish_reason": row.get("finish_reason") or "stop",
            "classification": classification,
            "source": "v0.1.0-minimax-m3",
        })
    return records


def main() -> int:
    fixtures = load_fixtures()
    write_recordings(recording_path("oracle"), [oracle_record(item) for item in fixtures])
    minimax = minimax_records()
    if minimax:
        write_recordings(recording_path("MiniMax-M3"), minimax)
    print(f"oracle recordings: {len(fixtures)}")
    print(f"MiniMax-M3 recordings: {len(minimax)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
