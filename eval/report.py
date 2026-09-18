#!/usr/bin/env python3
"""Write per-CRS-rule-ID confusion matrices for one or more recorded models."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

from evaluate import RECORDINGS_DIR, build_report, classify_recorded, load_fixture_rows, load_recordings, recording_path  # noqa: E402


def _pct(num: int | None, den: int | None) -> str:
    if not den:
        return "n/a"
    return f"{(num or 0) / den:.1%}"


def matrix_markdown(model: str, report: dict[str, Any]) -> str:
    overall = report["confusion"]["overall"]["counts"]
    lines = [
        f"# Eval report — {model}",
        "",
        f"Generated: {report.get('generated_at', '')}",
        f"Prompt: `{report.get('prompt_version', '')}` (`{report.get('prompt_sha256', '')[:12]}`)",
        "",
        "## Overall",
        "",
        f"- Fixtures: {overall['n']}",
        f"- Schema valid: {overall['schema_valid']}/{overall['n']}",
        f"- Repair rate: {_pct(overall['repaired'], overall['n'])}",
        f"- Attack cases classified false_positive (miss): {overall['attack_false_positive']}/{overall['attack']}",
        f"- Benign accuracy (classified false_positive): {_pct(overall['benign_false_positive'], overall['benign'])}",
        "",
        "| expected \\ predicted | true_positive | false_positive | uncertain | invalid |",
        "|---|---:|---:|---:|---:|",
        (
            f"| attack | {overall['attack_true_positive']} | {overall['attack_false_positive']} "
            f"| {overall['attack_uncertain']} | {overall['attack_invalid']} |"
        ),
        (
            f"| benign | {overall['benign_true_positive']} | {overall['benign_false_positive']} "
            f"| {overall['benign_uncertain']} | {overall['benign_invalid']} |"
        ),
        "",
        "## Per CRS rule ID",
        "",
        "| rule ID | n | attack | benign | attack miss (FP) | benign accuracy | uncertain |",
        "|---|---:|---:|---:|---:|---:|---:|",
    ]
    for rule_id, payload in report["confusion"]["by_rule_id"].items():
        counts = payload["counts"]
        lines.append(
            f"| {rule_id} | {counts['n']} | {counts['attack']} | {counts['benign']} | "
            f"{counts['attack_false_positive']} | {_pct(counts['benign_false_positive'], counts['benign'])} | "
            f"{counts['attack_uncertain'] + counts['benign_uncertain']} |"
        )
    lines.append("")
    return "\n".join(lines)


def comparison_markdown(reports: dict[str, dict[str, Any]]) -> str:
    lines = [
        "# Multi-model eval comparison",
        "",
        "| model | fixtures | schema valid | attack miss | benign accuracy | repair rate |",
        "|---|---:|---:|---:|---:|---:|",
    ]
    for model, report in reports.items():
        summary = report["summary"]
        lines.append(
            f"| {model} | {summary['fixtures']} | {summary['schema_valid']} | "
            f"{summary['attack_false_positives']} | "
            f"{summary['benign_accuracy'] if summary['benign_accuracy'] is not None else 'n/a'} | "
            f"{summary['repair_rate']:.3f} |"
        )
    lines.extend(["", "Per-rule matrices are in the sibling `*.md` files.", ""])
    return "\n".join(lines)


def write_reports(reports: dict[str, dict[str, Any]], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for model, report in reports.items():
        safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in model)
        (output_dir / f"{safe}.json").write_text(json.dumps(report, indent=2) + "\n")
        (output_dir / f"{safe}.md").write_text(matrix_markdown(model, report))
    if len(reports) > 1:
        comparison = {
            "models": list(reports),
            "summaries": {model: report["summary"] for model, report in reports.items()},
        }
        (output_dir / "comparison.json").write_text(json.dumps(comparison, indent=2) + "\n")
        (output_dir / "comparison.md").write_text(comparison_markdown(reports))


def evaluate_recordings(
    fixtures: list[dict],
    models: list[str],
    recordings_dir: Path,
    *,
    ignore_missing: bool = True,
) -> dict[str, dict[str, Any]]:
    reports = {}
    for model in models:
        stored = load_recordings(recording_path(model, recordings_dir))
        subset = [fixture for fixture in fixtures if fixture["id"] in stored] if ignore_missing else fixtures
        results = [classify_recorded(fixture, stored.get(fixture["id"])) for fixture in subset]
        reports[model] = build_report(subset, results, {"model": model, "mode": "recorded"}, model)
    return reports


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", default=str(ROOT / "eval/fixtures.jsonl"))
    parser.add_argument("--recordings-dir", default=str(RECORDINGS_DIR))
    parser.add_argument("--models", default="", help="comma-separated model names; default: every *.jsonl in recordings/")
    parser.add_argument("--output-dir", default=str(ROOT / "eval/reports"))
    args = parser.parse_args()
    recordings_dir = Path(args.recordings_dir)
    if args.models.strip():
        models = [item.strip() for item in args.models.split(",") if item.strip()]
    else:
        models = sorted(path.stem for path in recordings_dir.glob("*.jsonl"))
    if not models:
        print("No recordings found", file=sys.stderr)
        return 2
    fixtures = load_fixture_rows(Path(args.fixtures))
    reports = evaluate_recordings(fixtures, models, recordings_dir)
    write_reports(reports, Path(args.output_dir))
    print(f"Wrote reports for {', '.join(models)} to {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
