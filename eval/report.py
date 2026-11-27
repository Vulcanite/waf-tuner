#!/usr/bin/env python3
"""Write per-CRS-rule-ID confusion matrices for one or more recorded runs, plus a side-by-side
comparison when there are several.

A run is a recording stem in eval/recordings, for example `--models oracle,deepseek-flash`.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "eval"))

from evaluate import (  # noqa: E402
    DEFAULT_FIXTURES, RECORDINGS_DIR, build_report, evaluate_fixture, fixture_labels, load_fixture_rows,
    load_recordings, recording_path,
)


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
        f"Prompt: `{report.get('prompt_version') or 'unrecorded'}` (`{(report.get('prompt_sha256') or '')[:12]}`)",
        "",
        "## Overall",
        "",
        f"- Fixtures: {overall['n']}",
        f"- Schema valid: {overall['schema_valid']}/{overall['n']}",
        f"- Repair rate: {_pct(overall['repaired'], overall['n'])}",
        f"- Attack cases classified false_positive (miss): {overall['attack_false_positive']}/{overall['attack']}",
        f"- Benign accuracy (classified false_positive): {_pct(overall['benign_false_positive'], overall['benign'])}",
        f"- Median / p95 provider latency in ms: "
        f"{report['summary'].get('latency_ms', {}).get('p50')} / "
        f"{report['summary'].get('latency_ms', {}).get('p95')}",
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
        *run_metrics_markdown(report),
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


def _num(value, digits: int = 1) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, int):
        return f"{value:,}"
    return f"{value:,.{digits}f}"


def _rate(value) -> str:
    return "n/a" if value is None else f"{value:.1%}"


def _stack(counts: dict | None) -> str:
    counts = counts or {}
    return ", ".join(f"{key} {counts[key]}" for key in sorted(counts)) or "none"


def run_metrics_markdown(report: dict[str, Any]) -> list[str]:
    summary = report["summary"]
    tokens = summary.get("tokens") or {}
    lines = [
        "## Run metrics",
        "",
        f"- Requests / scored matches: {summary.get('requests')} / {summary.get('scored_matches')}",
        f"- Invalid: {summary.get('invalid')}",
        f"- Attacks classified false_positive (must be 0): {summary.get('attacks_classified_false_positive')}",
        f"- Attack detection: {_rate(summary.get('attack_detection'))}",
        f"- Harmless correctly cleared: {_rate(summary.get('harmless_cleared_rate'))}",
        f"- Uncertain rate: {_rate(summary.get('uncertain_rate'))}",
        f"- Copyable exclusions (estimate): {summary.get('copyable_exclusions')}",
        f"- applies_to_stack on attacks: {_stack((summary.get('applies_to_stack') or {}).get('attack'))}",
        f"- applies_to_stack on harmless: {_stack((summary.get('applies_to_stack') or {}).get('false_positive'))}",
    ]
    wrong = summary.get("wrong_stack_attacks")
    if wrong:
        lines.append(
            f"- Wrong-stack attacks: {wrong['attacks']} (true_positive {wrong['true_positive']}, false_positive "
            f"{wrong['false_positive']}, uncertain {wrong['uncertain']}, invalid {wrong['invalid']}; "
            f"applies_to_stack {_stack(wrong['applies_to_stack'])})"
        )
    if tokens:
        lines.append(
            f"- Model calls: {tokens['model_calls']} ({_num(tokens['calls_per_request'], 2)} per request); tokens "
            f"prompt {_num(tokens['prompt_tokens'])}, cached {_num(tokens['cached_prompt_tokens'])}, completion "
            f"{_num(tokens['completion_tokens'])}, reasoning {_num(tokens['reasoning_tokens'])}"
        )
    lines.append("")
    return lines


# (label, getter) rows of the comparison table; runs are the columns.
_COMPARISON_ROWS = [
    ("prompt", lambda r, s, t: f"`{r.get('prompt_version') or 'unrecorded'}`"),
    ("requests", lambda r, s, t: _num(s.get("requests"))),
    ("scored matches", lambda r, s, t: _num(s.get("scored_matches"))),
    ("invalid", lambda r, s, t: _num(s.get("invalid"))),
    ("attacks classified false_positive (must be 0)", lambda r, s, t: _num(s.get("attacks_classified_false_positive"))),
    ("attack detection", lambda r, s, t: _rate(s.get("attack_detection"))),
    ("harmless correctly cleared", lambda r, s, t: _rate(s.get("harmless_cleared_rate"))),
    ("uncertain rate", lambda r, s, t: _rate(s.get("uncertain_rate"))),
    ("copyable exclusions (estimate)", lambda r, s, t: _num(s.get("copyable_exclusions"))),
    ("repair rate", lambda r, s, t: _rate(s.get("repair_rate"))),
    ("applies_to_stack, attacks", lambda r, s, t: _stack((s.get("applies_to_stack") or {}).get("attack"))),
    ("applies_to_stack, harmless", lambda r, s, t: _stack((s.get("applies_to_stack") or {}).get("false_positive"))),
    ("wrong-stack attacks detected", lambda r, s, t: (
        f"{s['wrong_stack_attacks']['true_positive']}/{s['wrong_stack_attacks']['attacks']}"
        if s.get("wrong_stack_attacks") else "n/a"
    )),
    ("model calls", lambda r, s, t: _num(t.get("model_calls"))),
    ("calls per request", lambda r, s, t: _num(t.get("calls_per_request"), 2)),
    ("prompt tokens", lambda r, s, t: _num(t.get("prompt_tokens"))),
    ("cached prompt tokens", lambda r, s, t: _num(t.get("cached_prompt_tokens"))),
    ("completion tokens", lambda r, s, t: _num(t.get("completion_tokens"))),
    ("reasoning tokens", lambda r, s, t: _num(t.get("reasoning_tokens"))),
    *[
        (f"{label} / {scope_label}", (lambda key, scope: lambda r, s, t: _num((t.get(scope) or {}).get(key)))(key, scope))
        for scope, scope_label in (("per_request", "request"), ("per_scored_match", "scored match"))
        for key, label in (("prompt_tokens", "prompt tokens"), ("cached_prompt_tokens", "cached prompt tokens"),
                           ("completion_tokens", "completion tokens"), ("reasoning_tokens", "reasoning tokens"))
    ],
    ("p50 / p95 latency ms", lambda r, s, t: (
        f"{(s.get('latency_ms') or {}).get('p50')} / {(s.get('latency_ms') or {}).get('p95')}"
    )),
]


def comparison_markdown(reports: dict[str, dict[str, Any]]) -> str:
    runs = list(reports)
    lines = [
        "# Eval comparison",
        "",
        "| metric | " + " | ".join(runs) + " |",
        "|---|" + "---:|" * len(runs),
    ]
    for label, getter in _COMPARISON_ROWS:
        cells = []
        for run in runs:
            report = reports[run]
            summary = report["summary"]
            cells.append(str(getter(report, summary, summary.get("tokens") or {})))
        lines.append(f"| {label} | " + " | ".join(cells) + " |")
    lines.extend([
        "",
        "Token averages divide by requests and by scored matches.",
        "Per-rule matrices are in the sibling `*.md` files.",
        "",
    ])
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


def evaluate_run(
    fixtures: list[dict], run: str, recordings_dir: Path, *, ignore_missing: bool = True,
) -> dict[str, Any]:
    """Replay one recorded run."""
    stored = load_recordings(recording_path(run, recordings_dir))
    subset = [
        fixture for fixture in fixtures if any(label["row_id"] in stored for label in fixture_labels(fixture))
    ] if ignore_missing else fixtures
    rows, calls = [], []
    for fixture in subset:
        fixture_rows, fixture_calls, _ = evaluate_fixture(fixture, stored=stored)
        rows.extend(fixture_rows)
        calls.extend(fixture_calls)
    report = build_report(subset, rows, {"model": run, "mode": "recorded"}, run, calls)
    report["run"] = run
    return report


def evaluate_recordings(
    fixtures: list[dict],
    models: list[str],
    recordings_dir: Path,
    *,
    ignore_missing: bool = True,
) -> dict[str, dict[str, Any]]:
    return {run: evaluate_run(fixtures, run, recordings_dir, ignore_missing=ignore_missing) for run in models}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--fixtures", default=str(DEFAULT_FIXTURES))
    parser.add_argument("--recordings-dir", default=str(RECORDINGS_DIR))
    parser.add_argument("--models", default="", help="comma-separated run names; default: every *.jsonl in recordings/")
    parser.add_argument("--output-dir", default=str(ROOT / "eval/reports"))
    args = parser.parse_args()
    recordings_dir = Path(args.recordings_dir)
    selected = args.models.strip()
    if selected:
        models = [item.strip() for item in selected.split(",") if item.strip()]
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
