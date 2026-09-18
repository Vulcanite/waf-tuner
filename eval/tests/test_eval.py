import json
import sys
from pathlib import Path

EVAL = Path(__file__).resolve().parents[1]
ROOT = EVAL.parent
sys.path.insert(0, str(EVAL))

from capture_lab import parse_audit_log  # noqa: E402
from corpus import all_cases  # noqa: E402
from evaluate import classify_recorded, load_recordings, oracle_response, recording_path  # noqa: E402
from fixtures import case_to_fixture, load_fixtures, merge_fixtures  # noqa: E402
from report import evaluate_recordings, matrix_markdown, write_reports  # noqa: E402


def test_corpus_has_unique_ids_and_rule_citations():
    cases = all_cases()
    ids = [case.id for case in cases]
    assert len(ids) == len(set(ids))
    assert len(cases) >= 180
    assert all(case.crs_rule_ids and case.label in {"attack", "false_positive"} for case in cases)
    assert any(case.label == "attack" and case.category == "sqli" for case in cases)
    assert any(case.label == "false_positive" and "DVWA" in json.dumps(case.application_context) for case in cases)


def test_committed_fixtures_match_schema_and_volume():
    fixtures = load_fixtures()
    assert len(fixtures) >= 200
    for record in fixtures:
        assert record["id"]
        assert record["expected"] in {"attack", "false_positive"}
        assert record["label"] in {"attack", "false_positive"}
        assert record["crs_rule_ids"]
        assert "incident" in record["context"]
        assert record["context"]["incident"]["rule_id"]


def test_merge_preserves_legacy_ids():
    legacy = load_fixtures()[:19]
    generated = [case_to_fixture(case) for case in all_cases()[:5]]
    merged = merge_fixtures(legacy, generated)
    assert {item["id"] for item in legacy} <= {item["id"] for item in merged}


def test_oracle_recorded_eval_has_no_attack_misses():
    fixtures = load_fixtures()
    stored = load_recordings(recording_path("oracle"))
    assert len(stored) == len(fixtures)
    results = [classify_recorded(fixture, stored[fixture["id"]]) for fixture in fixtures]
    assert all(row["valid"] for row in results)
    assert sum(row["classification"] == "false_positive" for row in results if row["expected"] == "attack") == 0
    benign = [row for row in results if row["expected"] == "false_positive"]
    assert benign and all(row["classification"] == "false_positive" for row in benign)


def test_per_rule_report_covers_crs_ids(tmp_path: Path):
    fixtures = load_fixtures()
    reports = evaluate_recordings(fixtures, ["oracle"], EVAL / "recordings")
    write_reports(reports, tmp_path)
    payload = json.loads((tmp_path / "oracle.json").read_text())
    by_rule = payload["confusion"]["by_rule_id"]
    assert "942100" in by_rule
    assert "941100" in by_rule
    markdown = matrix_markdown("oracle", payload)
    assert "Per CRS rule ID" in markdown
    assert (tmp_path / "oracle.md").exists()


def test_historical_minimax_recording_covers_original_fixtures():
    stored = load_recordings(recording_path("MiniMax-M3"))
    assert len(stored) == 19
    assert "attack-sqli-union" in stored
    assert stored["benign-url-field"]["classification"] == "uncertain"


def test_oracle_response_matches_expected_label():
    assert oracle_response("attack")["classification"] == "true_positive"
    assert oracle_response("false_positive")["classification"] == "false_positive"


def test_audit_log_parser_handles_missing_file(tmp_path: Path):
    assert parse_audit_log(tmp_path / "missing.log") == []
