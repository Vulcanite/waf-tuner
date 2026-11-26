import json
import sys
import io
from pathlib import Path

EVAL = Path(__file__).resolve().parents[1]
ROOT = EVAL.parent
sys.path.insert(0, str(EVAL))

from capture_lab import parse_audit_log  # noqa: E402
from corpus import all_cases, route_profile  # noqa: E402
from evaluate import classify_recorded, load_recordings, oracle_response, recording_path  # noqa: E402
from fixtures import case_to_fixture, load_fixtures, merge_fixtures  # noqa: E402
from report import evaluate_recordings, matrix_markdown, write_reports  # noqa: E402
import evaluate  # noqa: E402
from services import crs_index  # noqa: E402


def test_corpus_has_unique_ids_and_rule_citations():
    cases = all_cases()
    ids = [case.id for case in cases]
    assert len(ids) == len(set(ids))
    assert len(cases) >= 180
    assert all(case.crs_rule_ids and case.label in {"attack", "false_positive"} for case in cases)
    assert any(case.label == "attack" and case.category == "sqli" for case in cases)


def test_route_profile_does_not_reveal_the_label():
    # The profile comes from the route alone, so both labels appear with and without one.
    pairs = {(case.label, bool(route_profile(case.path))) for case in all_cases()}
    assert pairs == {("attack", True), ("attack", False), ("false_positive", True), ("false_positive", False)}
    fixtures = load_fixtures()
    assert all(
        record["context"]["application_context"] == route_profile(record["context"]["incident"]["path"])
        for record in fixtures
    )


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


def test_live_eval_sends_the_backend_contract_and_records_provenance(tmp_path, monkeypatch):
    for name in ("_index_dir", "_marker_key", "_status", "CRS_INDEX"):
        monkeypatch.setattr(crs_index, name, getattr(crs_index, name))
    (tmp_path / "LOCAL.conf").write_text('SecRule ARGS:q "@streq music" "id:10001,phase:2,log"\n')
    crs_index.initialize_crs_index(tmp_path)
    monkeypatch.setenv("LLM_API_BASE_URL", "http://localhost:12345/v1")
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setenv("LLM_STRUCTURED_OUTPUT", "true")
    monkeypatch.setenv("LLM_ESCALATION_REASONING_EFFORT", "")
    fixture = {
        "id": "benign-catalog",
        "expected": "false_positive",
        "modsec_audit": {"transaction": {
            "id": "local-fixture",
            "time_stamp": "Mon Jan 01 12:00:00 2024",
            "request": {"method": "GET", "uri": "/catalog?q=books&q=music&token=secret-fixture"},
            "messages": [{"details": {
                "ruleId": "10001",
                "data": "Matched Data: music found within ARGS:q: music",
            }}],
        }},
    }
    sent = []

    def fake_urlopen(request, **kwargs):
        assert request.full_url == "http://localhost:12345/v1/chat/completions"
        sent.append(json.loads(request.data))
        return io.BytesIO(json.dumps({
            "choices": [{
                "finish_reason": "stop",
                "message": {"content": json.dumps(oracle_response("false_positive"))},
            }],
        }).encode())

    monkeypatch.setattr(evaluate.urllib.request, "urlopen", fake_urlopen)
    result, recording = evaluate.classify_live(fixture, evaluate.request_settings(model="mock"))
    assert result["classification"] == "false_positive"
    assert len(sent) == 1 and sent[0]["response_format"]["type"] == "json_schema"
    user_message = sent[0]["messages"][1]["content"]
    context = json.loads(user_message)
    assert context["crs_rule"]["operator"] == "@streq music"
    assert "books" in user_message and "music" in user_message
    assert "secret-fixture" not in user_message and "local-fixture" not in user_message
    assert "api_key" not in recording["settings"]
    assert recording["prompt_sha256"] == evaluate.PROMPT_SHA256
    assert evaluate.classify_recorded({**fixture, "expected": "attack"}, recording)["finish_reason"] == "fixture_mismatch"


def test_recorded_metadata_cannot_rescue_invalid_output():
    fixture = {"id": "benign-catalog", "expected": "false_positive"}
    result = evaluate.classify_recorded(fixture, {"classification": "false_positive", "raw": "not JSON"})
    assert not result["valid"]


def test_live_eval_pauses_rejected_escalation_for_remaining_fixtures(monkeypatch):
    monkeypatch.setenv("LLM_THINKING", "enabled")
    monkeypatch.setenv("LLM_ESCALATION_REASONING_EFFORT", "hgih")
    settings = evaluate.request_settings(model="mock")
    sent = []

    def fake_request(messages, settings, attempt_type="initial"):
        sent.append(attempt_type)
        if attempt_type == "escalation":
            raise evaluate.urllib.error.HTTPError(
                "http://provider.test/v1/chat/completions", 422, "Unprocessable Entity", {},
                io.BytesIO(b'{"error":{"param":"reasoning_effort"}}'),
            )
        result = {**oracle_response("false_positive"), "classification": "uncertain"}
        return {"finish_reason": "stop", "message": {"content": json.dumps(result)}}, 1, {}

    monkeypatch.setattr(evaluate, "request", fake_request)
    for fixture_id in ("first", "second"):
        fixture = {"id": fixture_id, "expected": "false_positive", "context": {"incident": {"rule_id": "10001"}}}
        result, _ = evaluate.classify_live(fixture, settings)
        assert result["classification"] == "uncertain"
    assert sent == ["initial", "escalation", "initial"]
    assert evaluate.public_settings(settings)["escalation_error"] == evaluate.ESCALATION_EFFORT_REJECTED


def test_live_eval_does_not_escalate_a_repaired_verdict(monkeypatch):
    # The backend returns a repaired verdict without escalating; the eval must report the same verdict.
    monkeypatch.setenv("LLM_THINKING", "enabled")
    monkeypatch.setenv("LLM_ESCALATION_REASONING_EFFORT", "high")
    settings = evaluate.request_settings(model="mock")
    uncertain = json.dumps({**oracle_response("false_positive"), "classification": "uncertain"})
    replies = {"initial": '{"classification": "uncertain", "confidence": 0.5}', "repair": uncertain,
               "escalation": json.dumps(oracle_response("attack"))}
    sent = []

    def fake_request(messages, settings, attempt_type="initial"):
        sent.append(attempt_type)
        return {"finish_reason": "stop", "message": {"content": replies[attempt_type]}}, 1, {}

    monkeypatch.setattr(evaluate, "request", fake_request)
    fixture = {"id": "repaired", "expected": "attack", "context": {"incident": {"rule_id": "10001"}}}
    result, _ = evaluate.classify_live(fixture, settings)
    assert (result["classification"], sent) == ("uncertain", ["initial", "repair"])
