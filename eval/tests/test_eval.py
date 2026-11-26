import json
import sys
import io
from pathlib import Path

EVAL = Path(__file__).resolve().parents[1]
ROOT = EVAL.parent
sys.path.insert(0, str(EVAL))

from capture_lab import label_request_matches, parse_audit_log  # noqa: E402
from corpus import RequestCase, all_cases, request_cases, route_profile  # noqa: E402
from evaluate import classify_recorded, load_recordings, oracle_response, recording_path  # noqa: E402
from fixtures import case_to_fixture, load_fixtures, merge_fixtures  # noqa: E402
from report import evaluate_recordings, matrix_markdown, write_reports  # noqa: E402
import evaluate  # noqa: E402
from services import crs_index  # noqa: E402
from services.audit_event import normalize_audit_event  # noqa: E402
from services.inference_context import is_aggregate_match  # noqa: E402
from services.lab_profiles import SHOP_LAB_HOST, seeded_profiles  # noqa: E402
from services.profile_match import application_context_for  # noqa: E402
from services.redaction import is_credential_name  # noqa: E402

REQUESTS = EVAL / "requests.jsonl"
REQUEST_KEYS = {"id", "app", "source", "expected_request", "modsec_audit", "labels", "application_context",
                "payload_target", "notes"}


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


def test_eval_uses_the_alert_pinned_ruleset_like_the_worker(monkeypatch):
    from types import SimpleNamespace

    rules = {"a" * 64: "@streq first", None: "@streq second"}
    lookups = []

    def get_rule_at(rule_id, digest):
        lookups.append(digest)
        return SimpleNamespace(raw="SecRule ARGS:q", operator=rules[digest], message="", severity="", source_file="",
                               ruleset_digest=digest, targets=[], tags=[], paranoia_level=0, phase=2, chain=False,
                               chain_rules=[])

    monkeypatch.setattr(evaluate, "get_rule_at", get_rule_at)
    event = {"method": "GET", "uri": "/catalog?q=x", "crs_ruleset_digest": "a" * 64,
             "raw_request": {"headers": {"Host": "catalog.test"}},
             "matches": [{"rule_id": "10001", "collection": "ARGS", "parameter": "q"}]}
    context = evaluate.fixture_context({"id": "pinned", "audit_event": event})
    assert lookups == ["a" * 64] and context["crs_rule"]["operator"] == "@streq first"


def test_gate_fails_a_model_that_never_commits_to_a_verdict(tmp_path):
    fixtures = [record for record in load_fixtures() if record["expected"] == "attack"][:3]
    fixtures_path = tmp_path / "fixtures.jsonl"
    fixtures_path.write_text("".join(json.dumps(record) + "\n" for record in fixtures))
    uncertain = {**oracle_response("attack"), "classification": "uncertain"}
    evaluate.write_recordings(recording_path("hedger", tmp_path), [
        {"id": record["id"], "raw": json.dumps(uncertain), "repaired": False, "finish_reason": "stop",
         "classification": "uncertain", "latency_ms": 0, "token_usage": {}}
        for record in fixtures
    ])
    argv = ["--mode", "recorded", "--model", "hedger", "--fixtures", str(fixtures_path),
            "--recordings-dir", str(tmp_path), "--output", str(tmp_path / "report.json")]
    assert evaluate.main(argv) == 1
    assert evaluate.main([*argv, "--min-attack-detection", "0"]) == 0


def load_requests():
    return [json.loads(line) for line in REQUESTS.read_text().splitlines() if line.strip()]


def test_request_corpus_covers_both_apps_stacks_and_inputs():
    cases = request_cases()
    assert len({case.id for case in cases}) == len(cases)
    assert {(case.app, case.label) for case in cases} == {
        ("dvwa", "attack"), ("dvwa", "false_positive"), ("flask", "attack"), ("flask", "false_positive")}
    assert {case.app for case in cases if case.wrong_stack} == {"dvwa", "flask"}
    assert all(case.label == "attack" for case in cases if case.wrong_stack)
    assert {"header", "cookie", "json", "path"} <= {case.target for case in cases}
    # A credential-named cookie or header is hidden from the model, so the corpus avoids them.
    assert not [case.id for case in cases if case.target in {"header", "cookie"} and is_credential_name(case.parameter)]


def test_request_labels_follow_the_payload_target():
    case = RequestCase(id="t", app="flask", label="attack", category="sqli", method="GET", path="/search",
                       target="cookie", parameter="cart_id", payload="1' OR '1'='1")
    normalized = {"matches": [
        {"rule_id": "942100", "collection": "REQUEST_COOKIES", "parameter": "cart_id", "matched_data": ""},
        {"rule_id": "932240", "collection": "MATCHED_VARS", "parameter": "REQUEST_COOKIES:cart_id", "matched_data": ""},
        {"rule_id": "930110", "collection": "REQUEST_HEADERS", "parameter": "Cookie", "matched_data": ""},
        {"rule_id": "949110", "collection": None, "parameter": None, "matched_data": ""},
    ]}
    assert label_request_matches(case, normalized) == [
        {"match_index": 0, "expected": "attack"}, {"match_index": 1, "expected": "attack"}]


def test_request_set_schema_and_labels():
    records = load_requests()
    assert 150 <= len(records) <= 300
    ids = [record["id"] for record in records]
    assert len(ids) == len(set(ids))
    cases = {case.id: case for case in request_cases()}
    for record in records:
        assert REQUEST_KEYS <= set(record)
        assert record["source"] == "lab-capture"
        assert record["app"] in {"dvwa", "flask"}
        assert record["expected_request"] in {"attack", "false_positive"}
        case = cases[record["id"]]
        assert (case.app, case.label) == (record["app"], record["expected_request"])
        assert record["payload_target"] == case.payload_target
        matches = normalize_audit_event(record["modsec_audit"])["matches"]
        assert record["labels"]
        indexes = [label["match_index"] for label in record["labels"]]
        assert len(indexes) == len(set(indexes))
        for label in record["labels"]:
            assert 0 <= label["match_index"] < len(matches)
            assert label["expected"] == record["expected_request"]
            assert not is_aggregate_match(matches[label["match_index"]])
    assert {(r["app"], r["expected_request"]) for r in records} == {
        ("dvwa", "attack"), ("dvwa", "false_positive"), ("flask", "attack"), ("flask", "false_positive")}
    assert sum(len(record["labels"]) > 1 for record in records) >= len(records) // 2
    assert any(record["wrong_stack"] for record in records if record["app"] == "flask")
    assert any(record["wrong_stack"] for record in records if record["app"] == "dvwa")
    assert {"REQUEST_HEADERS", "REQUEST_COOKIES"} <= {record["payload_target"]["collection"] for record in records}


def test_request_set_profile_matches_the_app():
    profiles = seeded_profiles()
    expected = {"dvwa": ("default-lab", ["php"]), "flask": ("shop-lab", ["python"])}
    for record in load_requests():
        context = record["application_context"]
        name, languages = expected[record["app"]]
        assert (context["profile_name"], context["application"]["languages"]) == (name, languages)
        normalized = normalize_audit_event(record["modsec_audit"])
        host = normalized["raw_request"]["headers"].get("Host")
        assert (host == SHOP_LAB_HOST) == (record["app"] == "flask")
        path = normalized["uri"].split("?", 1)[0]
        assert application_context_for(profiles, host, normalized["method"], path)[1] == context
