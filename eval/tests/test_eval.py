import json
import sys
import io
from pathlib import Path

import pytest

EVAL = Path(__file__).resolve().parents[1]
ROOT = EVAL.parent
sys.path.insert(0, str(EVAL))

from capture_lab import label_request_matches, parse_audit_log  # noqa: E402
from corpus import RequestCase, all_cases, request_cases, route_profile  # noqa: E402
from evaluate import load_recordings, oracle_response, recording_path  # noqa: E402
from fixtures import case_to_fixture, load_fixtures, merge_fixtures  # noqa: E402
from report import evaluate_recordings, matrix_markdown, write_reports  # noqa: E402
import evaluate  # noqa: E402
import report  # noqa: E402
from services import crs_index  # noqa: E402
from services.audit_event import normalize_audit_event  # noqa: E402
from services.inference_context import is_aggregate_match  # noqa: E402
from services.lab_profiles import SHOP_LAB_HOST, seeded_profiles  # noqa: E402
from services.profile_match import application_context_for  # noqa: E402
from services.redaction import is_credential_name  # noqa: E402

REQUESTS = EVAL / "requests.jsonl"


def replay(fixture, recording):
    """One match-level fixture replayed (the path `evaluate.py --mode recorded` takes)."""
    rows, _, _ = evaluate.evaluate_fixture(fixture, stored={fixture["id"]: recording} if recording else {})
    return rows[0]


def run_live(fixture, settings):
    """One match-level fixture run live: (row, recording)."""
    rows, _, recordings = evaluate.evaluate_fixture(fixture, settings=settings)
    return rows[0], recordings[0]


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
    results = [replay(fixture, stored[fixture["id"]]) for fixture in fixtures]
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
    result, recording = run_live(fixture, evaluate.request_settings(model="mock"))
    assert result["classification"] == "false_positive"
    assert len(sent) == 1 and sent[0]["response_format"]["type"] == "json_schema"
    user_message = sent[0]["messages"][1]["content"]
    context = json.loads(user_message)
    assert context["crs_rule"]["operator"] == "@streq music"
    assert "books" in user_message and "music" in user_message
    assert "secret-fixture" not in user_message and "local-fixture" not in user_message
    assert "api_key" not in recording["settings"]
    assert recording["prompt_sha256"] == evaluate.PROMPT_SHA256
    assert replay({**fixture, "expected": "attack"}, recording)["finish_reason"] == "fixture_mismatch"


def test_recorded_metadata_cannot_rescue_invalid_output():
    fixture = {"id": "benign-catalog", "expected": "false_positive"}
    result = replay(fixture, {"classification": "false_positive", "raw": "not JSON"})
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
        result, _ = run_live(fixture, settings)
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
    result, _ = run_live(fixture, settings)
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
    fixture = {"id": "pinned", "audit_event": event}
    context = evaluate.match_context(fixture, *evaluate.fixture_event(fixture)[::2], 0)
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
    # A credential-named cookie or header is hidden from the model, so the corpus avoids them. The one
    # exception was captured before remember-me cookies counted as credentials; the model now sees
    # that target hidden. Rename the cookie when eval/requests.jsonl is next regenerated.
    hidden = [case.id for case in cases if case.target in {"header", "cookie"} and is_credential_name(case.parameter)]
    assert hidden == ["dvwa-attack-java-cookie-java-deser"]


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
        live = application_context_for(profiles, host, normalized["method"], path)[1]
        assert live == context


# Request-level fixtures: a captured ModSecurity record with several labeled matches.

ATTACK_Q = "1' UNION SELECT password FROM users--"


def request_fixture(fixture_id="req-search", wrong_stack=None):
    """A ModSecurity serial record with two scored matches and the 949110 anomaly-score match."""
    fixture = {
        "id": fixture_id,
        "app": "flask",
        "source": "lab-capture",
        "expected_request": "attack",
        "modsec_audit": {"transaction": {
            "id": "txn-" + fixture_id,
            "time_stamp": "Mon Jan 01 12:00:00 2024",
            "client_ip": "10.0.0.5",
            "request": {
                "method": "GET",
                "uri": "/search?q=1%27%20UNION%20SELECT%20password%20FROM%20users--&comment=select%20all%20shoes",
                "headers": {"Host": "shop.test", "User-Agent": "lab"},
            },
            "messages": [
                {"message": "SQL Injection Attack Detected via libinjection", "details": {
                    "ruleId": "942100", "severity": "2",
                    "data": f"Matched Data: {ATTACK_Q} found within ARGS:q: {ATTACK_Q}",
                }},
                {"message": "Detects MSSQL code execution and information gathering attempts", "details": {
                    "ruleId": "942190", "severity": "2",
                    "data": "Matched Data: select all found within ARGS:comment: select all shoes",
                }},
                {"message": "Inbound Anomaly Score Exceeded (Total Score: 10)", "details": {
                    "ruleId": "949110", "severity": "2", "data": "",
                }},
            ],
        }},
        "labels": [
            {"match_index": 0, "expected": "attack"},
            {"match_index": 1, "expected": "false_positive"},
        ],
        "application_context": {
            "application": {"purpose": "shop search", "languages": ["python"], "data_stores": ["sqlite"]},
            "route": {"path": "/search", "methods": ["GET"],
                      "parameters": {"q": "product search terms", "comment": "free-text shopper note"}},
        },
        "payload_target": {"collection": "ARGS", "parameter": "q"},
        "notes": "synthetic request for eval tests",
    }
    if wrong_stack is not None:
        fixture["labels"][0]["wrong_stack"] = wrong_stack
    return fixture


def verdict(classification, **extra):
    base = {**oracle_response("attack" if classification == "true_positive" else "false_positive"),
            "classification": classification, "applies_to_stack": "yes"}
    return {**base, **extra}


def by_rule(messages, attempt_type):
    """The attack on `q` (942100) is a true positive, the comment match (942190) a false positive."""
    context = json.loads(messages[1]["content"])
    return json.dumps(verdict("true_positive" if context["incident"]["rule_id"] == "942100" else "false_positive"))


USAGE = {
    "prompt_tokens": 1000, "completion_tokens": 200,
    "prompt_tokens_details": {"cached_tokens": 600},
    "completion_tokens_details": {"reasoning_tokens": 150},
}


@pytest.fixture
def settings(monkeypatch):
    monkeypatch.setenv("LLM_API_BASE_URL", "http://localhost:12345/v1")
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setenv("LLM_ESCALATION_REASONING_EFFORT", "")
    monkeypatch.setenv("FALSE_POSITIVE_THRESHOLD", "0.90")
    return evaluate.request_settings(model="mock")


def mock_provider(monkeypatch, replies, usage=USAGE):
    """replies: attempt_type -> content, or a callable(messages, attempt_type) -> content."""
    sent = []

    def fake_request(messages, settings, attempt_type="initial"):
        sent.append({"attempt": attempt_type, "messages": messages})
        content = replies(messages, attempt_type) if callable(replies) else replies[attempt_type]
        return {"finish_reason": "stop", "message": {"content": content}}, 7, usage

    monkeypatch.setattr(evaluate, "request", fake_request)
    return sent


def test_request_fixture_loads_and_rejects_an_aggregate_label(tmp_path):
    path = tmp_path / "requests.jsonl"
    path.write_text(json.dumps(request_fixture()) + "\n")
    assert evaluate.load_fixture_rows(path)[0]["id"] == "req-search"
    bad = request_fixture()
    bad["labels"].append({"match_index": 2, "expected": "attack"})
    path.write_text(json.dumps(bad) + "\n")
    with pytest.raises(ValueError, match="aggregate"):
        evaluate.load_fixture_rows(path)


def test_one_call_per_labeled_match(settings, monkeypatch):
    sent = mock_provider(monkeypatch, by_rule)
    rows, calls, recordings = evaluate.evaluate_fixture(request_fixture(), settings=settings)
    assert [item["attempt"] for item in sent] == ["initial", "initial"]
    context = json.loads(sent[0]["messages"][1]["content"])
    assert [item.get("rule_id") for item in context["incident"]["other_matches"]] == ["942190", "949110"]
    assert [(row["id"], row["classification"], row["applies_to_stack"]) for row in rows] == [
        ("req-search#0", "true_positive", "yes"), ("req-search#1", "false_positive", "yes"),
    ]
    assert [call["id"] for call in calls] == ["req-search#0", "req-search#1"]
    assert all(rec["prompt_sha256"] == evaluate.PROMPT_SHA256 for rec in recordings)


def test_repair_cannot_change_a_classification(settings, monkeypatch):
    # Missing the factor lists: invalid, but the classification is stated, so one repair is allowed.
    broken = json.dumps({"classification": "false_positive", "confidence": 0.95, "verdict": "x"})
    fixture = {**request_fixture(), "labels": [{"match_index": 1, "expected": "false_positive"}]}
    sent = mock_provider(monkeypatch, {"initial": broken, "repair": json.dumps(verdict("true_positive"))})
    rows, calls, _ = evaluate.evaluate_fixture(fixture, settings=settings)
    assert [item["attempt"] for item in sent] == ["initial", "repair"]
    assert not rows[0]["valid"] and rows[0]["repaired"] and calls[0]["model_calls"] == 2

    sent = mock_provider(monkeypatch, {"initial": broken, "repair": json.dumps(verdict("false_positive"))})
    rows, _, recordings = evaluate.evaluate_fixture(fixture, settings=settings)
    assert rows[0]["classification"] == "false_positive"
    # The stored repair input holds the candidate label, not the evidence.
    assert json.loads(recordings[0]["repair_input"]) == {"classification": "false_positive", "confidence": 0.95}
    replayed, _, _ = evaluate.evaluate_fixture(fixture, stored={"req-search#1": recordings[0]})
    assert replayed[0]["classification"] == "false_positive"


def test_copyable_estimate_applies_the_route_and_evidence_gates(settings, monkeypatch):
    def cleared(fixture):
        mock_provider(monkeypatch, by_rule)
        rows, calls, _ = evaluate.evaluate_fixture(fixture, settings=settings)
        return evaluate.build_report([fixture], rows, settings, "mock", calls)["summary"], rows

    summary, rows = cleared(request_fixture())
    assert summary["copyable_exclusions"] == 1
    assert (rows[1]["route_supports_exception"], rows[1]["evidence_withheld"]) == (True, False)

    # The route does not document `comment`: the worker withholds the draft.
    undocumented = request_fixture()
    del undocumented["application_context"]["route"]["parameters"]["comment"]
    summary, rows = cleared(undocumented)
    assert summary["copyable_exclusions"] == 0 and rows[1]["route_supports_exception"] is False

    # A cookie entry on the route never vouches for an argument of the same name.
    cookie_only = request_fixture()
    parameters = cookie_only["application_context"]["route"]["parameters"]
    parameters["REQUEST_COOKIES:comment"] = parameters.pop("comment")
    assert cleared(cookie_only)[0]["copyable_exclusions"] == 0

    # The match's own evidence was trimmed: no copyable rule either.
    monkeypatch.setenv("AI_MAX_CONTEXT_BYTES", "300")
    summary, rows = cleared(request_fixture())
    assert summary["copyable_exclusions"] == 0 and rows[1]["evidence_withheld"] is True


def test_cut_off_output_is_never_parsed(settings, monkeypatch):
    def fake_request(messages, settings, attempt_type="initial"):
        return {"finish_reason": "length", "message": {"content": json.dumps(verdict("false_positive"))}}, 1, {}

    monkeypatch.setattr(evaluate, "request", fake_request)
    rows, calls, _ = evaluate.evaluate_fixture(request_fixture(), settings=settings)
    assert [row["valid"] for row in rows] == [False, False]
    assert calls[0]["finish_reason"] == "length" and calls[0]["model_calls"] == 1


def test_tokens_are_summed_once_per_call(settings, monkeypatch):
    fixtures = [request_fixture("req-a"), request_fixture("req-b")]
    mock_provider(monkeypatch, by_rule)
    rows, calls = [], []
    for fixture in fixtures:
        fixture_rows, fixture_calls, _ = evaluate.evaluate_fixture(fixture, settings=settings)
        rows += fixture_rows
        calls += fixture_calls
    tokens = evaluate.build_report(fixtures, rows, settings, "mock", calls)["summary"]["tokens"]
    # Two requests, two labeled matches each, one call per match.
    assert tokens["model_calls"] == 4 and tokens["calls_per_request"] == 2
    assert (tokens["prompt_tokens"], tokens["cached_prompt_tokens"], tokens["completion_tokens"],
            tokens["reasoning_tokens"]) == (4000, 2400, 800, 600)
    assert tokens["per_request"]["prompt_tokens"] == 2000
    assert tokens["per_scored_match"]["prompt_tokens"] == 1000


def test_cached_tokens_come_only_from_the_openai_compatible_field():
    from scoring import usage_tokens

    # A provider-specific top-level cache field is ignored, alone or beside the standard one.
    assert usage_tokens({"prompt_tokens": 800, "prompt_cache_hit_tokens": 512})["cached_prompt_tokens"] == 0
    both = {"prompt_tokens": 800, "prompt_cache_hit_tokens": 512, "prompt_tokens_details": {"cached_tokens": 256}}
    assert usage_tokens(both)["cached_prompt_tokens"] == 256


def test_metrics_cover_gates_copyable_exclusions_and_stack(settings, monkeypatch):
    mock_provider(monkeypatch, by_rule)
    fixture = request_fixture(wrong_stack=True)
    rows, calls, _ = evaluate.evaluate_fixture(fixture, settings=settings)
    summary = evaluate.build_report([fixture], rows, settings, "mock", calls)["summary"]
    assert summary["attacks_classified_false_positive"] == 0
    assert summary["attack_detection"] == 1 and summary["harmless_cleared_rate"] == 1
    assert summary["uncertain_rate"] == 0 and summary["invalid"] == 0
    assert summary["copyable_exclusions"] == 1  # ARGS:comment
    assert summary["applies_to_stack"] == {"attack": {"yes": 1}, "false_positive": {"yes": 1}}
    assert summary["wrong_stack_attacks"]["attacks"] == 1 and summary["wrong_stack_attacks"]["true_positive"] == 1


def test_recorded_mode_round_trips_per_model(settings, monkeypatch, tmp_path):
    fixtures_path = tmp_path / "requests.jsonl"
    fixtures_path.write_text(json.dumps(request_fixture()) + "\n")
    crs = tmp_path / "crs"
    crs.mkdir()
    (crs / "LOCAL.conf").write_text('SecRule ARGS "@rx union" "id:942100,phase:2,log"\n')
    for name in ("_index_dir", "_marker_key", "_status", "CRS_INDEX"):
        monkeypatch.setattr(crs_index, name, getattr(crs_index, name))
    sent = mock_provider(monkeypatch, by_rule)
    base = ["--fixtures", str(fixtures_path), "--recordings-dir", str(tmp_path), "--model", "mock",
            "--record-as", "flash"]
    live = [*base, "--crs-rules-dir", str(crs), "--record", "--output", str(tmp_path / "live.json")]
    assert evaluate.main(live) == 0
    assert (tmp_path / "flash.jsonl").exists() and len(sent) == 2
    monkeypatch.setattr(evaluate, "request", None)  # replay must not call a provider
    output = tmp_path / "replay.json"
    assert evaluate.main([*base, "--mode", "recorded", "--output", str(output)]) == 0
    replayed = json.loads(output.read_text())
    recorded = json.loads((tmp_path / "live.json").read_text())
    assert replayed["prompt_version"] == evaluate.PROMPT_VERSION
    assert [row["classification"] for row in replayed["results"]] == [row["classification"] for row in recorded["results"]]
    assert replayed["summary"]["tokens"]["prompt_tokens"] == recorded["summary"]["tokens"]["prompt_tokens"]
    with pytest.raises(ValueError, match="no recordings"):
        evaluate.main([*base, "--record-as", "pro", "--mode", "recorded"])


def test_gates_fail_on_an_attack_cleared_as_false_positive(tmp_path):
    fixtures_path = tmp_path / "requests.jsonl"
    fixtures_path.write_text(json.dumps(request_fixture()) + "\n")
    evaluate.write_recordings(evaluate.recording_path("leaky", tmp_path), [
        {"id": f"req-search#{index}", "raw": json.dumps(verdict("false_positive")), "finish_reason": "stop"}
        for index in (0, 1)
    ])
    argv = ["--mode", "recorded", "--model", "leaky", "--fixtures", str(fixtures_path),
            "--recordings-dir", str(tmp_path), "--output", str(tmp_path / "report.json"), "--min-attack-detection", "0"]
    assert evaluate.main(argv) == 1


def test_comparison_report_renders_one_column_per_run(tmp_path):
    runs = ["deepseek-flash", "deepseek-pro"]
    for run in runs:
        attack_class = "true_positive" if run == "deepseek-pro" else "uncertain"
        evaluate.write_recordings(evaluate.recording_path(run, tmp_path), [
            {"id": "req-search#0", "raw": json.dumps(verdict(attack_class)), "finish_reason": "stop",
             "token_usage": USAGE, "model_calls": 1},
            {"id": "req-search#1", "raw": json.dumps(verdict("false_positive")), "finish_reason": "stop",
             "token_usage": USAGE, "model_calls": 1},
        ])
    reports = report.evaluate_recordings([request_fixture()], runs, tmp_path)
    assert reports["deepseek-flash"]["summary"]["tokens"]["prompt_tokens"] == 2000
    out = tmp_path / "out"
    report.write_reports(reports, out)
    table = (out / "comparison.md").read_text()
    header = next(line for line in table.splitlines() if line.startswith("| metric"))
    assert header == "| metric | " + " | ".join(runs) + " |"
    rows = {line.split(" | ")[0].lstrip("| "): line for line in table.splitlines() if line.startswith("| ")}
    assert rows["attack detection"].endswith("| 0.0% | 100.0% |")
    assert rows["model calls"].endswith("| 2 | 2 |")
    assert rows["prompt tokens"].endswith("| 2,000 | 2,000 |")
    for label in ("cached prompt tokens", "reasoning tokens", "copyable exclusions (estimate)",
                  "attacks classified false_positive (must be 0)", "harmless correctly cleared", "uncertain rate"):
        assert label in rows
    assert "Run metrics" in (out / "deepseek-pro.md").read_text()
