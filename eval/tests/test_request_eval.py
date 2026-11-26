"""Request-level fixtures and the match/request analysis units in eval/evaluate.py.

No provider is contacted: every test replaces evaluate.request.
"""
import json
import sys
from pathlib import Path

import pytest

EVAL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(EVAL))

import evaluate  # noqa: E402
import report  # noqa: E402
from evaluate import oracle_response  # noqa: E402
from fixtures import load_fixtures  # noqa: E402


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


def request_reply(*items):
    return json.dumps({"verdicts": [{"match_index": index, **verdict(cls)} for index, cls in items]})


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

    def fake_request(messages, settings, attempt_type="initial", response_format=None):
        sent.append({"attempt": attempt_type, "messages": messages, "response_format": response_format})
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


def test_request_unit_makes_one_call_and_scores_both_matches(settings, monkeypatch):
    sent = mock_provider(monkeypatch, {"initial": request_reply((0, "true_positive"), (1, "false_positive"))})
    rows, calls, recordings = evaluate.evaluate_fixture(request_fixture(), "request", settings=settings)
    assert len(sent) == 1 and sent[0]["response_format"] == evaluate.REQUEST_RESPONSE_FORMAT
    context = json.loads(sent[0]["messages"][1]["content"])
    assert sorted(entry["match_index"] for entry in context["matches"]) == [0, 1]
    assert [item.get("rule_id") for item in context["other_matches"]] == ["949110"]
    assert [(row["id"], row["classification"], row["applies_to_stack"]) for row in rows] == [
        ("req-search#0", "true_positive", "yes"), ("req-search#1", "false_positive", "yes"),
    ]
    assert {row["call_id"] for row in rows} == {"req-search"} and all(row["valid"] for row in rows)
    assert len(calls) == 1 and calls[0]["model_calls"] == 1
    assert recordings[0]["prompt_version"] == evaluate.REQUEST_PROMPT_VERSION
    assert recordings[0]["prompt_sha256"] == evaluate.REQUEST_PROMPT_SHA256


def test_match_unit_makes_one_call_per_labeled_match(settings, monkeypatch):
    def reply(messages, attempt_type):
        context = json.loads(messages[1]["content"])
        is_attack = context["incident"]["rule_id"] == "942100"
        return json.dumps(verdict("true_positive" if is_attack else "false_positive"))

    sent = mock_provider(monkeypatch, reply)
    rows, calls, recordings = evaluate.evaluate_fixture(request_fixture(), "match", settings=settings)
    assert [item["attempt"] for item in sent] == ["initial", "initial"]
    assert all(item["response_format"] is None for item in sent)
    assert [row["classification"] for row in rows] == ["true_positive", "false_positive"]
    assert [call["id"] for call in calls] == ["req-search#0", "req-search#1"]
    assert all(rec["prompt_sha256"] == evaluate.PROMPT_SHA256 for rec in recordings)
    # Both units yield rows with the same fields, so scoring cannot depend on the unit.
    request_rows, _, _ = evaluate.evaluate_fixture(
        request_fixture(), "request", stored={"req-search": {"raw": request_reply((0, "true_positive"), (1, "false_positive")),
                                                             "finish_reason": "stop"}},
    )
    assert [set(row) for row in rows] == [set(row) for row in request_rows]


def test_a_missing_verdict_index_is_invalid_and_not_repaired(settings, monkeypatch):
    sent = mock_provider(monkeypatch, {"initial": request_reply((0, "true_positive"))})
    rows, calls, _ = evaluate.evaluate_fixture(request_fixture(), "request", settings=settings)
    assert [row["valid"] for row in rows] == [False, False]
    assert [item["attempt"] for item in sent] == ["initial"]
    summary = evaluate.build_report([request_fixture()], rows, settings, "mock", calls, "request")["summary"]
    assert summary["invalid"] == 2


def test_request_repair_runs_once_and_cannot_change_a_classification(settings, monkeypatch):
    # Missing the factor lists: invalid, but each classification is stated, so one repair is allowed.
    broken = json.dumps({"verdicts": [
        {"match_index": 0, "classification": "true_positive", "confidence": 0.9, "verdict": "x"},
        {"match_index": 1, "classification": "false_positive", "confidence": 0.95, "verdict": "x"},
    ]})
    flipped = request_reply((0, "false_positive"), (1, "false_positive"))
    sent = mock_provider(monkeypatch, {"initial": broken, "repair": flipped})
    rows, calls, recordings = evaluate.evaluate_fixture(request_fixture(), "request", settings=settings)
    assert [item["attempt"] for item in sent] == ["initial", "repair"]
    assert sent[1]["response_format"] == evaluate.REQUEST_RESPONSE_FORMAT
    assert [row["valid"] for row in rows] == [False, False] and all(row["repaired"] for row in rows)
    assert calls[0]["model_calls"] == 2

    kept = request_reply((0, "true_positive"), (1, "false_positive"))
    sent = mock_provider(monkeypatch, {"initial": broken, "repair": kept})
    rows, _, recordings = evaluate.evaluate_fixture(request_fixture(), "request", settings=settings)
    assert [item["attempt"] for item in sent] == ["initial", "repair"]
    assert [row["classification"] for row in rows] == ["true_positive", "false_positive"]
    # Confidence is capped at the candidate's; the stored repair input holds labels, not evidence.
    stored = json.loads(recordings[0]["repair_input"])
    assert set(stored) == {"verdicts"} and stored["verdicts"][1] == {
        "match_index": 1, "classification": "false_positive", "confidence": 0.95,
    }
    replayed, _, _ = evaluate.evaluate_fixture(request_fixture(), "request", stored={"req-search": recordings[0]})
    assert [row["classification"] for row in replayed] == ["true_positive", "false_positive"]


def test_request_escalation_only_for_an_unrepaired_uncertain_first_pass(monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "mock-key")
    monkeypatch.setenv("LLM_THINKING", "enabled")
    monkeypatch.setenv("LLM_ESCALATION_REASONING_EFFORT", "high")
    settings = evaluate.request_settings(model="mock")
    sent = mock_provider(monkeypatch, {
        "initial": request_reply((0, "true_positive"), (1, "uncertain")),
        "escalation": request_reply((0, "true_positive"), (1, "false_positive")),
    })
    rows, calls, _ = evaluate.evaluate_fixture(request_fixture(), "request", settings=settings)
    assert [item["attempt"] for item in sent] == ["initial", "escalation"]
    assert [row["classification"] for row in rows] == ["true_positive", "false_positive"]
    assert all(row["escalated"] for row in rows) and calls[0]["model_calls"] == 2


def test_cut_off_output_is_never_parsed(settings, monkeypatch):
    def fake_request(messages, settings, attempt_type="initial", response_format=None):
        content = request_reply((0, "true_positive"), (1, "false_positive"))
        return {"finish_reason": "length", "message": {"content": content}}, 1, {}

    monkeypatch.setattr(evaluate, "request", fake_request)
    rows, calls, _ = evaluate.evaluate_fixture(request_fixture(), "request", settings=settings)
    assert [row["valid"] for row in rows] == [False, False]
    assert calls[0]["finish_reason"] == "length" and calls[0]["model_calls"] == 1


def test_tokens_are_summed_once_per_call(settings, monkeypatch):
    fixtures = [request_fixture("req-a"), request_fixture("req-b")]
    mock_provider(monkeypatch, {"initial": request_reply((0, "true_positive"), (1, "false_positive"))})
    rows, calls = [], []
    for fixture in fixtures:
        fixture_rows, fixture_calls, _ = evaluate.evaluate_fixture(fixture, "request", settings=settings)
        rows += fixture_rows
        calls += fixture_calls
    tokens = evaluate.build_report(fixtures, rows, settings, "mock", calls, "request")["summary"]["tokens"]
    # Two requests, one call each: not four matches' worth of tokens.
    assert tokens["model_calls"] == 2 and tokens["calls_per_request"] == 1
    assert (tokens["prompt_tokens"], tokens["cached_prompt_tokens"], tokens["completion_tokens"],
            tokens["reasoning_tokens"]) == (2000, 1200, 400, 300)
    assert tokens["per_request"]["prompt_tokens"] == 1000
    assert tokens["per_scored_match"]["prompt_tokens"] == 500

    def reply(messages, attempt_type):
        context = json.loads(messages[1]["content"])
        return json.dumps(verdict("true_positive" if context["incident"]["rule_id"] == "942100" else "false_positive"))

    # DeepSeek's top-level cache field counts too.
    mock_provider(monkeypatch, reply, usage={"prompt_tokens": 800, "completion_tokens": 50, "prompt_cache_hit_tokens": 512})
    rows, calls, _ = evaluate.evaluate_fixture(fixtures[0], "match", settings=settings)
    tokens = evaluate.build_report(fixtures[:1], rows, settings, "mock", calls, "match")["summary"]["tokens"]
    assert (tokens["model_calls"], tokens["prompt_tokens"], tokens["cached_prompt_tokens"]) == (2, 1600, 1024)
    assert tokens["calls_per_request"] == 2 and tokens["per_scored_match"]["prompt_tokens"] == 800


def test_metrics_cover_gates_copyable_exclusions_and_stack(settings, monkeypatch):
    mock_provider(monkeypatch, {"initial": request_reply((0, "true_positive"), (1, "false_positive"))})
    fixture = request_fixture(wrong_stack=True)
    rows, calls, _ = evaluate.evaluate_fixture(fixture, "request", settings=settings)
    summary = evaluate.build_report([fixture], rows, settings, "mock", calls, "request")["summary"]
    assert summary["attacks_classified_false_positive"] == 0
    assert summary["attack_detection"] == 1 and summary["harmless_cleared_rate"] == 1
    assert summary["uncertain_rate"] == 0 and summary["invalid"] == 0
    assert summary["copyable_exclusions"] == 1  # ARGS:comment
    assert summary["applies_to_stack"] == {"attack": {"yes": 1}, "false_positive": {"yes": 1}}
    assert summary["wrong_stack_attacks"]["attacks"] == 1 and summary["wrong_stack_attacks"]["true_positive"] == 1


def test_recorded_mode_round_trips_per_model_and_unit(settings, monkeypatch, tmp_path):
    fixtures_path = tmp_path / "requests.jsonl"
    fixtures_path.write_text(json.dumps(request_fixture()) + "\n")
    crs = tmp_path / "crs"
    crs.mkdir()
    (crs / "LOCAL.conf").write_text('SecRule ARGS "@rx union" "id:942100,phase:2,log"\n')
    from services import crs_index

    for name in ("_index_dir", "_marker_key", "_status", "CRS_INDEX"):
        monkeypatch.setattr(crs_index, name, getattr(crs_index, name))

    def reply(messages, attempt_type):
        context = json.loads(messages[1]["content"])
        if "matches" in context:
            return request_reply((0, "true_positive"), (1, "false_positive"))
        return json.dumps(verdict("true_positive" if context["incident"]["rule_id"] == "942100" else "false_positive"))

    sent = mock_provider(monkeypatch, reply)
    base = ["--fixtures", str(fixtures_path), "--recordings-dir", str(tmp_path), "--model", "mock",
            "--record-as", "flash"]
    for unit in ("match", "request"):
        live = [*base, "--unit", unit, "--crs-rules-dir", str(crs), "--record", "--output", str(tmp_path / f"{unit}.json")]
        assert evaluate.main(live) == 0
        assert (tmp_path / f"flash__{unit}.jsonl").exists()
    assert len(sent) == 3  # two match-unit calls, one request-unit call
    monkeypatch.setattr(evaluate, "request", None)  # replay must not call a provider
    for unit, version in (("match", evaluate.PROMPT_VERSION), ("request", evaluate.REQUEST_PROMPT_VERSION)):
        output = tmp_path / f"replay-{unit}.json"
        assert evaluate.main([*base, "--mode", "recorded", "--unit", unit, "--output", str(output)]) == 0
        replay = json.loads(output.read_text())
        live = json.loads((tmp_path / f"{unit}.json").read_text())
        assert replay["prompt_version"] == version and replay["unit"] == unit
        assert [row["classification"] for row in replay["results"]] == [row["classification"] for row in live["results"]]
        assert replay["summary"]["tokens"]["prompt_tokens"] == live["summary"]["tokens"]["prompt_tokens"]
    with pytest.raises(ValueError, match="no recordings"):
        evaluate.main([*base, "--record-as", "pro", "--mode", "recorded", "--unit", "request"])


def test_gates_fail_on_an_attack_cleared_as_false_positive(settings, monkeypatch, tmp_path):
    fixtures_path = tmp_path / "requests.jsonl"
    fixtures_path.write_text(json.dumps(request_fixture()) + "\n")
    evaluate.write_recordings(evaluate.recording_path("leaky", tmp_path, "request"), [{
        "id": "req-search", "raw": request_reply((0, "false_positive"), (1, "false_positive")), "finish_reason": "stop",
    }])
    argv = ["--mode", "recorded", "--unit", "request", "--model", "leaky", "--fixtures", str(fixtures_path),
            "--recordings-dir", str(tmp_path), "--output", str(tmp_path / "report.json"), "--min-attack-detection", "0"]
    assert evaluate.main(argv) == 1


def write_run(tmp_path, name, unit, attack_class, usage):
    fixture = request_fixture()
    if unit == "request":
        records = [{"id": fixture["id"], "raw": request_reply((0, attack_class), (1, "false_positive")),
                    "finish_reason": "stop", "token_usage": usage, "model_calls": 1}]
    else:
        records = [
            {"id": "req-search#0", "raw": json.dumps(verdict(attack_class)), "finish_reason": "stop",
             "token_usage": usage, "model_calls": 1},
            {"id": "req-search#1", "raw": json.dumps(verdict("false_positive")), "finish_reason": "stop",
             "token_usage": usage, "model_calls": 1},
        ]
    evaluate.write_recordings(evaluate.recording_path(name, tmp_path, unit), records)


def test_comparison_report_renders_the_four_run_table(tmp_path):
    runs = []
    for model in ("deepseek-flash", "deepseek-pro"):
        for unit in ("match", "request"):
            write_run(tmp_path, model, unit, "true_positive" if model == "deepseek-pro" else "uncertain", USAGE)
            runs.append(f"{model}__{unit}")
    reports = report.evaluate_recordings([request_fixture()], runs, tmp_path)
    assert reports["deepseek-flash__request"]["summary"]["tokens"]["prompt_tokens"] == 1000
    assert reports["deepseek-flash__match"]["summary"]["tokens"]["prompt_tokens"] == 2000
    out = tmp_path / "out"
    report.write_reports(reports, out)
    table = (out / "comparison.md").read_text()
    header = next(line for line in table.splitlines() if line.startswith("| metric"))
    assert header == "| metric | " + " | ".join(runs) + " |"
    rows = {line.split(" | ")[0].lstrip("| "): line for line in table.splitlines() if line.startswith("| ")}
    assert rows["unit"].endswith("| match | request | match | request |")
    assert rows["attack detection"].endswith("| 0.0% | 0.0% | 100.0% | 100.0% |")
    assert rows["model calls"].endswith("| 2 | 1 | 2 | 1 |")
    assert rows["prompt tokens"].endswith("| 2,000 | 1,000 | 2,000 | 1,000 |")
    for label in ("cached prompt tokens", "reasoning tokens", "copyable exclusions (estimate)",
                  "attacks classified false_positive (must be 0)", "harmless correctly cleared", "uncertain rate"):
        assert label in rows
    assert "Run metrics" in (out / "deepseek-pro__request.md").read_text()


def test_old_fixtures_and_oracle_still_pass_in_the_match_unit(tmp_path):
    fixtures = load_fixtures()
    reports = report.evaluate_recordings(fixtures, ["oracle"], EVAL / "recordings")
    summary = reports["oracle"]["summary"]
    assert summary["scored_matches"] == len(fixtures) and summary["invalid"] == 0
    assert summary["attacks_classified_false_positive"] == 0 and summary["harmless_cleared_rate"] == 1
    argv = ["--mode", "recorded", "--model", "oracle", "--unit", "match", "--output", str(tmp_path / "o.json")]
    assert evaluate.main(argv) == 0


def test_an_old_fixture_runs_as_a_one_match_request(settings, monkeypatch):
    fixture = load_fixtures()[0]
    sent = mock_provider(monkeypatch, {"initial": request_reply((0, "false_positive"))})
    rows, calls, _ = evaluate.evaluate_fixture(fixture, "request", settings=settings)
    assert len(sent) == 1 and [row["id"] for row in rows] == [fixture["id"]]
    assert rows[0]["classification"] == "false_positive"
