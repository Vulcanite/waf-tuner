import asyncio
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from openai import AsyncOpenAI
from sqlalchemy import select

from db import models
from db.models import AnalysisCase, AnalysisRevision, AuditEvent, IncidentOccurrence, InferenceAttempt
from services import agent
from services.llm_options import request_settings
from services.model_contract import classify_repair_response


@pytest.fixture
def isolated_database(tmp_path, monkeypatch):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.setenv("DATABASE_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("INCIDENT_FINGERPRINT_KEY", "test-only-key")
    monkeypatch.setattr(models, "_async_engine", None)
    monkeypatch.setattr(models, "_async_session_factory", None)


async def insert_case():
    now = datetime.now(timezone.utc)
    event = {
        "transaction_id": "test-transaction",
        "method": "GET",
        "uri": "/search?q=books",
        "raw_request": {"headers": {"Host": "books.example.test"}},
        "matches": [{"rule_id": "942100", "matched_data": "books", "collection": "ARGS", "parameter": "q"}],
    }
    async with models.get_session_factory()() as session:
        case = AnalysisCase(
            fingerprint="test-fingerprint", method="GET", application_host="books.example.test",
            path="/search", rule_id="942100", collection="ARGS", parameter="q", latest_event_line=1,
        )
        audit_event = AuditEvent(
            transaction_id=event["transaction_id"], event_line=1, timestamp=now, raw_event=event,
        )
        session.add_all([case, audit_event])
        await session.flush()
        session.add(IncidentOccurrence(
            audit_event_id=audit_event.id, analysis_case_id=case.id,
            transaction_id=audit_event.transaction_id, event_line=1, match_index=0,
            rule_id=case.rule_id, fingerprint=case.fingerprint,
        ))
        await session.commit()
        return case.id


async def run_next_case():
    claim_token = "test-claim"
    case_id = await agent._claim_case(claim_token)
    assert case_id is not None
    token = agent._claim_token.set(claim_token)
    try:
        await agent._run_claimed_case(case_id)
    finally:
        agent._claim_token.reset(token)
    return case_id


def test_budget_deferred_repair_resumes_with_same_revision(isolated_database, monkeypatch):
    monkeypatch.setenv("AGENT_MAX_REQUESTS_PER_HOUR", "1")
    monkeypatch.setenv("LLM_API_KEY", "test")
    monkeypatch.setenv("LLM_API_BASE_URL", "https://model.example.test/v1")
    monkeypatch.setenv("LLM_THINKING", "off")
    monkeypatch.setenv("LLM_ESCALATION_REASONING_EFFORT", "")
    replies = [
        {"classification": "true_positive", "confidence": 0.95, "verdict": "unstructured invalid prose"},
        {
            "classification": "true_positive", "confidence": 0.99,
            "verdict": "The observed evidence supports this synthetic test verdict.",
            "context_factors": ["synthetic evidence"], "uncertainty_factors": [],
        },
    ]
    sent = []

    def transport(request):
        assert request.url.path == "/v1/chat/completions"
        sent.append(json.loads(request.content))
        return httpx.Response(200, json={
            "id": "mock-completion", "model": "mock", "object": "chat.completion", "created": 1,
            "choices": [{"index": 0, "finish_reason": "stop", "message": {
                "role": "assistant", "content": json.dumps(replies.pop(0)),
            }}],
            "usage": {
                "prompt_tokens": 100, "completion_tokens": 40, "total_tokens": 140,
                "completion_tokens_details": {"reasoning_tokens": 5},
            },
        })

    async def run():
        await models.init_db()
        async with AsyncOpenAI(
            api_key="test", base_url="https://model.example.test/v1", max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(transport)),
        ) as client:
            with patch.object(agent, "_provider_client", client), patch.object(agent, "_provider_settings", request_settings()):
                case_id = await insert_case()
                assert await run_next_case() == case_id
                async with models.get_session_factory()() as session:
                    case = await session.get(AnalysisCase, case_id)
                    revision = (await session.execute(select(AnalysisRevision))).scalars().one()
                    attempt = (await session.execute(select(InferenceAttempt))).scalars().one()
                    assert case.state == "queued"
                    assert revision.state == "budget_deferred"
                    assert revision.pending_repair_input
                    assert attempt.provider_ms is not None and attempt.reasoning_tokens == 5
                    assert await agent.next_budget_at() is not None
                    case.next_retry_at = datetime.now(timezone.utc) - timedelta(minutes=1)
                    attempt.started_at = datetime.now(timezone.utc) - timedelta(hours=2)
                    await session.commit()
                assert await run_next_case() == case_id
                async with models.get_session_factory()() as session:
                    revision = (await session.execute(select(AnalysisRevision))).scalars().one()
                    attempts = (await session.execute(select(InferenceAttempt).order_by(InferenceAttempt.id))).scalars().all()
                    assert revision.state == "complete"
                    assert revision.confidence == 0.95
                    assert revision.pending_repair_input is None
                    assert revision.stage_metrics["context_ms"] >= 0
                    assert revision.stage_metrics["budget_wait_ms"] >= 0
                    assert [attempt.attempt_type for attempt in attempts] == ["initial", "repair"]
        await models._async_engine.dispose()

    asyncio.run(run())
    assert len(sent) == 2
    first_context = json.loads(sent[0]["messages"][1]["content"])
    assert first_context["incident"]["rule_id"] == "942100"
    repair = json.loads(sent[1]["messages"][1]["content"])
    assert repair == {"classification": "true_positive", "confidence": 0.95, "evidence": first_context}
    assert "unstructured invalid prose" not in sent[1]["messages"][1]["content"]


def test_replaced_lease_cannot_write_current_attempt(isolated_database):
    async def run():
        await models.init_db()
        case_id = await insert_case()
        assert await agent._claim_case("first-worker") == case_id
        async with models.get_session_factory()() as session:
            case = await session.get(AnalysisCase, case_id)
            case.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
            await session.commit()
        await agent._recover_expired_leases()
        assert await agent._claim_case("next-worker") == case_id
        token = agent._claim_token.set("first-worker")
        try:
            await agent._record_retry(case_id, agent.TerminalAnalysisError("stale worker"))
        finally:
            agent._claim_token.reset(token)
        async with models.get_session_factory()() as session:
            case = await session.get(AnalysisCase, case_id)
            assert case.lease_token == "next-worker"
            assert case.state == "analyzing"
        await models._async_engine.dispose()

    asyncio.run(run())


def test_unstructured_output_without_classification_does_not_trigger_repair():
    provider = AsyncMock(return_value="No final classification is available.")
    with patch.object(agent, "_provider_request", provider):
        with pytest.raises(agent.InvalidOutputError):
            asyncio.run(agent._call_model({}, {}, 1))
    assert provider.await_count == 1


@pytest.mark.parametrize("provider_error, blocked", [
    ("Unsupported reasoning_effort", True),
    ("Invalid evidence format", False),
])
def test_only_effort_rejection_pauses_escalation(provider_error, blocked, monkeypatch):
    monkeypatch.setenv("LLM_API_KEY", "test")
    monkeypatch.setenv("LLM_THINKING", "enabled")
    monkeypatch.setenv("LLM_REASONING_EFFORT", "low")
    monkeypatch.setenv("LLM_ESCALATION_REASONING_EFFORT", "hgih")
    monkeypatch.setattr(agent, "_provider_settings", request_settings())
    monkeypatch.setattr(agent, "_provider_configuration_error", None)
    monkeypatch.setattr(agent, "_escalation_error", None)
    sent = []
    result = {
        "classification": "uncertain", "confidence": 0.5,
        "verdict": "This evidence needs review to determine the application intent.",
        "context_factors": [], "uncertainty_factors": [],
    }

    def respond(request):
        effort = json.loads(request.content)["reasoning_effort"]
        sent.append(effort)
        if effort == "hgih":
            return httpx.Response(400, json={"error": {"message": provider_error}})
        return httpx.Response(200, json={
            "choices": [{"index": 0, "finish_reason": "stop",
                         "message": {"role": "assistant", "content": json.dumps(result)}}],
        })

    async def run():
        async with AsyncOpenAI(
            api_key="test", base_url="https://model.example.test/v1", max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
        ) as client:
            with (
                patch.object(agent, "_provider_client", client),
                patch.object(agent, "_reserve_attempt", AsyncMock(side_effect=[1, 2, 3, 4])),
                patch.object(agent, "_finish_attempt", AsyncMock()) as finish,
            ):
                for revision_id in (1, 2):
                    verdict, _ = await agent._call_model({}, {}, revision_id)
                    assert verdict["classification"] == "uncertain"
                settings = agent.public_model_settings()
                assert settings["configuration_error"] is None
                assert bool(settings["escalation_error"]) is blocked
                if blocked:
                    assert finish.await_args_list[1].kwargs["error_code"] == "escalation_effort_rejected"

    asyncio.run(run())
    assert sent == (["low", "hgih", "low"] if blocked else ["low", "hgih", "low", "hgih"])


def test_repair_cannot_reclassify_a_detection_as_false_positive():
    initial = json.dumps({"classification": "true_positive", "confidence": 0.96, "evidence": {}})
    repaired = json.dumps({
        "classification": "false_positive", "confidence": 0.99,
        "verdict": "A repair may not change the selected classification.",
        "context_factors": [], "uncertainty_factors": [],
    })
    with pytest.raises(ValueError, match="changed"):
        classify_repair_response(repaired, initial)


def test_generation_change_marks_completed_case_and_draft_stale(isolated_database, monkeypatch):
    monkeypatch.setattr(agent, "_last_generation", None)
    monkeypatch.setattr(agent, "_analysis_generation", lambda ruleset: "next-generation")

    async def run():
        await models.init_db()
        case_id = await insert_case()
        async with models.get_session_factory()() as session:
            case = await session.get(AnalysisCase, case_id)
            case.state = "complete"
            case.completed_generation = "previous-generation"
            revision = AnalysisRevision(
                analysis_case_id=case_id, model="prior-model", prompt_version="previous",
                state="complete", classification="false_positive",
            )
            session.add(revision)
            await session.flush()
            session.add(models.ExceptionDraft(
                transaction_id="test-transaction", event_line=1, classification="false_positive",
                confidence=0.96, verdict="A previous model found this observed traffic benign.",
                status="approved", analysis_revision_id=revision.id,
            ))
            await session.commit()
        await agent._mark_obsolete_verdicts()
        async with models.get_session_factory()() as session:
            case = await session.get(AnalysisCase, case_id)
            revision = (await session.execute(select(AnalysisRevision))).scalars().one()
            draft = (await session.execute(select(models.ExceptionDraft))).scalars().one()
            assert case.state == "stale"
            assert draft.status == "stale"
            assert revision.classification == "false_positive"
        await models._async_engine.dispose()

    asyncio.run(run())
