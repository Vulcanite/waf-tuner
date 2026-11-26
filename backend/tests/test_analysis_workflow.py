import asyncio
import json
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from openai import AsyncOpenAI
from sqlalchemy import select

from db import models
from services import agent, crs_index
from services.inference_retention import prune_audit_evidence, prune_inference_artifacts


@pytest.mark.parametrize("variant", ["normal", "missing_method", "rule_removed"])
def test_audited_match_becomes_a_reviewable_exception(tmp_path, monkeypatch, variant):
    monkeypatch.delenv("DATABASE_URL", raising=False)
    paths = {
        "DATABASE_PATH": tmp_path / "cases.db",
        "MODSEC_AUDIT_LOG": tmp_path / "audit.log",
        "EVENTS_JSONL_PATH": tmp_path / "events.jsonl",
        "AUDIT_CURSOR_PATH": tmp_path / "cursor.json",
        "RUNTIME_CONFIG_PATH": tmp_path / "runtime.json",
        "CRS_RULES_DIR": tmp_path / "rules",
    }
    for key, path in paths.items():
        monkeypatch.setenv(key, str(path))
    for key, value in {
        "SEED_DEFAULT_PROFILE": "false", "REQUIRE_APPLICATION_CONTEXT": "true",
        "LLM_API_KEY": "local", "LLM_API_BASE_URL": "http://classifier.test/v1",
        "LLM_MODEL": "test-classifier", "LLM_THINKING": "off",
        "AGENT_WORKER_CONCURRENCY": "1", "INFERENCE_ARTIFACT_RETENTION_DAYS": "0",
        "AUDIT_EVIDENCE_RETENTION_DAYS": "0", "EVENTS_JSONL_MAX_BYTES": "0",
        "INCIDENT_FINGERPRINT_KEY": "test-only-key", "AI_MAX_CONTEXT_BYTES": "16384",
    }.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(models, "_async_engine", None)
    monkeypatch.setattr(models, "_async_session_factory", None)
    monkeypatch.setattr(agent, "analysis_queue_changed", asyncio.Event())
    for name in ("_index_dir", "_marker_key", "_status", "CRS_INDEX"):
        monkeypatch.setattr(crs_index, name, getattr(crs_index, name))
    paths["CRS_RULES_DIR"].mkdir()
    (paths["CRS_RULES_DIR"] / "LOCAL.conf").write_text(
        'SecRule ARGS:q "@streq catalog-sample" "id:10001,phase:2,log"\n'
    )
    paths["MODSEC_AUDIT_LOG"].touch()
    sent = []

    def respond(request):
        sent.append(json.loads(request.content))
        result = {
            "classification": "false_positive",
            "confidence": 0.98,
            "verdict": "The matched value is an ordinary search term in the catalog.",
            "context_factors": ["Catalog search field"],
            "uncertainty_factors": [],
        }
        return httpx.Response(200, json={
            "choices": [{"index": 0, "message": {"role": "assistant", "content": json.dumps(result)},
                         "finish_reason": "stop"}],
        })

    def mock_provider(settings, concurrency):
        return AsyncOpenAI(
            api_key=settings["api_key"], base_url=settings["base_url"], max_retries=0,
            http_client=httpx.AsyncClient(transport=httpx.MockTransport(respond)),
        )

    monkeypatch.setattr(agent, "_make_provider", mock_provider)
    from main import app

    try:
        with TestClient(app) as client:
            profile = client.post("/api/application-profiles", json={
                "name": "catalog",
                "host_patterns": ["catalog.test"],
                "routes": [{
                    "path": "/catalog", "methods": ["GET"], "parameters": {"q": "Catalog search term"},
                }],
            })
            assert profile.status_code == 200, profile.text
            audited_request = {
                "uri": "/catalog?q=catalog-sample&token=private-value",
                "method": "GET",
                "headers": {"Host": "catalog.test", "Cookie": "session=private-cookie"},
            }
            if variant == "missing_method":
                del audited_request["method"]
            if variant == "rule_removed":
                # The alert fired under the rule, but the current ruleset no longer has it.
                monkeypatch.setattr(agent, "get_rule", lambda _: None)
            paths["MODSEC_AUDIT_LOG"].write_text(json.dumps({"transaction": {
                "id": "fixture-transaction",
                "time_stamp": "Mon Jan 01 12:00:00 2024",
                "request": audited_request,
                "messages": [{"details": {
                    "ruleId": "10001", "data": "Matched Data: catalog-sample found within ARGS:q: catalog-sample",
                }}],
            }}) + "\n")
            deadline = time.monotonic() + 12
            while time.monotonic() < deadline:
                cases = client.get("/api/cases").json()["items"]
                if cases and cases[0]["state"] in {"complete", "failed"}:
                    break
                time.sleep(0.05)
            assert cases and cases[0]["state"] == "complete", cases
            assert len(sent) == 1
            evidence = sent[0]["messages"][1]["content"]
            assert json.loads(evidence)["crs_rule"]["operator"] == "@streq catalog-sample"
            assert all(value not in evidence for value in ("private-value", "private-cookie", "fixture-transaction"))

            drafts = client.get("/api/exceptions?classification=false_positive").json()["items"]
            if variant != "normal":
                # No method, or a rule that no longer exists: nothing may become approvable.
                assert all(draft["validation_status"] != "valid" for draft in drafts)
                assert all(client.post(f"/api/exceptions/{draft['id']}/approve").status_code != 200 for draft in drafts)
                return
            assert len(drafts) == 1
            approved = client.post(f"/api/exceptions/{drafts[0]['id']}/approve")
            assert approved.status_code == 200, approved.text
            assert "ruleRemoveTargetById=10001;ARGS:q" in approved.json()["proposed_rule"]

        async def check_retention():
            cutoff = datetime.now(timezone.utc) + timedelta(days=1)
            assert await prune_inference_artifacts(cutoff) == 1
            assert await prune_audit_evidence(cutoff) == 1
            assert await prune_audit_evidence(cutoff) == 0
            async with models.get_session_factory()() as session:
                attempt = (await session.scalars(select(models.InferenceAttempt))).one()
                revision = (await session.scalars(select(models.AnalysisRevision))).one()
                event = (await session.scalars(select(models.AuditEvent))).one()
                draft = (await session.scalars(select(models.ExceptionDraft))).one()
                case = (await session.scalars(select(models.AnalysisCase))).one()
                assert attempt.status == "complete" and attempt.raw_response is None
                assert revision.classification == "false_positive"
                assert revision.normalized_rule is None and case.state == "stale"
                assert event.raw_event["evidence_expired"] and "raw_request" not in event.raw_event
                assert event.raw_event["matches"] == [{"rule_id": "10001"}]
                assert draft.status == "stale" and draft.proposed_rule is None

        asyncio.run(check_retention())
    finally:
        if models._async_engine is not None:
            asyncio.run(models._async_engine.dispose())
