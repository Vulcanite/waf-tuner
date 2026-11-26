"""Bounded off-path analysis with auditable provider attempts and safe drafts."""
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import math
import os
import random
from contextvars import ContextVar
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from time import perf_counter
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
from openai import AsyncOpenAI
from sqlalchemy import func, or_, select, text, update

from db.models import (
    AnalysisCase,
    AnalysisRevision,
    AuditEvent,
    ExceptionDraft,
    InferenceAttempt,
    IncidentOccurrence,
    get_session_factory,
)
from services.application_context import profile_is_current, select_application_context
from services.crs_index import get_rule, get_rule_at, index_status
from services.draft_scope import canonical_scope_key, case_exception_scope, rule_numeric_id
from services.exception_builder import build_exception_rule, can_build_exception
from services.json_extract import extract_json as _extract_json
from services.inference_context import (
    bound_repair_input, bound_request_repair_input, build_inference_context, build_request_context,
    match_evidence_withheld, request_match_view, serialize_inference_context,
)
from services.llm_options import (
    ESCALATION_EFFORT_REJECTED, analysis_unit, env_bool, is_escalation_effort_rejection, request_payload,
    request_settings,
)
from services.model_contract import (
    JSON_REPAIR_PROMPT, PROMPT_SHA256, PROMPT_VERSION, REQUEST_JSON_REPAIR_PROMPT, REQUEST_PROMPT_SHA256,
    REQUEST_PROMPT_VERSION, REQUEST_RESPONSE_FORMAT, RESPONSE_FORMAT,
    CompletionOutputError, classify_repair_response, classify_request_repair_response, classify_request_response,
    classify_response, completion_text, false_positive_threshold, repair_messages, request_repair_messages,
    request_response_messages, response_messages,
)
from services.profile_match import route_supports_exception
from services.scope_conflicts import (
    SCOPE_CONFLICT_ERROR,
    has_true_positive,
    invalidate_false_positive_drafts,
)

logger = logging.getLogger(__name__)
analysis_queue_changed = asyncio.Event()
_claim_token: ContextVar[str | None] = ContextVar("analysis_claim_token", default=None)
_provider_client: AsyncOpenAI | None = None
_provider_settings: dict | None = None
_provider_configuration_error: str | None = None
_escalation_error: str | None = None
_last_generation: str | None = None
_provider_paused_until: datetime | None = None


def initialize_analysis_queue() -> asyncio.Event:
    global analysis_queue_changed
    analysis_queue_changed = asyncio.Event()
    return analysis_queue_changed


class ClaimLost(RuntimeError):
    """An expired worker must leave the current owner's state alone."""


class RetryableAnalysisError(RuntimeError):
    def __init__(self, message: str, *, error_code: str = "provider_error", retry_after: float | None = None):
        super().__init__(message)
        self.error_code = error_code
        self.retry_after = retry_after


class TerminalAnalysisError(RuntimeError):
    def __init__(self, message: str, *, error_code: str = "configuration_error"):
        super().__init__(message)
        self.error_code = error_code


class InvalidOutputError(TerminalAnalysisError):
    def __init__(self, message: str, raw_response: str):
        super().__init__(message, error_code="invalid_output")
        self.raw_response = raw_response


class RetryableInvalidOutput(RetryableAnalysisError):
    """Request mode: invalid output for a group of several cases goes through the normal retry path."""

    def __init__(self, message: str, raw_response: str):
        super().__init__(message, error_code="invalid_output")
        self.raw_response = raw_response


class BudgetDeferred(RuntimeError):
    def __init__(self, retry_at: datetime):
        super().__init__("hourly inference request budget exhausted")
        self.retry_at = retry_at
        self.elapsed_ms = 0


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _max_retries() -> int:
    return max(1, int(os.environ.get("AGENT_MAX_RETRIES", "5")))


def request_budget() -> int:
    return max(1, int(os.environ.get("AGENT_MAX_REQUESTS_PER_HOUR", "120")))


def _make_provider(settings: dict, concurrency: int) -> AsyncOpenAI:
    return AsyncOpenAI(
        api_key=settings["api_key"],
        base_url=settings["base_url"],
        timeout=settings["timeout"],
        max_retries=0,
        default_headers=settings["headers"] or None,
        http_client=httpx.AsyncClient(
            verify=settings["verify_ssl"],
            limits=httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency),
        ),
    )


async def start_analysis_provider(concurrency: int) -> bool:
    global _provider_client, _provider_settings, _provider_configuration_error, _escalation_error
    try:
        settings = request_settings()
        analysis_unit()
        false_positive_threshold()
        request_budget()
        _max_retries()
        idle_seconds = float(os.getenv("AGENT_IDLE_SECONDS", "5"))
        if not math.isfinite(idle_seconds) or idle_seconds <= 0:
            raise ValueError("AGENT_IDLE_SECONDS must be positive")
        _provider_client = _make_provider(settings, concurrency)
    except (ValueError, TypeError) as exc:
        _provider_configuration_error = "Invalid analysis configuration. Check the LLM and agent environment settings."
        logger.error("%s (%s)", _provider_configuration_error, type(exc).__name__)
        return False
    _provider_settings = settings
    _provider_configuration_error = None
    _escalation_error = None
    if not settings["verify_ssl"]:
        logger.warning("LLM TLS certificate verification is disabled")
    return True


async def stop_analysis_provider() -> None:
    global _provider_client, _provider_settings, _last_generation, _provider_paused_until, _escalation_error
    if _provider_client:
        await _provider_client.close()
    _provider_client = None
    _provider_settings = None
    _last_generation = None
    _provider_paused_until = None
    _escalation_error = None


def public_model_settings() -> dict:
    try:
        settings = {**(_provider_settings or request_settings()), "analysis_unit": analysis_unit()}
    except (ValueError, TypeError):
        return {
            "model": os.getenv("LLM_MODEL", "").strip() or "Foundation-Sec-1.1-8B-Instruct",
            "structured_output": env_bool("LLM_STRUCTURED_OUTPUT"),
            "configuration_error": "Invalid analysis configuration. Check the LLM environment settings.",
        }
    parsed = urlsplit(settings["base_url"])
    return {
        **{key: value for key, value in settings.items() if key not in {"base_url", "api_key", "headers"}},
        "provider": f"{parsed.scheme}://{parsed.netloc}",
        "configuration_error": _provider_configuration_error,
        "escalation_error": _escalation_error,
    }


def _elapsed_ms(started: datetime | None, completed: datetime) -> int | None:
    if started is None:
        return None
    started = started if started.tzinfo else started.replace(tzinfo=timezone.utc)
    completed = completed if completed.tzinfo else completed.replace(tzinfo=timezone.utc)
    return max(0, round((completed - started).total_seconds() * 1000))


# Raise when the evidence rules change in a way that makes older verdicts unsafe to approve.
# 2: a missing HTTP method is no longer recorded as GET, and rules are compared by signature.
EVIDENCE_POLICY_VERSION = 2


def _analysis_generation(ruleset: dict) -> str:
    settings = _provider_settings or request_settings()
    unit = analysis_unit()
    per_request = unit == "request"
    inputs = {
        # Switching the analysis unit changes the prompt and evidence, so older verdicts go stale.
        "analysis_unit": unit,
        "prompt": REQUEST_PROMPT_SHA256 if per_request else PROMPT_SHA256,
        "repair_prompt": hashlib.sha256((REQUEST_JSON_REPAIR_PROMPT if per_request else JSON_REPAIR_PROMPT).encode()).hexdigest(),
        "settings": {key: value for key, value in settings.items() if key != "api_key"},
        "schema": REQUEST_RESPONSE_FORMAT if per_request else RESPONSE_FORMAT,
        "threshold": false_positive_threshold(),
        "ruleset": ruleset,
        "redaction": {
            key: os.getenv(key) for key in (
                "AI_MAX_FIELD_CHARS", "AI_MAX_CONTEXT_BYTES", "AI_MAX_REQUEST_CHARS", "SENSITIVE_FIELD_PATTERN",
            )
        },
        "require_application_context": env_bool("REQUIRE_APPLICATION_CONTEXT", True),
        "evidence_policy": EVIDENCE_POLICY_VERSION,
    }
    return hashlib.sha256(json.dumps(inputs, sort_keys=True).encode()).hexdigest()


def current_analysis_generation() -> str | None:
    try:
        return _analysis_generation(index_status())
    except (ValueError, TypeError):
        return None


async def _mark_obsolete_verdicts() -> None:
    global _last_generation
    ruleset = await asyncio.to_thread(index_status)
    generation = _analysis_generation(ruleset)
    if generation == _last_generation:
        return
    async with get_session_factory()() as session:
        stale_cases = select(AnalysisCase.id).where(
            AnalysisCase.state == "complete",
            AnalysisCase.completed_generation.is_distinct_from(generation),
        )
        old_revisions = select(AnalysisRevision.id).where(AnalysisRevision.analysis_case_id.in_(stale_cases))
        await session.execute(update(ExceptionDraft).where(
            ExceptionDraft.analysis_revision_id.in_(old_revisions),
            ExceptionDraft.status.in_(["pending", "approved"]),
        ).values(status="stale"))
        await session.execute(update(AnalysisCase).where(AnalysisCase.id.in_(stale_cases)).values(
            state="stale",
            last_error="Model, evidence policy, or WAF ruleset has changed. Reanalyze for a current verdict.",
            updated_at=_utcnow(),
        ))
        await session.commit()
    _last_generation = generation


async def _recover_expired_leases() -> None:
    now = _utcnow()
    async with get_session_factory()() as session:
        expired = select(AnalysisCase.id).where(
            AnalysisCase.state == "analyzing",
            or_(AnalysisCase.lease_expires_at.is_(None), AnalysisCase.lease_expires_at <= now),
        )
        if (await session.execute(expired.limit(1))).first() is None:
            return
        await session.execute(text(
            "UPDATE inference_attempts SET status='error', error_code='lease_expired', completed_at=:now, "
            "latency_ms=CAST(MAX(0,(julianday(:now)-julianday(started_at))*86400000) AS INTEGER) "
            "WHERE status='active' AND analysis_revision_id IN "
            "(SELECT r.id FROM analysis_revisions r JOIN analysis_cases c ON c.id=r.analysis_case_id "
            "WHERE r.state='analyzing' AND c.state='analyzing' "
            "AND (c.lease_expires_at IS NULL OR c.lease_expires_at<=:now))"
        ), {"now": now})
        await session.execute(update(AnalysisRevision).where(
            AnalysisRevision.state == "analyzing", AnalysisRevision.analysis_case_id.in_(expired),
        ).values(
            state="failed", error_code="lease_expired", validation_error="Analysis lease expired", completed_at=now,
        ))
        await session.execute(update(AnalysisCase).where(AnalysisCase.id.in_(expired)).values(
            state="retryable_error", lease_token=None, lease_expires_at=None,
            next_retry_at=now, last_error="Analysis lease expired", updated_at=now,
        ))
        await session.commit()


async def next_budget_at() -> datetime | None:
    """When the rolling request window will next have capacity."""
    now = _utcnow()
    limit = request_budget()
    cutoff = now - timedelta(hours=1)
    async with get_session_factory()() as session:
        used = (await session.execute(
            select(func.count()).select_from(InferenceAttempt).where(InferenceAttempt.started_at >= cutoff)
        )).scalar_one()
        if used < limit:
            return None
        next_start = (await session.execute(
            select(InferenceAttempt.started_at).where(InferenceAttempt.started_at >= cutoff)
            .order_by(InferenceAttempt.started_at).offset(used - limit).limit(1)
        )).scalar_one_or_none()
    return (next_start or now).replace(tzinfo=timezone.utc) + timedelta(hours=1, seconds=1)


# Request mode: the claimed case's queued siblings from the same audited transaction join its lease.
# Siblings must be ready by the same condition as the primary (no pending retry backoff).
_CLAIM_REQUEST_SIBLINGS = (
    "UPDATE analysis_cases SET state='analyzing', lease_expires_at=:lease, lease_token=:token, "
    "updated_at=:now, next_retry_at=NULL WHERE state IN ('queued','retryable_error') "
    "AND (next_retry_at IS NULL OR next_retry_at<=:now) AND id IN ("
    "SELECT o.analysis_case_id FROM incident_occurrences o WHERE o.audit_event_id=("
    "SELECT p.audit_event_id FROM incident_occurrences p WHERE p.analysis_case_id=:case_id "
    "ORDER BY p.observed_at DESC, p.id DESC LIMIT 1))"
)


async def _claim_case(lease_token: str | None = None) -> int | None:
    """Claim the case that has been ready the longest.

    With ANALYSIS_UNIT=request the same transaction also claims every ready queued or retryable
    case with an occurrence in that case's latest audit event, under the same lease token,
    so one worker analyses the whole request and no case is analysed twice. A sibling still
    waiting for its retry time is left for a later claim.
    """
    if lease_token is None:
        await _recover_expired_leases()
        lease_token = uuid4().hex
    now = _utcnow()
    timeout = (_provider_settings or {}).get("timeout", 180)
    lease = now + timedelta(seconds=max(600, 2 * timeout + 60))
    ready = (
        "state IN ('queued','retryable_error') AND (next_retry_at IS NULL OR next_retry_at<=:now)"
    )
    async with get_session_factory()() as session:
        if (await session.execute(text(f"SELECT 1 FROM analysis_cases WHERE {ready} LIMIT 1"), {"now": now})).first() is None:
            return None
        row = (await session.execute(text(
            "UPDATE analysis_cases SET state='analyzing', lease_expires_at=:lease, lease_token=:token, "
            "updated_at=:now, next_retry_at=NULL WHERE id=("
            f"SELECT id FROM analysis_cases WHERE {ready} "
            "ORDER BY COALESCE(next_retry_at,enqueued_at,created_at), id LIMIT 1) RETURNING id"
        ), {"now": now, "lease": lease, "token": lease_token})).first()
        if row and analysis_unit() == "request":
            # Same write transaction, so no other worker can claim a sibling in between.
            await session.execute(text(_CLAIM_REQUEST_SIBLINGS), {
                "now": now, "lease": lease, "token": lease_token, "case_id": int(row[0]),
            })
        await session.commit()
        return int(row[0]) if row else None


async def _fence_case(session, case_id: int) -> None:
    token = _claim_token.get()
    filters = [AnalysisCase.id == case_id, AnalysisCase.state == "analyzing"]
    if token is not None:
        filters.extend([AnalysisCase.lease_token == token, AnalysisCase.lease_expires_at > _utcnow()])
    changed = await session.execute(update(AnalysisCase).where(*filters).values(lease_token=AnalysisCase.lease_token))
    if changed.rowcount != 1:
        raise ClaimLost()


async def _load_case_evidence(session, case_id: int, audit_event_id: int | None = None):
    """The case's latest occurrence, or its occurrence in one audit event (request mode)."""
    case = await session.get(AnalysisCase, case_id)
    filters = [IncidentOccurrence.analysis_case_id == case_id]
    if audit_event_id is not None:
        filters.append(IncidentOccurrence.audit_event_id == audit_event_id)
    row = (
        await session.execute(
            select(IncidentOccurrence, AuditEvent)
            .join(AuditEvent, AuditEvent.id == IncidentOccurrence.audit_event_id)
            .where(*filters)
            .order_by(IncidentOccurrence.observed_at.desc(), IncidentOccurrence.id.desc())
            .limit(1)
        )
    ).first()
    if case is None or row is None:
        raise RuntimeError("analysis case has no occurrence evidence")
    occurrence, audit_event = row
    event = audit_event.raw_event
    if event.get("evidence_expired"):
        raise TerminalAnalysisError("Audit evidence expired. Capture a new occurrence.", error_code="evidence_expired")
    matches = event.get("matches") or []
    if occurrence.match_index >= len(matches):
        raise RuntimeError("stored match index is outside the archived event")
    return case, occurrence, audit_event, event, matches[occurrence.match_index]


def _retry_after(exc: Exception) -> float | None:
    response = getattr(exc, "response", None)
    headers = getattr(response, "headers", {}) or {}
    raw = headers.get("retry-after") or headers.get("Retry-After")
    if not raw:
        return None
    try:
        seconds = float(raw)
        return min(86400.0, max(0.0, seconds)) if math.isfinite(seconds) else None
    except ValueError:
        try:
            return min(86400.0, max(0.0, (parsedate_to_datetime(raw) - _utcnow()).total_seconds()))
        except (TypeError, ValueError):
            return None


async def _reserve_attempt(revision_id: int, attempt_type: str) -> int:
    now = _utcnow()
    cutoff = now - timedelta(hours=1)
    token = _claim_token.get()
    async with get_session_factory()() as session:
        if token is not None:
            case_id = (await session.execute(
                select(AnalysisRevision.analysis_case_id).where(AnalysisRevision.id == revision_id)
            )).scalar_one()
            await _fence_case(session, case_id)
        row = (await session.execute(text(
            "INSERT INTO inference_attempts (analysis_revision_id, attempt_type, started_at, status) "
            "SELECT :revision_id, :attempt_type, :now, 'active' "
            "WHERE (SELECT COUNT(*) FROM inference_attempts WHERE started_at>=:cutoff) < :budget "
            "RETURNING id"
        ), {"revision_id": revision_id, "attempt_type": attempt_type,
            "now": now.replace(tzinfo=None), "cutoff": cutoff.replace(tzinfo=None), "budget": request_budget()}
        )).first()
        if row:
            await session.commit()
            return int(row[0])
    raise BudgetDeferred(await next_budget_at() or now + timedelta(seconds=1))


def _retained_response(raw: str | None) -> str | None:
    return raw[:4096] if raw else None


async def _finish_attempt(
    attempt_id: int, *, status: str, raw: str = "", finish_reason: str | None = None,
    error_code: str | None = None, usage=None, provider_ms: int | None = None,
) -> None:
    async with get_session_factory()() as session:
        attempt = await session.get(InferenceAttempt, attempt_id)
        if attempt is None or attempt.status != "active":
            return
        completed = _utcnow()
        await session.execute(update(InferenceAttempt).where(
            InferenceAttempt.id == attempt_id, InferenceAttempt.status == "active",
        ).values(
            completed_at=completed, latency_ms=_elapsed_ms(attempt.started_at, completed),
            status=status, error_code=error_code, finish_reason=finish_reason,
            raw_response=_retained_response(raw), provider_ms=provider_ms,
            prompt_tokens=getattr(usage, "prompt_tokens", None),
            completion_tokens=getattr(usage, "completion_tokens", None),
            total_tokens=getattr(usage, "total_tokens", None),
            reasoning_tokens=getattr(getattr(usage, "completion_tokens_details", None), "reasoning_tokens", None),
        ))
        await session.commit()


def _provider_failure(exc: Exception, structured: bool) -> TerminalAnalysisError | RetryableAnalysisError:
    status = getattr(exc, "status_code", None)
    if status == 429:
        return RetryableAnalysisError("provider rate limit reached", error_code="rate_limited", retry_after=_retry_after(exc))
    if isinstance(exc, (TimeoutError, httpx.TimeoutException)) or type(exc).__name__ == "APITimeoutError":
        return RetryableAnalysisError("provider timed out", error_code="provider_timeout")
    if status in (401, 403):
        return TerminalAnalysisError("provider rejected the configured credentials", error_code="provider_authentication")
    if status == 404:
        return TerminalAnalysisError("provider endpoint or model was unavailable", error_code="provider_not_found")
    if isinstance(status, int) and 400 <= status < 500 and status not in (408, 409, 425):
        if structured and any(field in str(exc).lower() for field in ("response_format", "json_schema", "structured output")):
            return TerminalAnalysisError("provider rejected structured output", error_code="structured_output_rejected")
        return TerminalAnalysisError(f"provider rejected the analysis request (HTTP {status})", error_code="provider_request_rejected")
    return RetryableAnalysisError("provider request failed", retry_after=_retry_after(exc))


async def _provider_request(
    revision_id: int, messages: list[dict], attempt_type: str, response_format: dict | None = None,
) -> str:
    global _provider_configuration_error, _provider_paused_until, _escalation_error
    try:
        settings = _provider_settings or request_settings()
    except (ValueError, TypeError) as exc:
        raise TerminalAnalysisError("invalid analysis provider settings") from exc
    temporary_client = _provider_client is None
    client = _provider_client or _make_provider(settings, 1)
    options = request_payload(settings, messages, attempt_type, response_format)
    thinking = {key: options.pop(key) for key in ("thinking", "reasoning_effort") if key in options}
    if thinking:
        options["extra_body"] = thinking
    try:
        attempt_id = await _reserve_attempt(revision_id, attempt_type)
        started = perf_counter()
        try:
            async with asyncio.timeout(settings["timeout"]):
                response = await client.chat.completions.create(**options)
        except asyncio.CancelledError:
            await asyncio.shield(_finish_attempt(
                attempt_id, status="error", error_code="cancelled", provider_ms=round((perf_counter() - started) * 1000),
            ))
            raise
        except Exception as exc:
            error = _provider_failure(exc, settings["structured_output"])
            if attempt_type == "escalation" and is_escalation_effort_rejection(getattr(exc, "status_code", None), str(exc)):
                if _escalation_error is None:
                    logger.warning("%s", ESCALATION_EFFORT_REJECTED)
                _escalation_error = ESCALATION_EFFORT_REJECTED
                error = TerminalAnalysisError(_escalation_error, error_code="escalation_effort_rejected")
            elif error.error_code in {"provider_authentication", "provider_not_found", "structured_output_rejected"}:
                _provider_configuration_error = str(error)
            elif error.error_code == "rate_limited":
                retry_after = _utcnow() + timedelta(seconds=error.retry_after or 15)
                _provider_paused_until = max(_provider_paused_until or retry_after, retry_after)
            await _finish_attempt(
                attempt_id, status="error", error_code=error.error_code,
                provider_ms=round((perf_counter() - started) * 1000),
            )
            raise error from exc
        elapsed = round((perf_counter() - started) * 1000)
        choice = response.choices[0] if response.choices else None
        finish_reason = getattr(choice, "finish_reason", None)
        message = getattr(choice, "message", None)
        try:
            raw = completion_text({"message": {
                "content": getattr(message, "content", None),
                "refusal": getattr(message, "refusal", None),
            }, "finish_reason": finish_reason})
        except CompletionOutputError as exc:
            await _finish_attempt(
                attempt_id, status="error", raw=exc.raw_response, error_code=exc.code,
                finish_reason=finish_reason, usage=response.usage, provider_ms=elapsed,
            )
            if exc.code == "empty_output":
                raise RetryableAnalysisError(str(exc), error_code=exc.code) from exc
            raise InvalidOutputError(str(exc), exc.raw_response) from exc
        await _finish_attempt(
            attempt_id, status="complete", raw=raw, finish_reason=finish_reason,
            usage=response.usage, provider_ms=elapsed,
        )
        return raw
    finally:
        if temporary_client:
            await client.close()


async def _save_repair_input(revision_ids: list[int], repair_input: str) -> None:
    """Keep the repair input so a budget-deferred repair resumes; request mode saves it on every revision."""
    if _claim_token.get() is None:
        return
    async with get_session_factory()() as session:
        for revision_id in revision_ids:
            revision = await session.get(AnalysisRevision, revision_id)
            await _fence_case(session, revision.analysis_case_id)
            revision.pending_repair_input = repair_input
        await session.commit()


async def _call_model(
    context: dict, _scope: dict, revision_id: int, *, pending_repair_input: str | None = None,
) -> tuple[dict, str]:
    """One match: (verdict, the raw response it came from)."""
    messages = response_messages(context)
    repair_input = pending_repair_input
    if repair_input is None:
        raw = await _provider_request(revision_id, messages, "initial")
        try:
            result = classify_response(raw)
        except (ValueError, TypeError) as exc:
            repair_input = bound_repair_input(raw, context)
            if not repair_input:
                raise InvalidOutputError(f"invalid output with no safe repair input ({exc})", raw) from exc
            await _save_repair_input([revision_id], repair_input)
        else:
            settings = _provider_settings or request_settings()
            if settings["escalation_effort"] and not _escalation_error and result["classification"] == "uncertain":
                try:
                    escalated = await _provider_request(revision_id, messages, "escalation")
                    return classify_response(escalated), escalated
                except (RetryableAnalysisError, TerminalAnalysisError, BudgetDeferred, ValueError):
                    logger.info("Kept uncertain verdict after analysis escalation could not finish")
            return result, raw

    repaired = await _provider_request(revision_id, repair_messages(repair_input), "repair")
    try:
        return classify_repair_response(repaired, repair_input), repaired
    except (ValueError, TypeError) as exc:
        raise InvalidOutputError(f"invalid repair output ({exc})", repaired) from exc


async def _call_request_model(
    context: dict, match_indexes: list[int], revision_ids: list[int], *, pending_repair_input: str | None = None,
) -> tuple[dict[int, dict], dict[int, str]]:
    """One model call for a whole request, with the same repair and escalation rules as one match.

    Returns ({match_index: verdict}, {match_index: the raw response that verdict came from}).
    Attempts are recorded on revision_ids[0]. Escalation runs only when the first pass was
    valid (not repaired) and at least one verdict is uncertain; it must return a valid verdict
    for every match or the first pass is kept, and it replaces only the verdicts that were
    uncertain on the first pass, so a confident first-pass verdict never changes.
    """
    primary = revision_ids[0]
    messages = request_response_messages(context)
    repair_input = pending_repair_input
    if repair_input is None:
        raw = await _provider_request(primary, messages, "initial", REQUEST_RESPONSE_FORMAT)
        try:
            results = classify_request_response(raw, match_indexes)
        except (ValueError, TypeError) as exc:
            repair_input = bound_request_repair_input(raw, context, match_indexes)
            if not repair_input:
                raise InvalidOutputError(f"invalid output with no safe repair input ({exc})", raw) from exc
            await _save_repair_input(revision_ids, repair_input)
        else:
            settings = _provider_settings or request_settings()
            if settings["escalation_effort"] and not _escalation_error and any(
                result["classification"] == "uncertain" for result in results.values()
            ):
                try:
                    escalated = await _provider_request(primary, messages, "escalation", REQUEST_RESPONSE_FORMAT)
                    second = classify_request_response(escalated, match_indexes)
                except (RetryableAnalysisError, TerminalAnalysisError, BudgetDeferred, ValueError):
                    logger.info("Kept uncertain verdicts after request escalation could not finish")
                else:
                    uncertain = {index for index, result in results.items() if result["classification"] == "uncertain"}
                    return (
                        {index: second[index] if index in uncertain else result for index, result in results.items()},
                        {index: escalated if index in uncertain else raw for index in results},
                    )
            return results, {index: raw for index in results}

    repaired = await _provider_request(primary, request_repair_messages(repair_input), "repair", REQUEST_RESPONSE_FORMAT)
    try:
        results = classify_request_repair_response(repaired, repair_input)
        return results, {index: repaired for index in results}
    except (ValueError, TypeError, KeyError) as exc:
        raise InvalidOutputError(f"invalid repair output ({exc})", repaired) from exc


async def _apply_draft_policy(result: dict, scope: dict, route_context_present: bool):
    """Apply server-owned context and builder policy. The server builds the only rule shape."""
    if result["classification"] != "false_positive":
        return None, "not_applicable", None
    if env_bool("REQUIRE_APPLICATION_CONTEXT", True) and not route_context_present:
        return (
            None,
            "missing_application_context",
            "Create a matching application route profile, then explicitly reanalyze.",
        )
    buildable, error = can_build_exception(scope)
    if not buildable:
        return None, "cannot_build", error
    return build_exception_rule(scope, phase=1), "valid", None


def refresh_active_false_positive_draft(
    existing: ExceptionDraft,
    *,
    case: AnalysisCase,
    revision: AnalysisRevision,
    result: dict,
    scope: dict,
    match_index: int,
    sibling_rule_ids: list[str],
    normalized_rule: str | None,
    validation_status: str,
    validation_error: str | None,
    numeric_id: int | None,
    crs_raw: str | None,
    transaction_id: str,
    event_line: int,
) -> None:
    """Merge a new FP analysis into the active draft for this scope.

    Approved drafts are never rewritten (count + last_seen only). Pending drafts
    upgrade when a later analysis produces a valid copyable rule (e.g. after a
    route profile is added and the case is reanalyzed), and are not downgraded
    from a valid rule to missing context.
    """
    existing.last_seen_at = case.last_seen_at
    existing.supporting_case_count = (existing.supporting_case_count or 1) + 1

    if existing.status != "pending":
        return

    if validation_status == "scope_conflict":
        existing.proposed_rule = None
        existing.rule_placement = None
        existing.rule_numeric_id = None
        existing.validation_status = "scope_conflict"
        existing.validation_error = validation_error
        existing.status = "stale"
        existing.analysis_revision_id = revision.id
        return

    existing.classification = result["classification"]
    existing.confidence = result["confidence"]
    existing.verdict = result["verdict"]
    existing.transaction_id = transaction_id
    existing.event_line = event_line
    existing.analysis_revision_id = revision.id
    existing.crs_rule_raw = crs_raw or existing.crs_rule_raw
    existing.proposed_rule_scope = {
        **scope,
        "match_index": match_index,
        "sibling_rule_ids": sibling_rule_ids,
    }

    has_copyable = existing.validation_status == "valid" and bool(existing.proposed_rule)
    new_copyable = validation_status == "valid" and bool(normalized_rule)

    if new_copyable:
        existing.proposed_rule = normalized_rule
        existing.validation_status = "valid"
        existing.validation_error = None
        existing.rule_placement = "before_crs"
        existing.rule_numeric_id = numeric_id
    elif not has_copyable:
        existing.proposed_rule = normalized_rule
        existing.validation_status = validation_status
        existing.validation_error = validation_error
        existing.rule_placement = "before_crs" if normalized_rule else None
        existing.rule_numeric_id = numeric_id


async def _open_revision(session, case, *, evidence_digest: str, stage_metrics: dict, claimed_at, **fields):
    """Resume this case's revision that holds a pending repair for the same evidence, else start one."""
    revision = (await session.execute(
        select(AnalysisRevision).where(
            AnalysisRevision.analysis_case_id == case.id,
            AnalysisRevision.started_at >= (case.enqueued_at or case.created_at),
            AnalysisRevision.evidence_digest == evidence_digest,
            AnalysisRevision.state.in_(["budget_deferred", "retryable_error", "failed"]),
            AnalysisRevision.pending_repair_input.is_not(None),
        ).order_by(AnalysisRevision.id.desc()).limit(1)
    )).scalars().first()
    if revision is None:
        revision = AnalysisRevision(
            analysis_case_id=case.id, state="analyzing", stage_metrics=stage_metrics,
            evidence_digest=evidence_digest, **fields,
        )
        session.add(revision)
    else:
        stage_metrics = dict(revision.stage_metrics or stage_metrics)
        if revision.state == "budget_deferred":
            stage_metrics["budget_wait_ms"] = stage_metrics.get("budget_wait_ms", 0) + (
                _elapsed_ms(revision.completed_at, claimed_at) or 0
            )
        revision.state = "analyzing"
        revision.error_code = None
        revision.validation_error = None
        revision.completed_at = None
        revision.stage_metrics = stage_metrics
    await session.flush()
    return revision, stage_metrics


def _stage_metrics(case, audit_event, claimed_at, context_started) -> dict:
    return {
        "audit_to_ingest_ms": _elapsed_ms(audit_event.timestamp, audit_event.created_at),
        "queue_wait_ms": _elapsed_ms(case.enqueued_at or case.created_at, claimed_at),
        "context_ms": round((perf_counter() - context_started) * 1000),
    }


async def _analyze_claimed_case(case_id: int) -> None:
    factory = get_session_factory()
    claimed_at = _utcnow()
    context_started = perf_counter()
    async with factory() as session:
        case, occurrence, audit_event, event, match = await _load_case_evidence(session, case_id)
        profile, application_context = await select_application_context(session, event)
        # Analyse against the rule that fired, from the ruleset active when the alert was ingested.
        crs_rule = get_rule_at(case.rule_id, event.get('crs_ruleset_digest'))
        scope = case_exception_scope(case)
        context = build_inference_context(
            event, match, match_index=occurrence.match_index, crs_rule=crs_rule,
            application_context=application_context, collection=case.collection, parameter=case.parameter,
        )
        profile_id = profile.id if profile else None
        profile_version = profile.version if profile else None
        # The rule's signature covers its text and the data files it reads.
        crs_digest = crs_rule.signature if crs_rule else None
        ruleset = index_status()
        generation = _analysis_generation(ruleset)
        settings = {**public_model_settings(), "ruleset_digest": ruleset.get("digest")}
        decision = {
            "generation": generation,
            "profile": [profile_id, profile_version],
            "crs_digest": crs_digest,
            "context": serialize_inference_context(context),
        }
        evidence_digest = hashlib.sha256(json.dumps(decision, sort_keys=True).encode()).hexdigest()
        stage_metrics = _stage_metrics(case, audit_event, claimed_at, context_started)
        await _fence_case(session, case_id)
        revision, stage_metrics = await _open_revision(
            session, case, evidence_digest=evidence_digest, stage_metrics=stage_metrics, claimed_at=claimed_at,
            application_profile_id=profile_id, profile_version=profile_version, crs_digest=crs_digest,
            model=settings["model"], prompt_version=PROMPT_VERSION, prompt_sha256=PROMPT_SHA256,
            model_settings=settings, context=context,
        )
        revision_id = revision.id
        pending_repair_input = revision.pending_repair_input
        await session.commit()

    model_started = perf_counter()
    try:
        result, _raw = await _call_model(context, scope, revision_id, pending_repair_input=pending_repair_input)
    except BudgetDeferred as exc:
        exc.elapsed_ms = round((perf_counter() - model_started) * 1000)
        raise
    model_ms = round((perf_counter() - model_started) * 1000)
    stage_metrics["model_and_validation_ms"] = stage_metrics.get("model_and_validation_ms", 0) + model_ms
    await _finalize_case(
        case_id, revision_id, result, context=context, crs_rule=crs_rule, scope=scope,
        application_context=application_context, event=event, profile_id=profile_id,
        profile_version=profile_version, generation=generation, stage_metrics=stage_metrics,
        transaction_id=audit_event.transaction_id, event_line=audit_event.event_line,
        match_index=occurrence.match_index, audit_observed_at=audit_event.timestamp,
    )


async def _claimed_group(case_id: int) -> list[int]:
    """The claimed case first, then the request siblings that share its lease token."""
    token = _claim_token.get()
    if token is None:
        return [case_id]
    async with get_session_factory()() as session:
        ids = (await session.execute(
            select(AnalysisCase.id).where(AnalysisCase.lease_token == token, AnalysisCase.state == "analyzing")
            .order_by(AnalysisCase.id)
        )).scalars().all()
    return [case_id, *(other for other in ids if other != case_id)]


async def _analyze_claimed_request(case_ids: list[int]) -> None:
    """ANALYSIS_UNIT=request: one model call for the claimed cases of one audited request.

    Every case gets its own revision and is finalized through the same per-case gates as
    match mode. The provider attempts are recorded on the first case's revision; each
    revision stores the raw response its verdict came from.
    """
    factory = get_session_factory()
    claimed_at = _utcnow()
    context_started = perf_counter()
    async with factory() as session:
        loaded = [await _load_case_evidence(session, case_ids[0])]
        audit_event, event = loaded[0][2], loaded[0][3]
        for other in case_ids[1:]:
            loaded.append(await _load_case_evidence(session, other, audit_event.id))
        profile, application_context = await select_application_context(session, event)
        crs_rules = {
            occurrence.match_index: get_rule_at(case.rule_id, event.get('crs_ruleset_digest'))
            for case, occurrence, *_ in loaded
        }
        match_indexes = sorted(crs_rules)
        context = build_request_context(event, match_indexes, crs_rules, application_context)
        profile_id = profile.id if profile else None
        profile_version = profile.version if profile else None
        ruleset = index_status()
        generation = _analysis_generation(ruleset)
        settings = {**public_model_settings(), "ruleset_digest": ruleset.get("digest")}
        decision = {
            "generation": generation,
            "profile": [profile_id, profile_version],
            "crs_digest": {str(index): rule.signature if rule else None for index, rule in crs_rules.items()},
            "context": serialize_inference_context(context),
        }
        evidence_digest = hashlib.sha256(json.dumps(decision, sort_keys=True).encode()).hexdigest()
        opened = []
        for case, occurrence, *_ in loaded:
            crs_rule = crs_rules[occurrence.match_index]
            await _fence_case(session, case.id)
            revision, stage_metrics = await _open_revision(
                session, case, evidence_digest=evidence_digest, claimed_at=claimed_at,
                stage_metrics=_stage_metrics(case, audit_event, claimed_at, context_started),
                application_profile_id=profile_id, profile_version=profile_version,
                crs_digest=crs_rule.signature if crs_rule else None, model=settings["model"],
                prompt_version=REQUEST_PROMPT_VERSION, prompt_sha256=REQUEST_PROMPT_SHA256,
                model_settings=settings, context=context,
            )
            opened.append((revision, stage_metrics))
        revision_ids = [revision.id for revision, _ in opened]
        pending_repair_input = next((revision.pending_repair_input for revision, _ in opened if revision.pending_repair_input), None)
        await session.commit()

    model_started = perf_counter()
    try:
        results, raws = await _call_request_model(
            context, match_indexes, revision_ids, pending_repair_input=pending_repair_input,
        )
    except BudgetDeferred as exc:
        exc.elapsed_ms = round((perf_counter() - model_started) * 1000)
        raise
    except InvalidOutputError as exc:
        # One bad answer for several matches is worth another try; a one-match request fails like match mode.
        if len(case_ids) > 1:
            raise RetryableInvalidOutput(str(exc), exc.raw_response) from exc
        raise
    model_ms = round((perf_counter() - model_started) * 1000)
    for (case, occurrence, *_), (revision, stage_metrics) in zip(loaded, opened):
        stage_metrics["model_and_validation_ms"] = stage_metrics.get("model_and_validation_ms", 0) + model_ms
        try:
            await _finalize_case(
                case.id, revision.id, results[occurrence.match_index],
                context=request_match_view(context, occurrence.match_index),
                crs_rule=crs_rules[occurrence.match_index], scope=case_exception_scope(case),
                application_context=application_context, event=event, profile_id=profile_id,
                profile_version=profile_version, generation=generation, stage_metrics=stage_metrics,
                transaction_id=audit_event.transaction_id, event_line=audit_event.event_line,
                match_index=occurrence.match_index, audit_observed_at=audit_event.timestamp,
                raw_response=raws[occurrence.match_index], attempts_revision_id=revision_ids[0],
            )
        except ClaimLost:
            logger.info("Analysis claim for case %s expired", case.id)


async def _finalize_case(
    case_id: int, revision_id: int, result: dict, *, context: dict, crs_rule, scope: dict,
    application_context: dict, event: dict, profile_id, profile_version, generation: str, stage_metrics: dict,
    transaction_id: str, event_line: int, match_index: int, audit_observed_at,
    raw_response: str | None = None, attempts_revision_id: int | None = None,
) -> None:
    """Apply every server-owned gate to one match's verdict and publish it, in either analysis unit.

    `context` is the per-match evidence shape (build_inference_context, or inference_context.request_match_view).
    `raw_response`/`attempts_revision_id` are set in request mode, where the attempts live on
    one revision of the group.
    """
    factory = get_session_factory()
    crs_raw = crs_rule.raw if crs_rule else ""
    publish_started = perf_counter()
    route_context_present = bool(scope.get("host")) and route_supports_exception(
        application_context, scope.get("collection"), scope.get("parameter"),
    )
    normalized_rule, validation_status, validation_error = await _apply_draft_policy(result, scope, route_context_present)
    if result["classification"] == "false_positive":
        if not crs_rule or not context.get("crs_rule"):
            normalized_rule, validation_status, validation_error = (
                None, "missing_crs_rule", "Load the ruleset ModSecurity used for this alert and reanalyze.",
            )
        elif validation_status == "valid" and event.get("crs_ruleset_uncertain"):
            normalized_rule, validation_status, validation_error = (
                None, "ruleset_uncertain",
                "A new CRS ruleset went live around when this alert fired. Review a new alert under the current ruleset.",
            )
        elif validation_status == "valid" and getattr(get_rule(scope["rule_id"]), "signature", None) != crs_rule.signature:
            # The exclusion would be deployed against today's rule. If it is gone or detects differently, withhold it.
            normalized_rule, validation_status, validation_error = (
                None, "rule_changed_since_alert",
                "This rule changed after the alert fired. Review a new alert under the current ruleset.",
            )
        elif validation_status == "valid" and crs_rule.chain:
            normalized_rule, validation_status, validation_error = (
                None, "chained_rule_review",
                "ModSecurity target exclusions apply to the first rule in a chain. Review the matched clause manually.",
            )
        if validation_status == "valid" and not (scope.get("host") and scope.get("method")):
            normalized_rule, validation_status, validation_error = (
                None, "missing_request_scope", "The captured host and HTTP method are required for a scoped exception.",
            )
        if validation_status == "valid" and match_evidence_withheld(context):
            normalized_rule, validation_status, validation_error = (
                None, "missing_match_evidence", "The matched value was unavailable or redacted.",
            )

    async with factory() as session:
        await _fence_case(session, case_id)
        revision = await session.get(AnalysisRevision, revision_id)
        case = await session.get(AnalysisCase, case_id)
        # The pinned rule cannot change; a ruleset published mid-analysis changes the generation.
        ruleset_changed = _analysis_generation(index_status()) != generation
        if ruleset_changed or not await profile_is_current(session, event, profile_id, profile_version):
            revision.state = "stale"
            revision.validation_status = "stale_context"
            revision.validation_error = "Application profile or WAF ruleset changed during analysis."
            revision.completed_at = _utcnow()
            revision.pending_repair_input = None
            case.state = "stale"
            case.last_error = revision.validation_error
            case.lease_expires_at = None
            case.lease_token = None
            case.updated_at = revision.completed_at
            await session.commit()
            return
        if validation_status == "valid" and await has_true_positive(session, case):
            normalized_rule = None
            validation_status = "scope_conflict"
            validation_error = SCOPE_CONFLICT_ERROR
        scope_key = canonical_scope_key(scope)
        numeric_id = rule_numeric_id(normalized_rule)
        if numeric_id is not None:
            collision = (
                await session.execute(
                    select(ExceptionDraft.id).where(
                        ExceptionDraft.rule_numeric_id == numeric_id,
                        ExceptionDraft.classification == "false_positive",
                        ExceptionDraft.scope_key != scope_key,
                        ExceptionDraft.status.in_(["pending", "approved"]),
                    ).limit(1)
                )
            ).scalar_one_or_none()
            if collision is not None:
                normalized_rule = None
                validation_status = "id_conflict"
                validation_error = f"Server-owned rule ID collides with active draft {collision}."
                numeric_id = None

        revision.state = "complete"
        # Recorded only; no gate reads applies_to_stack. Kept in a JSON column so no migration is needed.
        revision.model_settings = {
            **(revision.model_settings or {}), "applies_to_stack": result.get("applies_to_stack", "unknown"),
            **({"attempts_revision_id": attempts_revision_id} if attempts_revision_id is not None else {}),
        }
        if raw_response is not None:
            revision.raw_response = _retained_response(raw_response)
        revision.classification = result["classification"]
        revision.confidence = result["confidence"]
        revision.verdict = result["verdict"]
        revision.context_factors = result["context_factors"]
        revision.uncertainty_factors = result["uncertainty_factors"]
        revision.pending_repair_input = None
        revision.proposed_rule_scope = scope
        revision.normalized_rule = normalized_rule
        revision.validation_status = validation_status
        revision.validation_error = validation_error
        revision.completed_at = _utcnow()
        case.state = "complete"
        case.completed_generation = generation
        case.lease_expires_at = None
        case.lease_token = None
        case.last_error = None
        case.updated_at = _utcnow()
        if result["classification"] == "true_positive":
            await invalidate_false_positive_drafts(session, case)

        sibling_rule_ids = [
            str(m.get("rule_id"))
            for m in (event.get("matches") or [])
            if str(m.get("rule_id") or "") != case.rule_id
        ]
        scope_payload = {
            **scope,
            "match_index": match_index,
            "sibling_rule_ids": sibling_rule_ids,
        }

        if result["classification"] == "false_positive" and validation_status == "valid":
            existing = (
                await session.execute(
                    select(ExceptionDraft).where(
                        ExceptionDraft.scope_key == scope_key,
                        ExceptionDraft.classification == "false_positive",
                        ExceptionDraft.status.in_(["pending", "approved"]),
                    ).limit(1)
                )
            ).scalars().first()
            if existing:
                refresh_active_false_positive_draft(
                    existing,
                    case=case,
                    revision=revision,
                    result=result,
                    scope=scope,
                    match_index=match_index,
                    sibling_rule_ids=sibling_rule_ids,
                    normalized_rule=normalized_rule,
                    validation_status=validation_status,
                    validation_error=validation_error,
                    numeric_id=numeric_id,
                    crs_raw=crs_raw or None,
                    transaction_id=transaction_id,
                    event_line=event_line,
                )
            else:
                session.add(ExceptionDraft(
                    transaction_id=transaction_id,
                    event_line=event_line,
                    classification="false_positive",
                    confidence=result["confidence"],
                    verdict=result["verdict"],
                    crs_rule_raw=crs_raw or None,
                    proposed_rule=normalized_rule,
                    proposed_rule_scope=scope_payload,
                    status="pending",
                    analysis_revision_id=revision.id,
                    validation_status="valid",
                    rule_placement="before_crs",
                    last_seen_at=case.last_seen_at,
                    scope_key=scope_key,
                    rule_numeric_id=numeric_id,
                    supporting_case_count=1,
                ))
        revision.stage_metrics = {
            **stage_metrics,
            "publish_ms": round((perf_counter() - publish_started) * 1000),
            "audit_to_verdict_ms": _elapsed_ms(audit_observed_at, _utcnow()),
        }
        await session.commit()


async def _active_revision(session, case_id: int) -> AnalysisRevision | None:
    return (await session.execute(select(AnalysisRevision).where(
        AnalysisRevision.analysis_case_id == case_id,
        AnalysisRevision.state == "analyzing",
    ).order_by(AnalysisRevision.id.desc()).limit(1))).scalars().first()


async def _record_budget_deferral(case_id: int, retry_at: datetime, elapsed_ms: int = 0) -> None:
    async with get_session_factory()() as session:
        try:
            await _fence_case(session, case_id)
        except ClaimLost:
            return
        case = await session.get(AnalysisCase, case_id)
        case.state = "queued"
        case.next_retry_at = retry_at
        case.lease_expires_at = None
        case.lease_token = None
        case.last_error = "Inference paused by hourly request budget"
        case.updated_at = _utcnow()
        revision = await _active_revision(session, case_id)
        if revision:
            revision.state = "budget_deferred"
            revision.error_code = "budget_exhausted"
            revision.validation_error = case.last_error
            revision.completed_at = case.updated_at
            stage_metrics = dict(revision.stage_metrics or {})
            stage_metrics["model_and_validation_ms"] = stage_metrics.get("model_and_validation_ms", 0) + elapsed_ms
            revision.stage_metrics = stage_metrics
        await session.commit()


async def _record_retry(case_id: int, error: Exception, *, terminal: bool = False) -> None:
    async with get_session_factory()() as session:
        try:
            await _fence_case(session, case_id)
        except ClaimLost:
            return
        case = await session.get(AnalysisCase, case_id)
        case.retry_count += 1
        case.lease_expires_at = None
        case.lease_token = None
        case.last_error = str(error)[:4000]
        case.updated_at = _utcnow()
        if terminal or case.retry_count >= _max_retries():
            case.state = "failed"
            case.next_retry_at = None
        else:
            base = min(1800.0, 15.0 * (2 ** min(case.retry_count - 1, 7)))
            jittered = base * random.uniform(0.8, 1.2)
            retry_after = getattr(error, "retry_after", None) or 0
            case.state = "retryable_error"
            case.next_retry_at = case.updated_at + timedelta(seconds=max(jittered, retry_after))
        revision = await _active_revision(session, case_id)
        if revision:
            revision.state = "failed" if case.state == "failed" else "retryable_error"
            revision.error_code = getattr(error, "error_code", "provider_error")
            revision.validation_error = case.last_error
            revision.raw_response = _retained_response(getattr(error, "raw_response", None))
            revision.completed_at = case.updated_at
            if case.state == "failed" or isinstance(error, RetryableInvalidOutput):
                # A retry after invalid output starts a fresh analysis instead of repeating the repair.
                revision.pending_repair_input = None
            await session.execute(update(InferenceAttempt).where(
                InferenceAttempt.analysis_revision_id == revision.id, InferenceAttempt.status == "active",
            ).values(status="error", error_code=revision.error_code, completed_at=case.updated_at))
        await session.commit()


async def _run_claimed_case(case_id: int) -> None:
    case_ids = [case_id]
    try:
        if analysis_unit() == "request":
            case_ids = await _claimed_group(case_id)
            await _analyze_claimed_request(case_ids)
        else:
            await _analyze_claimed_case(case_id)
    except ClaimLost:
        logger.info("Analysis claim for case %s expired", case_id)
    except asyncio.CancelledError:
        for claimed in case_ids:
            await asyncio.shield(_record_retry(
                claimed, RetryableAnalysisError("analysis worker stopped", error_code="cancelled"),
            ))
        raise
    except BudgetDeferred as exc:
        for claimed in case_ids:
            await _record_budget_deferral(claimed, exc.retry_at, exc.elapsed_ms)
    except TerminalAnalysisError as exc:
        logger.warning("Analysis case %s failed (%s)", case_id, exc.error_code)
        for claimed in case_ids:
            await _record_retry(claimed, exc, terminal=True)
    except RetryableAnalysisError as exc:
        logger.warning("Analysis case %s deferred (%s)", case_id, exc.error_code)
        for claimed in case_ids:
            await _record_retry(claimed, exc)
    except Exception:
        logger.exception("Analysis worker could not process case %s", case_id)
        for claimed in case_ids:
            await _record_retry(claimed, RetryableAnalysisError("Analysis could not be processed.", error_code="worker_error"))


async def analysis_lease_reaper() -> None:
    while True:
        try:
            await _recover_expired_leases()
            await _mark_obsolete_verdicts()
        except Exception:
            logger.exception("Unable to recover analysis state")
        await asyncio.sleep(30)


async def agent_worker(worker_id: int = 1):
    logger.info("Off-path analysis worker %d started (prompt=%s)", worker_id, PROMPT_VERSION)
    idle_seconds = float(os.getenv("AGENT_IDLE_SECONDS", "5"))
    while True:
        try:
            if _provider_configuration_error:
                await asyncio.sleep(idle_seconds)
                continue
            delay = await next_budget_at()
            if _provider_paused_until and _provider_paused_until > _utcnow():
                delay = max(delay or _provider_paused_until, _provider_paused_until)
            if delay is not None:
                await asyncio.sleep(min(60.0, max(0.01, (delay - _utcnow()).total_seconds())))
                continue
            analysis_queue_changed.clear()
            token = _claim_token.set(uuid4().hex)
            try:
                case_id = await _claim_case(_claim_token.get())
                if case_id is None:
                    try:
                        await asyncio.wait_for(analysis_queue_changed.wait(), timeout=idle_seconds)
                    except TimeoutError:
                        pass
                else:
                    await _run_claimed_case(case_id)
            finally:
                _claim_token.reset(token)
        except Exception:
            logger.exception("Analysis worker %d could not advance the queue", worker_id)
            await asyncio.sleep(idle_seconds)
