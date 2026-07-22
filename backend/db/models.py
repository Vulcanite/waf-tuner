"""
SQLAlchemy models and database utilities for the WAF Exception Agent.

Raw events live in events.jsonl; durable ingestion and analysis workflow state
lives in a local SQLite database (lightweight default for lab / bare metal).
"""
from __future__ import annotations

import os
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    JSON,
    Text,
    TIMESTAMP,
    UniqueConstraint,
    event,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


def _default_sqlite_path() -> Path:
    events = os.environ.get("EVENTS_JSONL_PATH", "/shared/events.jsonl")
    return Path(events).expanduser().resolve().parent / "waf-tuner.db"


def get_database_url() -> str:
    """Return the async SQLAlchemy URL (SQLite by default)."""
    explicit = (
        os.environ.get("DATABASE_URL")
        or os.environ.get("SQLITE_URL")
        or ""
    ).strip()
    if explicit:
        # Allow either sqlite+aiosqlite:///... or a bare filesystem path.
        if explicit.startswith("sqlite"):
            return explicit
        if "://" in explicit:
            return explicit
        path = Path(explicit).expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        return f"sqlite+aiosqlite:///{path}"

    path = Path(
        os.environ.get("DATABASE_PATH")
        or os.environ.get("SQLITE_PATH")
        or _default_sqlite_path()
    ).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{path}"


def is_sqlite() -> bool:
    return get_database_url().startswith("sqlite")


class Base(DeclarativeBase):
    pass


def _utcnow():
    return datetime.now(timezone.utc)


class ApplicationProfile(Base):
    """Versioned, operator-controlled application context used for analysis."""

    __tablename__ = "application_profiles"

    id = Column(Integer, primary_key=True)
    name = Column(Text, nullable=False)
    version = Column(Integer, nullable=False, default=1)
    active = Column(Boolean, nullable=False, default=True)
    host_patterns = Column(JSON, nullable=False, default=list)
    context = Column(JSON, nullable=False, default=dict)
    routes = Column(JSON, nullable=False, default=list)
    source_metadata = Column(JSON, nullable=False, default=dict)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        UniqueConstraint("name", "version", name="application_profiles_name_version_uq"),
        Index("application_profiles_active_idx", "active"),
    )


class AuditEvent(Base):
    """Durable transaction identity and link to the append-only JSONL archive."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    transaction_id = Column(Text, nullable=False, unique=True)
    event_line = Column(Integer, nullable=False)
    timestamp = Column(TIMESTAMP(timezone=True), nullable=True)
    raw_event = Column(JSON, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)


class AnalysisCase(Base):
    """A unique signature/payload combination; repeated traffic updates this row."""

    __tablename__ = "analysis_cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(Text, nullable=False, unique=True)
    method = Column(Text, nullable=False)
    path = Column(Text, nullable=False)
    rule_id = Column(Text, nullable=False)
    collection = Column(Text, nullable=True)
    parameter = Column(Text, nullable=True)
    matched_data = Column(Text, nullable=False, default="")
    occurrence_count = Column(Integer, nullable=False, default=1)
    first_seen_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)
    last_seen_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)
    latest_event_line = Column(Integer, nullable=False)
    state = Column(Text, nullable=False, default="queued")
    retry_count = Column(Integer, nullable=False, default=0)
    next_retry_at = Column(TIMESTAMP(timezone=True), nullable=True)
    lease_expires_at = Column(TIMESTAMP(timezone=True), nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("analysis_cases_state_retry_idx", "state", "next_retry_at"),
        Index("analysis_cases_rule_id_idx", "rule_id"),
    )


class IncidentOccurrence(Base):
    """One ModSecurity message within one audited transaction."""

    __tablename__ = "incident_occurrences"

    id = Column(Integer, primary_key=True, autoincrement=True)
    audit_event_id = Column(
        Integer, ForeignKey("audit_events.id", ondelete="CASCADE"), nullable=False
    )
    analysis_case_id = Column(
        Integer, ForeignKey("analysis_cases.id", ondelete="CASCADE"), nullable=False
    )
    transaction_id = Column(Text, nullable=False)
    event_line = Column(Integer, nullable=False)
    match_index = Column(Integer, nullable=False)
    rule_id = Column(Text, nullable=False)
    fingerprint = Column(Text, nullable=False)
    observed_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        UniqueConstraint(
            "transaction_id",
            "match_index",
            name="incident_occurrences_transaction_match_uq",
        ),
        Index("incident_occurrences_case_idx", "analysis_case_id"),
        Index("incident_occurrences_fingerprint_idx", "fingerprint"),
    )


class AnalysisRevision(Base):
    """Reproducible model result for a case and a specific context version."""

    __tablename__ = "analysis_revisions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_case_id = Column(
        Integer, ForeignKey("analysis_cases.id", ondelete="CASCADE"), nullable=False
    )
    application_profile_id = Column(
        Integer, ForeignKey("application_profiles.id", ondelete="SET NULL"), nullable=True
    )
    profile_version = Column(Integer, nullable=True)
    crs_digest = Column(Text, nullable=True)
    model = Column(Text, nullable=False)
    prompt_version = Column(Text, nullable=False)
    prompt_sha256 = Column(Text, nullable=True)
    model_settings = Column(JSON, nullable=False, default=dict)
    error_code = Column(Text, nullable=True)
    state = Column(Text, nullable=False, default="analyzing")
    context = Column(JSON, nullable=False, default=dict)
    classification = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    verdict = Column(Text, nullable=True)
    context_factors = Column(JSON, nullable=False, default=list)
    uncertainty_factors = Column(JSON, nullable=False, default=list)
    raw_response = Column(Text, nullable=True)
    raw_proposed_rule = Column(Text, nullable=True)
    proposed_rule_scope = Column(JSON, nullable=True)
    normalized_rule = Column(Text, nullable=True)
    validation_status = Column(Text, nullable=False, default="pending")
    validation_error = Column(Text, nullable=True)
    started_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)

    __table_args__ = (
        Index("analysis_revisions_case_idx", "analysis_case_id"),
        Index("analysis_revisions_state_idx", "state"),
    )


class ExceptionDraft(Base):
    __tablename__ = "exception_drafts"

    id = Column(Integer, primary_key=True)
    transaction_id = Column(Text, nullable=False)
    event_line = Column(Integer, nullable=False)
    classification = Column(Text, nullable=False)
    confidence = Column(Float, nullable=False)
    verdict = Column(Text, nullable=False)
    crs_rule_raw = Column(Text, nullable=True)
    proposed_rule = Column(Text, nullable=True)
    proposed_rule_scope = Column(JSON, nullable=True)
    status = Column(Text, nullable=False, default="pending")
    rejection_reason = Column(Text, nullable=True)
    analysis_revision_id = Column(
        Integer,
        ForeignKey("analysis_revisions.id", ondelete="SET NULL"),
        nullable=True,
        unique=True,
    )
    raw_proposed_rule = Column(Text, nullable=True)
    validation_status = Column(Text, nullable=False, default="pending")
    validation_error = Column(Text, nullable=True)
    rule_placement = Column(Text, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), default=_utcnow)
    reviewed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    last_seen_at = Column(TIMESTAMP(timezone=True), nullable=True)
    scope_key = Column(Text, nullable=True)
    rule_numeric_id = Column(Integer, nullable=True)
    supporting_case_count = Column(Integer, nullable=False, default=1)

    __table_args__ = (
        Index("exception_drafts_status_idx", "status"),
        Index("exception_drafts_transaction_id_idx", "transaction_id"),
    )


class InferenceAttempt(Base):
    """One provider request, including repairs and transport retries."""

    __tablename__ = "inference_attempts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_revision_id = Column(
        Integer, ForeignKey("analysis_revisions.id", ondelete="CASCADE"), nullable=False
    )
    attempt_type = Column(Text, nullable=False)
    started_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    latency_ms = Column(Integer, nullable=True)
    status = Column(Text, nullable=False, default="active")
    error_code = Column(Text, nullable=True)
    finish_reason = Column(Text, nullable=True)
    prompt_tokens = Column(Integer, nullable=True)
    completion_tokens = Column(Integer, nullable=True)
    total_tokens = Column(Integer, nullable=True)
    raw_response = Column(Text, nullable=True)

    __table_args__ = (
        Index("inference_attempts_revision_idx", "analysis_revision_id"),
        Index("inference_attempts_started_idx", "started_at"),
        Index("inference_attempts_status_idx", "status"),
    )


# Async engine + session factory
_async_engine = None
_async_session_factory = None


def _configure_sqlite(dbapi_conn, _connection_record):
    cursor = dbapi_conn.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.execute("PRAGMA journal_mode=WAL")
    cursor.execute("PRAGMA busy_timeout=5000")
    cursor.close()


def get_async_engine():
    global _async_engine
    if _async_engine is None:
        url = get_database_url()
        kwargs = {"echo": False}
        if url.startswith("sqlite"):
            # check_same_thread is for the sync sqlite3 driver; aiosqlite is fine without it.
            kwargs["connect_args"] = {"timeout": 30}
        _async_engine = create_async_engine(url, **kwargs)
        if url.startswith("sqlite"):
            event.listen(_async_engine.sync_engine, "connect", _configure_sqlite)
    return _async_engine


def get_session_factory():
    global _async_session_factory
    if _async_session_factory is None:
        _async_session_factory = async_sessionmaker(
            get_async_engine(), expire_on_commit=False
        )
    return _async_session_factory


async def get_db() -> AsyncSession:
    factory = get_session_factory()
    async with factory() as session:
        yield session


def _table_columns(conn, table: str) -> set[str]:
    rows = conn.execute(text(f"PRAGMA table_info({table})")).fetchall()
    # PRAGMA table_info: cid, name, type, notnull, dflt_value, pk
    return {row[1] for row in rows}


async def init_db():
    """Create all tables and indexes idempotently using SQLAlchemy metadata."""
    engine = get_async_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

        # Lightweight compatibility: add columns if an older SQLite file exists.
        def _migrate(sync_conn):
            if not str(engine.url).startswith("sqlite"):
                return {}
            try:
                cols = _table_columns(sync_conn, "exception_drafts")
            except Exception:
                return {}
            reconciliation = {"non_false_positive": 0, "duplicate_scope": 0, "id_conflict": 0}
            alters = []
            if "analysis_revision_id" not in cols:
                alters.append(
                    "ALTER TABLE exception_drafts ADD COLUMN analysis_revision_id INTEGER"
                )
            if "raw_proposed_rule" not in cols:
                alters.append("ALTER TABLE exception_drafts ADD COLUMN raw_proposed_rule TEXT")
            if "validation_status" not in cols:
                alters.append(
                    "ALTER TABLE exception_drafts ADD COLUMN validation_status TEXT "
                    "NOT NULL DEFAULT 'pending'"
                )
            if "validation_error" not in cols:
                alters.append("ALTER TABLE exception_drafts ADD COLUMN validation_error TEXT")
            if "rule_placement" not in cols:
                alters.append("ALTER TABLE exception_drafts ADD COLUMN rule_placement TEXT")
            if "scope_key" not in cols:
                alters.append("ALTER TABLE exception_drafts ADD COLUMN scope_key TEXT")
            if "rule_numeric_id" not in cols:
                alters.append("ALTER TABLE exception_drafts ADD COLUMN rule_numeric_id INTEGER")
            if "supporting_case_count" not in cols:
                alters.append(
                    "ALTER TABLE exception_drafts ADD COLUMN supporting_case_count INTEGER "
                    "NOT NULL DEFAULT 1"
                )
            for statement in alters:
                sync_conn.execute(text(statement))

            revision_cols = _table_columns(sync_conn, "analysis_revisions")
            revision_alters = []
            if "prompt_sha256" not in revision_cols:
                revision_alters.append(
                    "ALTER TABLE analysis_revisions ADD COLUMN prompt_sha256 TEXT"
                )
            if "model_settings" not in revision_cols:
                revision_alters.append(
                    "ALTER TABLE analysis_revisions ADD COLUMN model_settings JSON "
                    "NOT NULL DEFAULT '{}'"
                )
            if "error_code" not in revision_cols:
                revision_alters.append(
                    "ALTER TABLE analysis_revisions ADD COLUMN error_code TEXT"
                )
            for statement in revision_alters:
                sync_conn.execute(text(statement))

            rows = sync_conn.execute(
                text(
                    "SELECT id, proposed_rule_scope, proposed_rule FROM exception_drafts "
                    "WHERE scope_key IS NULL OR rule_numeric_id IS NULL"
                )
            ).fetchall()
            for draft_id, raw_scope, proposed_rule in rows:
                try:
                    scope = json.loads(raw_scope) if isinstance(raw_scope, str) else (raw_scope or {})
                except (TypeError, json.JSONDecodeError):
                    scope = {}
                parts = [
                    str(scope.get("uri") or "").split("?", 1)[0].rstrip("/") or "/",
                    str(scope.get("rule_id") or ""),
                    str(scope.get("collection") or "").upper(),
                    str(scope.get("parameter") or ""),
                ]
                scope_key = hashlib.sha256("\x1f".join(parts).encode()).hexdigest()
                match = re.search(r"(?:^|[,\s])id:(\d+)", proposed_rule or "")
                rule_numeric_id = int(match.group(1)) if match else None
                sync_conn.execute(
                    text(
                        "UPDATE exception_drafts SET scope_key=:scope_key, "
                        "rule_numeric_id=:rule_numeric_id WHERE id=:id"
                    ),
                    {"scope_key": scope_key, "rule_numeric_id": rule_numeric_id, "id": draft_id},
                )

            retired = sync_conn.execute(
                text(
                    "UPDATE exception_drafts SET status='stale', proposed_rule=NULL, "
                    "rule_placement=NULL WHERE classification!='false_positive' "
                    "AND status IN ('pending','approved')"
                )
            )
            reconciliation["non_false_positive"] = retired.rowcount

            # Reconcile old active duplicates before adding uniqueness constraints.
            duplicate_scopes = sync_conn.execute(
                text(
                    "SELECT scope_key FROM exception_drafts "
                    "WHERE status IN ('pending','approved') AND scope_key IS NOT NULL "
                    "GROUP BY scope_key HAVING COUNT(*) > 1"
                )
            ).fetchall()
            for (scope_key,) in duplicate_scopes:
                duplicates = sync_conn.execute(
                    text(
                        "SELECT id FROM exception_drafts WHERE scope_key=:scope_key "
                        "AND status IN ('pending','approved') "
                        "ORDER BY CASE status WHEN 'approved' THEN 0 ELSE 1 END, "
                        "created_at DESC, id DESC"
                    ),
                    {"scope_key": scope_key},
                ).fetchall()
                keep = duplicates[0][0]
                stale_ids = [row[0] for row in duplicates[1:]]
                reconciliation["duplicate_scope"] += len(stale_ids)
                for stale_id in stale_ids:
                    sync_conn.execute(
                        text(
                            "UPDATE exception_drafts SET status='stale', proposed_rule=NULL, "
                            "rule_placement=NULL, validation_status='duplicate_scope', "
                            "validation_error='Superseded by canonical active scope draft' "
                            "WHERE id=:id"
                        ),
                        {"id": stale_id},
                    )
                sync_conn.execute(
                    text(
                        "UPDATE exception_drafts SET supporting_case_count=:count WHERE id=:id"
                    ),
                    {"count": len(duplicates), "id": keep},
                )

            duplicate_rule_ids = sync_conn.execute(
                text(
                    "SELECT rule_numeric_id FROM exception_drafts "
                    "WHERE status IN ('pending','approved') AND rule_numeric_id IS NOT NULL "
                    "GROUP BY rule_numeric_id HAVING COUNT(*) > 1"
                )
            ).fetchall()
            for (numeric_id,) in duplicate_rule_ids:
                duplicates = sync_conn.execute(
                    text(
                        "SELECT id FROM exception_drafts WHERE rule_numeric_id=:numeric_id "
                        "AND status IN ('pending','approved') "
                        "ORDER BY CASE status WHEN 'approved' THEN 0 ELSE 1 END, "
                        "created_at DESC, id DESC"
                    ),
                    {"numeric_id": numeric_id},
                ).fetchall()
                for (stale_id,) in duplicates[1:]:
                    reconciliation["id_conflict"] += 1
                    sync_conn.execute(
                        text(
                            "UPDATE exception_drafts SET status='stale', proposed_rule=NULL, "
                            "rule_placement=NULL, validation_status='id_conflict', "
                            "validation_error='Numeric rule ID conflicts with another active scope' "
                            "WHERE id=:id"
                        ),
                        {"id": stale_id},
                    )
            sync_conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS exception_drafts_analysis_revision_uq "
                    "ON exception_drafts(analysis_revision_id) "
                    "WHERE analysis_revision_id IS NOT NULL"
                )
            )
            sync_conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS exception_drafts_active_scope_uq "
                    "ON exception_drafts(scope_key) WHERE status IN ('pending','approved')"
                )
            )
            sync_conn.execute(
                text(
                    "CREATE UNIQUE INDEX IF NOT EXISTS exception_drafts_active_rule_id_uq "
                    "ON exception_drafts(rule_numeric_id) "
                    "WHERE status IN ('pending','approved') AND rule_numeric_id IS NOT NULL"
                )
            )
            sync_conn.execute(
                text(
                    "UPDATE analysis_revisions SET error_code='invalid_output' "
                    "WHERE error_code IS NULL AND state='complete' "
                    "AND verdict LIKE 'Model response could not be validated:%'"
                )
            )
            sync_conn.execute(
                text(
                    "UPDATE exception_drafts SET status='stale' "
                    "WHERE validation_status='scope_conflict' "
                    "AND status IN ('pending', 'approved')"
                )
            )
            return reconciliation

        return await conn.run_sync(_migrate)
