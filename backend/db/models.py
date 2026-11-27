"""
SQLAlchemy models and database utilities for the WAF Exception Agent.

Raw audit events and the durable ingestion and analysis workflow state live in a
local SQLite database (lightweight default for lab / bare metal).
"""
from __future__ import annotations

import os
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
    inspect,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase


def _default_sqlite_path() -> Path:
    from services.runtime_config import data_dir

    return data_dir() / "waf-tuner.db"


def get_database_url() -> str:
    """Return the async SQLite URL. DATABASE_URL (a sqlite URL) overrides DATABASE_PATH."""
    explicit = os.environ.get("DATABASE_URL", "").strip()
    if explicit:
        return explicit
    path = Path(os.environ.get("DATABASE_PATH") or _default_sqlite_path()).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite+aiosqlite:///{path}"


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
    path = Column(Text, nullable=True)
    anomaly_score = Column(Integer, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("audit_events_event_line_idx", "event_line"),
        Index("audit_events_timestamp_idx", "timestamp"),
        Index("audit_events_created_at_idx", "created_at"),
    )


class AnalysisCase(Base):
    """A unique signature/payload combination; repeated traffic updates this row."""

    __tablename__ = "analysis_cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    fingerprint = Column(Text, nullable=False, unique=True)
    method = Column(Text, nullable=False)
    application_host = Column(Text, nullable=True)
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
    lease_token = Column(Text, nullable=True)
    enqueued_at = Column(TIMESTAMP(timezone=True), nullable=True, default=_utcnow)
    completed_generation = Column(Text, nullable=True)
    last_error = Column(Text, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)

    __table_args__ = (
        Index("analysis_cases_state_retry_idx", "state", "next_retry_at"),
        Index("analysis_cases_rule_id_idx", "rule_id"),
        Index("analysis_cases_last_seen_idx", "last_seen_at", "id"),
        Index("analysis_cases_lease_idx", "state", "lease_expires_at"),
        Index("analysis_cases_path_host_idx", "path", "application_host"),
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
        Index("incident_occurrences_latest_idx", "analysis_case_id", "observed_at", "id"),
        Index("incident_occurrences_event_rule_idx", "audit_event_id", "rule_id"),
        Index("incident_occurrences_fingerprint_idx", "fingerprint"),
    )


class AnalysisRevision(Base):
    """Reproducible model result for a case and a specific context version."""

    __tablename__ = "analysis_revisions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    analysis_case_id = Column(
        Integer, ForeignKey("analysis_cases.id", ondelete="CASCADE"), nullable=False
    )
    occurrence_id = Column(Integer, ForeignKey("incident_occurrences.id", ondelete="SET NULL"), nullable=True)
    input_keys = Column(JSON, nullable=True)
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
    stage_metrics = Column(JSON, nullable=True)
    pending_repair_input = Column(Text, nullable=True)
    evidence_digest = Column(Text, nullable=True)
    classification = Column(Text, nullable=True)
    confidence = Column(Float, nullable=True)
    verdict = Column(Text, nullable=True)
    context_factors = Column(JSON, nullable=False, default=list)
    uncertainty_factors = Column(JSON, nullable=False, default=list)
    raw_response = Column(Text, nullable=True)
    proposed_rule_scope = Column(JSON, nullable=True)
    normalized_rule = Column(Text, nullable=True)
    validation_status = Column(Text, nullable=False, default="pending")
    validation_error = Column(Text, nullable=True)
    started_at = Column(TIMESTAMP(timezone=True), nullable=False, default=_utcnow)
    completed_at = Column(TIMESTAMP(timezone=True), nullable=True)

    __table_args__ = (
        Index("analysis_revisions_case_idx", "analysis_case_id"),
        Index("analysis_revisions_occurrence_idx", "occurrence_id"),
        Index("analysis_revisions_state_idx", "state"),
        Index("analysis_revisions_evidence_idx", "analysis_case_id", "evidence_digest"),
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
        # One active draft per scope and per numeric rule ID. The agent's
        # INSERT OR IGNORE relies on these to resolve concurrent workers.
        Index(
            "exception_drafts_active_scope_uq", "scope_key", unique=True,
            sqlite_where=text("status IN ('pending','approved') AND classification = 'false_positive'"),
        ),
        Index(
            "exception_drafts_active_rule_id_uq", "rule_numeric_id", unique=True,
            sqlite_where=text("status IN ('pending','approved') AND classification = 'false_positive' AND rule_numeric_id IS NOT NULL"),
        ),
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
    reasoning_tokens = Column(Integer, nullable=True)
    provider_ms = Column(Integer, nullable=True)
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
        _async_engine = create_async_engine(url, echo=False, hide_parameters=True, connect_args={"timeout": 30})
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


def _migrate_schema(connection) -> None:
    Base.metadata.create_all(connection)
    added_columns = {
        AuditEvent: ("path", "anomaly_score"),
        AnalysisCase: ("application_host", "lease_token", "enqueued_at", "completed_generation"),
        IncidentOccurrence: (),
        AnalysisRevision: ("stage_metrics", "pending_repair_input", "evidence_digest", "occurrence_id", "input_keys"),
        InferenceAttempt: ("reasoning_tokens", "provider_ms"),
    }
    inspector = inspect(connection)
    for model, names in added_columns.items():
        table = model.__table__
        existing = {column["name"] for column in inspector.get_columns(table.name)}
        for name in names:
            if name not in existing:
                sql_type = table.c[name].type.compile(dialect=connection.dialect)
                connection.exec_driver_sql(f'ALTER TABLE "{table.name}" ADD COLUMN "{name}" {sql_type}')
        for index in table.indexes:
            index.create(connection, checkfirst=True)

    for index in ExceptionDraft.__table__.indexes:
        if not index.unique:
            continue
        existing_sql = connection.execute(
            text("SELECT sql FROM sqlite_master WHERE type='index' AND name=:name"),
            {"name": index.name},
        ).scalar_one_or_none()
        if existing_sql and "classification = 'false_positive'" not in existing_sql:
            # Index names and predicates come from model metadata, never from runtime input.
            index.drop(connection)
        index.create(connection, checkfirst=True)


async def init_db() -> None:
    """Create tables and apply additive changes to prior SQLite databases."""
    engine = get_async_engine()
    async with engine.begin() as conn:
        await conn.run_sync(_migrate_schema)
