"""
SQLAlchemy models and database utilities for the WAF Exception Agent.
Only the exception_drafts table is stored in Postgres.
Events live in events.jsonl.
"""
import os
from datetime import datetime
from typing import Optional, Any

from sqlalchemy import (
    Column, Integer, Text, Float, TIMESTAMP, Index, text
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker


def _get_db_url(async_: bool = False) -> str:
    user = os.environ.get("POSTGRES_USER", "waf")
    password = os.environ.get("POSTGRES_PASSWORD", "waf")
    host = os.environ.get("POSTGRES_HOST", "postgres")
    port = os.environ.get("POSTGRES_PORT", "5432")
    db = os.environ.get("POSTGRES_DB", "wafdb")
    driver = "asyncpg" if async_ else "psycopg2"
    scheme = f"postgresql+{driver}"
    return f"{scheme}://{user}:{password}@{host}:{port}/{db}"


class Base(DeclarativeBase):
    pass


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
    proposed_rule_scope = Column(JSONB, nullable=True)
    status = Column(Text, nullable=False, default="pending")
    rejection_reason = Column(Text, nullable=True)
    created_at = Column(TIMESTAMP(timezone=True), default=datetime.utcnow)
    reviewed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    deployed_at = Column(TIMESTAMP(timezone=True), nullable=True)
    last_seen_at = Column(TIMESTAMP(timezone=True), nullable=True)

    __table_args__ = (
        Index("exception_drafts_status_idx", "status"),
        Index("exception_drafts_transaction_id_idx", "transaction_id"),
    )


# Async engine + session factory
_async_engine = None
_async_session_factory = None


def get_async_engine():
    global _async_engine
    if _async_engine is None:
        _async_engine = create_async_engine(_get_db_url(async_=True), echo=False)
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


async def init_db():
    """Create all tables and indexes idempotently using SQLAlchemy metadata."""
    engine = get_async_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
