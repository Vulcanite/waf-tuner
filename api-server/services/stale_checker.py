"""
Stale Exception Checker — Phase 7

Background task that runs once per day and marks deployed exceptions
as 'stale' if last_seen_at is more than 90 days ago.
"""
import asyncio
import logging
from datetime import datetime, timezone, timedelta

logger = logging.getLogger(__name__)

STALE_DAYS = 90


async def stale_checker():
    """Mark deployed exceptions stale if not seen in STALE_DAYS days."""
    logger.info("Stale checker started")

    while True:
        try:
            from db.models import get_session_factory, ExceptionDraft
            from sqlalchemy import select, update

            factory = get_session_factory()
            async with factory() as session:
                now = datetime.now(timezone.utc)
                cutoff = now - timedelta(days=STALE_DAYS)

                stmt = (
                    update(ExceptionDraft)
                    .where(
                        ExceptionDraft.status == "deployed",
                        ExceptionDraft.last_seen_at.isnot(None),
                        ExceptionDraft.last_seen_at < cutoff,
                    )
                    .values(status="stale")
                )
                result = await session.execute(stmt)
                await session.commit()

                if result.rowcount:
                    logger.info("Marked %d exceptions as stale", result.rowcount)

        except Exception as e:
            logger.error("Stale checker error: %s", e)

        await asyncio.sleep(86400)
