"""Housekeeping tasks."""
import asyncio
from datetime import datetime, timedelta, timezone

from loguru import logger
from sqlalchemy import delete, select

from core.celery_app import celery_app
from core.config import settings
from core.database import make_task_session_factory
from db.models import RequestLog

BATCH_SIZE = 10_000


async def _purge() -> int:
    cutoff = datetime.now(timezone.utc) - timedelta(days=settings.RETENTION_DAYS)
    engine, session_factory = make_task_session_factory()
    total = 0
    try:
        while True:
            async with session_factory() as db:
                # Delete in batches to avoid long locks; verified samples are kept
                # because they are the training set. Alerts cascade via FK.
                stale_ids = (
                    select(RequestLog.id)
                    .where(RequestLog.timestamp < cutoff)
                    .where(RequestLog.verified_label.is_(None))
                    .limit(BATCH_SIZE)
                    .scalar_subquery()
                )
                stmt = delete(RequestLog).where(RequestLog.id.in_(stale_ids))
                result = await db.execute(stmt)
                await db.commit()
                total += result.rowcount or 0
                if (result.rowcount or 0) < BATCH_SIZE:
                    break
    finally:
        await engine.dispose()
    return total


@celery_app.task(name="tasks.maintenance.purge_old_logs")
def purge_old_logs():
    deleted = asyncio.run(_purge())
    logger.info(f"Retention: deleted {deleted} request logs older than {settings.RETENTION_DAYS} days")
    return {"deleted": deleted}
