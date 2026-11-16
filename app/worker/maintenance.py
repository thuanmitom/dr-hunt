"""Housekeeping jobs (Phase H): daily data retention (D-57)."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from celery.schedules import crontab
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import get_settings
from app.db.session import session_scope
from app.services.retention import purge_old_data
from app.worker import health
from app.worker.celery_app import celery_app
from app.worker.runtime import run_with_engine, single_flight

log = logging.getLogger(__name__)


async def _retention(engine: AsyncEngine) -> dict[str, int]:
    settings = get_settings()
    async with session_scope(engine) as session:
        deleted = await purge_old_data(session, now=datetime.now(UTC),
                                       raw_event_days=settings.retention_raw_event_days,
                                       ai_compilation_days=settings.retention_ai_compilation_days)  # fmt: skip
    log.info("retention: deleted %s", deleted)
    return deleted


@celery_app.task(name="maintenance.retention")
def retention() -> dict[str, int]:
    with single_flight("retention", 3600) as ok:
        if ok:
            with health.track("retention"):
                return run_with_engine(_retention)
    return {}


celery_app.conf.beat_schedule.update(
    # 02:45 UTC: away from the 03:30 HIBP sweep and the 6-hourly reference sync
    {"retention": {"task": "maintenance.retention", "schedule": crontab(hour=2, minute=45)}}
)
