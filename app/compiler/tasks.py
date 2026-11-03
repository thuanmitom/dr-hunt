"""Celery wiring for Phase 3: clustering, AI-assisted pack building, push dispatch."""

from __future__ import annotations

import logging
from datetime import UTC, datetime

import redis.asyncio as aioredis
from celery.schedules import crontab
from sqlalchemy.ext.asyncio import AsyncEngine

from app.collectors.base import http_client
from app.compiler.llm import GeminiProvider, LLMProvider
from app.core.config import get_settings
from app.db.session import session_scope
from app.dispatch.dispatcher import deliver_due
from app.processors.whitelist_filter import WhitelistFilter, default_sources
from app.services.ai_service import ai_tasks_for_cluster
from app.services.cluster_builder import cluster_pending_events
from app.services.pack_builder import build_packs
from app.services.tenant_context import load_active_tenants
from app.worker import health
from app.worker.celery_app import celery_app
from app.worker.runtime import run_with_engine, single_flight

log = logging.getLogger(__name__)


async def _whitelist(session) -> WhitelistFilter:
    tenants = await load_active_tenants(session)
    return WhitelistFilter(
        default_sources(),
        tenant_domains=[d for t in tenants for d in t.manifest.brand.domains + t.manifest.brand.email_domains],
        tenant_networks=[n for t in tenants for n in t.manifest.public_ip_ranges],
    )


def _provider() -> LLMProvider | None:
    s = get_settings()
    if not s.llm_enabled or s.gemini_api_key is None:
        return None
    return GeminiProvider(s.gemini_api_key.get_secret_value(), s.gemini_model_fast)


async def _reserve(tokens: int) -> bool:
    """Daily token budget shared by all workers (protects against cost-amplification floods)."""
    s = get_settings()
    client = aioredis.from_url(s.redis_url)
    try:
        key = f"hc:llm:tokens:{datetime.now(UTC):%Y%m%d}"
        used = await client.incrby(key, tokens)
        await client.expire(key, 2 * 86400)
        return used <= s.llm_daily_token_budget
    finally:
        await client.aclose()


async def _cluster(engine: AsyncEngine) -> int:
    async with session_scope(engine) as session:
        return await cluster_pending_events(session, await _whitelist(session))


async def _build(engine: AsyncEngine) -> int:
    provider = _provider()
    async with session_scope(engine) as session:
        wl = await _whitelist(session)

        async def ai(cluster):
            if provider is None:
                return []
            vectors = set(get_settings().llm_vectors)
            return await ai_tasks_for_cluster(
                session, cluster, provider, wl, enabled_vectors=vectors, reserve_tokens=_reserve
            )

        return await build_packs(session, ai_tasks=ai)


async def _dispatch(engine: AsyncEngine) -> dict[str, int]:
    async with session_scope(engine) as session, http_client() as client:
        return await deliver_due(session, client, batch=get_settings().dispatch_batch_size)


@celery_app.task(name="compiler.cluster_events")
def cluster_events() -> int:
    with single_flight("cluster_events", 240) as ok:
        if ok:
            with health.track("cluster_events"):
                return run_with_engine(_cluster)
    return 0


@celery_app.task(name="compiler.build_packs", soft_time_limit=900, time_limit=960)
def build_packs_task() -> int:
    with single_flight("build_packs", 900) as ok:
        if ok:
            with health.track("build_packs"):
                return run_with_engine(_build)
    return 0


@celery_app.task(name="dispatch.deliver_due")
def deliver_due_task() -> dict[str, int]:
    with single_flight("deliver_due", 55) as ok:
        if ok:
            with health.track("deliver_due"):
                return run_with_engine(_dispatch)
    return {}


celery_app.conf.beat_schedule.update(
    {
        "cluster-events": {"task": "compiler.cluster_events", "schedule": crontab(minute="*/5")},
        "build-packs": {"task": "compiler.build_packs", "schedule": crontab(minute="*/10")},
        "deliver-due": {"task": "dispatch.deliver_due", "schedule": crontab(minute="*")},
    }
)
