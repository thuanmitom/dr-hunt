"""Celery tasks for Phase 2 collectors and enrichment."""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from celery.schedules import crontab
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine

from app.collectors.base import IntelSignal, http_client
from app.collectors.edge_exploits import EdgeIntelClient, collect_edge_exploits
from app.collectors.urlscan import UrlscanClient, collect_brand_aitm, collect_clickfix
from app.core.config import Settings, get_settings
from app.db.models import RawIntelEvent
from app.db.session import session_scope
from app.processors.pivot import fetch_favicon_hash, jarm_fingerprint
from app.processors.whitelist_filter import Action, WhitelistFilter, default_sources
from app.services.intel_store import store_signals
from app.services.kev_reenrich import reenrich_kev
from app.services.tenant_context import load_active_tenants
from app.worker import health
from app.worker.celery_app import celery_app
from app.worker.runtime import run_with_engine, single_flight

log = logging.getLogger(__name__)
MAX_ENRICH_HOSTS = 10


async def _store(engine: AsyncEngine, signals: list[IntelSignal]) -> int:
    async with session_scope(engine) as session:
        inserted = await store_signals(session, signals)
    for s in signals:  # enrichment is cheap to skip if the row already existed
        if s.attack_vector is not None:
            celery_app.send_task("processors.enrich_event", args=[s.source.value, s.dedup_sha256()])
    return inserted


@celery_app.task(name="collectors.ingest_signals")
def ingest_signals(signals: list[dict[str, Any]]) -> int:
    return run_with_engine(_store, [IntelSignal.model_validate(s) for s in signals])


async def _urlscan_sweep(engine: AsyncEngine) -> int:
    settings = get_settings()
    if settings.urlscan_api_key is None:
        raise health.NotConfigured("HC_URLSCAN_API_KEY not set")
    async with session_scope(engine) as session:
        tenants = await load_active_tenants(session)
    signals: list[IntelSignal] = []
    async with http_client() as client:
        urlscan = UrlscanClient(client, settings.urlscan_api_key.get_secret_value(), settings.urlscan_base_url)
        for t in tenants:
            signals += await collect_brand_aitm(
                urlscan,
                tenant_id=t.id,
                keywords=t.manifest.brand.keywords,
                query_template=settings.urlscan_brand_query,
                size=settings.urlscan_search_size,
                bad_jarms=frozenset(settings.suspicious_jarm_fingerprints),
            )
        signals += await collect_clickfix(
            urlscan, query=settings.urlscan_clickfix_query, size=settings.urlscan_search_size
        )
    return await _store(engine, signals)


@celery_app.task(name="collectors.urlscan_sweep")
def urlscan_sweep() -> int:
    with single_flight("urlscan_sweep", ttl_seconds=25 * 60) as ok:
        if ok:
            with health.track("urlscan_sweep"):
                return run_with_engine(_urlscan_sweep)
    return 0


def _edge_client(client: Any, settings: Settings) -> EdgeIntelClient:
    return EdgeIntelClient(
        client,
        github_token=settings.github_token.get_secret_value() if settings.github_token else None,
        github_api=settings.github_api_url,
        kev_url=settings.kev_feed_url,
        epss_url=settings.epss_api_url,
    )


async def _edge_sweep(engine: AsyncEngine) -> tuple[int, list[str]]:
    settings = get_settings()
    async with session_scope(engine) as session:
        tenants = await load_active_tenants(session)
    tags = {t.slug: set(t.manifest.tech_stack_tags) for t in tenants if t.manifest.tech_stack_tags}
    if not tags:
        return 0, []
    errors: list[str] = []
    async with http_client() as client:
        edge = _edge_client(client, settings)
        signals = await collect_edge_exploits(
            edge,
            tags,
            lookback_days=settings.kev_lookback_days,
            epss_threshold=settings.epss_alert_threshold,
            errors=errors,
        )
    return await _store(engine, signals), errors


@celery_app.task(name="collectors.edge_exploit_sweep")
def edge_exploit_sweep() -> int:
    with single_flight("edge_exploit_sweep", ttl_seconds=25 * 60) as ok:
        if ok:
            with health.track("edge_exploit_sweep") as hb:
                inserted, errors = run_with_engine(_edge_sweep)
                for note in errors:  # GitHub enrichment failed; the KEV signals still shipped (D-54)
                    hb.fail(note)
                return inserted
    return 0


async def _kev_reenrich(engine: AsyncEngine) -> tuple[int, list[str]]:
    settings = get_settings()
    async with http_client() as client:
        result = await reenrich_kev(engine, _edge_client(client, settings), now=datetime.now(UTC),
                                    lookback_days=settings.kev_lookback_days,
                                    max_attempts=settings.kev_reenrich_max_attempts)  # fmt: skip
    log.info("kev re-enrichment: %s retried, %s improved", result.retried, result.improved)
    return result.retried, result.errors


@celery_app.task(name="collectors.kev_reenrich")
def kev_reenrich() -> int:
    """D-71: daily retry of the GitHub data KEV entries missed. Failures show on the health page."""
    with single_flight("kev_reenrich", ttl_seconds=55 * 60) as ok:
        if ok:
            with health.track("kev_reenrich") as hb:
                retried, errors = run_with_engine(_kev_reenrich)
                for note in errors:
                    hb.fail(note)
                return retried
    return 0


async def _enrich(engine: AsyncEngine, source: str, dedup_sha256: str) -> dict[str, Any]:
    settings = get_settings()
    async with session_scope(engine) as session:
        event = await session.scalar(
            select(RawIntelEvent).where(RawIntelEvent.source == source, RawIntelEvent.dedup_sha256 == dedup_sha256)
        )
        if event is None or "enrichment" in event.raw_payload:
            return {}
        tenants = await load_active_tenants(session)
        wf = WhitelistFilter(
            default_sources(),
            tenant_domains=[d for t in tenants for d in t.manifest.brand.domains],
            tenant_networks=[n for t in tenants for n in t.manifest.public_ip_ranges],
        )
        domains = [o["value"] for o in event.observables if o["type"] == "domain"]
        ips = [o["value"] for o in event.observables if o["type"] == "ip"]
        verdicts = wf.partition(domains, ips)
        enrichment: dict[str, Any] = {
            "whitelist": {a.value: [{"value": r.value, "reason": r.reason} for r in rs] for a, rs in verdicts.items()},
            "jarm": {},
            "favicon_mmh3": {},
        }
        # Probe only hosts that survived the whitelist and are worth blocking/hunting.
        probe = [r.value for r in verdicts[Action.BLOCK] if r.kind == "domain"][:MAX_ENRICH_HOSTS]
        async with http_client() as client:
            for host in probe:
                if jarm := await jarm_fingerprint(host, timeout=settings.jarm_timeout_seconds):
                    enrichment["jarm"][host] = jarm
                if fav := await fetch_favicon_hash(client, f"https://{host}/"):
                    enrichment["favicon_mmh3"][host] = fav[1]
        event.raw_payload = {**event.raw_payload, "enrichment": enrichment}
        return enrichment


@celery_app.task(name="processors.enrich_event", soft_time_limit=300, time_limit=360)
def enrich_event(source: str, dedup_sha256: str) -> dict[str, Any]:
    return run_with_engine(_enrich, source, dedup_sha256)


_minutes = get_settings().collector_interval_minutes
celery_app.conf.beat_schedule.update(
    {
        "urlscan-sweep": {"task": "collectors.urlscan_sweep", "schedule": crontab(minute=f"*/{_minutes}")},
        "edge-exploit-sweep": {"task": "collectors.edge_exploit_sweep", "schedule": crontab(minute=f"*/{_minutes}")},
        # 04:15 UTC: away from retention (02:45), HIBP (03:30) and the 6-hourly reference sync (:05)
        "kev-reenrich": {"task": "collectors.kev_reenrich", "schedule": crontab(hour=4, minute=15)},
    }
)
