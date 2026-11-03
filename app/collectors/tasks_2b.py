"""Celery tasks for Phase 2b: Telegram CTI, HIBP, reference datasets, MalwareBazaar."""

from __future__ import annotations

import logging

import redis.asyncio as aioredis
from celery.schedules import crontab
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.collectors import reference_data as rd
from app.collectors.base import IntelSignal, http_client
from app.collectors.hibp import collect_hibp
from app.collectors.tasks import _store
from app.collectors.telegram_cti import TelethonSource, TenantWatch, collect_telegram
from app.core.config import get_settings
from app.db.models import ReferenceDataset, Tenant
from app.db.session import session_scope
from app.processors.leak_redactor import account_key
from app.schemas.manifest import TenantManifest
from app.worker import health
from app.worker.celery_app import celery_app
from app.worker.runtime import run_with_engine, single_flight

log = logging.getLogger(__name__)
CURSOR_KEY = "hc:tg:cursors"


async def tenant_watches(session: AsyncSession) -> list[tuple[TenantWatch, TenantManifest]]:
    out = []
    for t in (await session.scalars(select(Tenant).where(Tenant.is_active.is_(True)))).all():
        m = TenantManifest.model_validate(t.manifest)
        watch = TenantWatch(
            t.id, m.brand.domains + m.brand.email_domains, m.portal_hostnames(), account_key(t.webhook_secret)
        )
        out.append((watch, m))
    return out


async def _telegram(engine: AsyncEngine) -> int:
    s = get_settings()
    if not (s.telegram_api_id and s.telegram_api_hash and s.telegram_session and s.telegram_channels):
        raise health.NotConfigured("HC_TELEGRAM_API_ID / API_HASH / SESSION / CHANNELS not set")
    async with session_scope(engine) as session:
        watches = [w for w, _ in await tenant_watches(session)]
    r = aioredis.from_url(s.redis_url)
    try:
        cursors = {k.decode(): int(v) for k, v in (await r.hgetall(CURSOR_KEY)).items()}
        source = TelethonSource(
            s.telegram_api_id, s.telegram_api_hash.get_secret_value(), s.telegram_session.get_secret_value()
        )
        signals, new = await collect_telegram(
            source, s.telegram_channels, watches, cursors=cursors, limit=s.telegram_fetch_limit
        )
        inserted = await _store(engine, signals)
        if new:
            await r.hset(CURSOR_KEY, mapping={k: str(v) for k, v in new.items()})  # only after a successful store
        return inserted
    finally:
        await r.aclose()


async def _hibp(engine: AsyncEngine) -> int:
    s = get_settings()
    if s.hibp_api_key is None:
        raise health.NotConfigured("HC_HIBP_API_KEY not set")
    async with session_scope(engine) as session:
        pairs = await tenant_watches(session)
    signals: list[IntelSignal] = []
    async with http_client() as client:
        for watch, manifest in pairs:
            domains = manifest.brand.email_domains or manifest.brand.domains
            signals += await collect_hibp(client, s.hibp_api_key.get_secret_value(), watch, domains)
    return await _store(engine, signals)


async def _reference(engine: AsyncEngine) -> tuple[int, list[str]]:
    """Returns (signals inserted, partial-failure messages)."""
    s = get_settings()
    async with session_scope(engine) as session:
        prev_osv = (
            await session.scalar(select(ReferenceDataset.records).where(ReferenceDataset.name == "osv_malicious"))
        ) or []
    fetchers = {
        "loldrivers": lambda c: rd.fetch_loldrivers(c, s.loldrivers_url),
        "lolrmm": lambda c: rd.fetch_lolrmm(c, s.lolrmm_url),
        "hijacklibs": lambda c: rd.fetch_hijacklibs(c, s.hijacklibs_zip_url),
        "osv_malicious": lambda c: rd.fetch_osv_malicious(
            c, s.osv_base_url, s.osv_ecosystems, s.osv_lookback_days, previous=prev_osv,
            max_ids=s.osv_max_ids_per_run,
        ),
    }  # fmt: skip
    signals: list[IntelSignal] = []
    errors: list[str] = []
    async with http_client() as client:
        for name, fetch in fetchers.items():
            try:
                ds = await fetch(client)
            except Exception as exc:  # noqa: BLE001 — one broken source must not block the others
                log.exception("reference dataset %s failed", name)
                errors.append(f"{name}: {type(exc).__name__}")
                continue
            errors += ds.errors
            async with session_scope(engine) as session:
                row = await session.scalar(select(ReferenceDataset).where(ReferenceDataset.name == name))
                if row is not None and row.version == ds.version:
                    continue
                key = {"loldrivers": "id", "hijacklibs": "dll", "lolrmm": "name", "osv_malicious": "id"}[name]
                previous = {r.get(key) for r in row.records} if row else set()
                if row is None:
                    row = ReferenceDataset(name=name)
                    session.add(row)
                row.version, row.records, row.record_count, row.fetched_at = (
                    ds.version,
                    ds.records,
                    len(ds.records),
                    ds.fetched_at,
                )
            signals.append(rd.dataset_signal(ds, previous))
    return await _store(engine, signals), errors


async def _malwarebazaar(engine: AsyncEngine) -> int:
    s = get_settings()
    if s.abusech_auth_key is None:
        raise health.NotConfigured("HC_ABUSECH_AUTH_KEY not set")
    signals = []
    async with http_client() as client:
        for tag in s.malwarebazaar_tags:
            if sig := await rd.fetch_malwarebazaar(
                client, s.malwarebazaar_url, s.abusech_auth_key.get_secret_value(), tag
            ):
                signals.append(sig)
    return await _store(engine, signals)


@celery_app.task(name="collectors.telegram_sweep")
def telegram_sweep() -> int:
    with single_flight("telegram_sweep", 25 * 60) as ok:
        if ok:
            with health.track("telegram_sweep"):
                return run_with_engine(_telegram)
    return 0


@celery_app.task(name="collectors.hibp_sweep")
def hibp_sweep() -> int:
    with single_flight("hibp_sweep", 3600) as ok:
        if ok:
            with health.track("hibp_sweep"):
                return run_with_engine(_hibp)
    return 0


@celery_app.task(name="collectors.reference_sync", soft_time_limit=1200, time_limit=1260)
def reference_sync() -> int:
    with single_flight("reference_sync", 3600) as ok:
        if ok:
            with health.track("reference_sync") as hb:
                inserted, errors = run_with_engine(_reference)
                for note in errors:  # one failing dataset or OSV ecosystem marks the job failing
                    hb.fail(note)
                return inserted
    return 0


@celery_app.task(name="collectors.malwarebazaar_sweep")
def malwarebazaar_sweep() -> int:
    with single_flight("malwarebazaar_sweep", 25 * 60) as ok:
        if ok:
            with health.track("malwarebazaar_sweep"):
                return run_with_engine(_malwarebazaar)
    return 0


_s = get_settings()
celery_app.conf.beat_schedule.update(
    {
        "telegram-sweep": {
            "task": "collectors.telegram_sweep",
            "schedule": crontab(minute=f"*/{_s.collector_interval_minutes}"),
        },
        "malwarebazaar-sweep": {"task": "collectors.malwarebazaar_sweep", "schedule": crontab(minute="15", hour="*/2")},
        "hibp-sweep": {"task": "collectors.hibp_sweep", "schedule": crontab(minute="30", hour="3")},
        "reference-sync": {
            "task": "collectors.reference_sync",
            "schedule": crontab(minute="5", hour=f"*/{_s.reference_sync_hours}"),
        },
    }
)
