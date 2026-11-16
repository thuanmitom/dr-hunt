"""Scheduled Telegram digest (TELEGRAM.md §4, DECISIONS.md D-43).

Window (owner decisions of 2026-11-02):
* top items, credential exposure and edge CVEs: clusters with at least one **new pack** (``hunting_packs.seq``
  above the last sent digest's mark) for the shown tenants; clusters below the delivery threshold are not listed;
* dataset updates: reference-dataset events **linked** after the last sent digest's ``cluster_event_links.linked_at``
  mark. (``pivoted_clusters.updated_at`` is not used: confidence decay rewrites it every 10 minutes.)

Idempotency: a ``sending`` row is committed before anything is sent; it becomes ``sent`` (and its marks become the
next window's start) only after every message went out, otherwise ``failed``. ``/digest`` writes ``preview`` rows,
which never count.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from collections.abc import Awaitable, Callable, Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, date, datetime, time
from typing import Any
from zoneinfo import ZoneInfo

import redis.asyncio as aioredis
from celery.schedules import crontab
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker

from app.collectors.edge_exploits import KEV_ENDPOINT
from app.core.config import Settings, get_settings
from app.db.models import (
    AiCompilation,
    HuntingPack,
    PivotedCluster,
    RawIntelEvent,
    TelegramDigest,
    Tenant,
    cluster_event_links,
)
from app.integrations.telegram.client import TelegramClient, scrub
from app.integrations.telegram.format import (
    ClusterLine,
    CveItem,
    DatasetItem,
    DigestData,
    ExposureItem,
    HealthReport,
    PatchItem,
    cluster_label,
    defang_text,
    render_digest,
)
from app.schemas.enums import AttackVector, DeliveryStatus, DigestStatus, IntelSource
from app.worker.celery_app import celery_app
from app.worker.health import read_heartbeats
from app.worker.runtime import run_with_engine, single_flight

log = logging.getLogger(__name__)
DATASET_SOURCES = (IntelSource.LOLDRIVERS, IntelSource.HIJACKLIBS, IntelSource.LOLRMM, IntelSource.OSV)
SOURCE_LABEL = {IntelSource.TELEGRAM_CTI: "Telegram", IntelSource.LEAK_API: "HIBP"}


@dataclass(frozen=True, slots=True)
class Marks:
    max_pack_seq: int
    max_link_at: datetime | None


# --- window -------------------------------------------------------------------------------------------
async def last_sent(session: AsyncSession) -> TelegramDigest | None:
    return await session.scalar(
        select(TelegramDigest)
        .where(TelegramDigest.status == DigestStatus.SENT)
        .order_by(TelegramDigest.created_at.desc(), TelegramDigest.max_pack_seq.desc())
        .limit(1)
    )


async def current_marks(session: AsyncSession) -> Marks:
    seq = await session.scalar(select(func.max(HuntingPack.seq)))
    link = await session.scalar(select(func.max(cluster_event_links.c.linked_at)))
    return Marks(int(seq or 0), link)


def _tenant_filter(stmt: Any, tenants: Iterable[str]) -> Any:
    tenants = sorted(set(tenants))
    return stmt.where(Tenant.slug.in_(tenants)) if tenants else stmt


def _ioc_count(payload: dict[str, Any]) -> int:
    bl = payload.get("prevention_blocklist") or {}
    return sum(len(bl.get(k) or []) for k in ("domains", "ips", "hashes", "jarm_fingerprints"))


def build_lines(rows: Sequence[Any], old_cluster_ids: set[Any]) -> list[ClusterLine]:
    """rows: (HuntingPack, tenant slug, PivotedCluster), any order. One line per cluster; the newest pack decides
    severity, confidence, task and IOC counts and the shown pack id."""
    by_cluster: dict[Any, list[Any]] = defaultdict(list)
    for row in rows:
        by_cluster[row[2].id].append(row)
    lines = []
    for cluster_id, items in by_cluster.items():
        pack, _, cluster = max(items, key=lambda r: r[0].seq)
        p = pack.payload
        lines.append(ClusterLine(
            cluster_id=str(cluster_id), cluster_key=cluster.cluster_key, vector=AttackVector(cluster.attack_vector),
            label=cluster_label(cluster.cluster_key, cluster.title), severity=str(p["severity"]),
            confidence=int(p["confidence_score"]), tasks=len(p.get("internal_hunting_tasks") or []),
            iocs=_ioc_count(p), pack_id=str(pack.id), tenants=tuple(sorted({r[1] for r in items})),
            is_new=cluster_id not in old_cluster_ids,
        ))  # fmt: skip
    return sorted(lines, key=lambda line: line.sort_key)


async def _pack_rows(session: AsyncSession, tenants: Iterable[str], *, after: int, upto: int) -> list[Any]:
    stmt = (
        select(HuntingPack, Tenant.slug, PivotedCluster)
        .join(Tenant, Tenant.id == HuntingPack.tenant_id)
        .join(PivotedCluster, PivotedCluster.id == HuntingPack.cluster_id)
        .where(HuntingPack.seq > after, HuntingPack.seq <= upto)
    )
    return list((await session.execute(_tenant_filter(stmt, tenants).order_by(HuntingPack.seq))).all())


async def _older_clusters(session: AsyncSession, cluster_ids: list[Any], tenants: Iterable[str], upto: int) -> set:
    if not cluster_ids:
        return set()
    stmt = (
        select(HuntingPack.cluster_id)
        .join(Tenant, Tenant.id == HuntingPack.tenant_id)
        .where(HuntingPack.cluster_id.in_(cluster_ids), HuntingPack.seq <= upto)
    )
    return set((await session.scalars(_tenant_filter(stmt, tenants))).all())


async def _cluster_events(session: AsyncSession, cluster_id: Any, limit: int = 200) -> list[RawIntelEvent]:
    return list(
        (
            await session.scalars(
                select(RawIntelEvent)
                .join(cluster_event_links, cluster_event_links.c.event_id == RawIntelEvent.id)
                .where(cluster_event_links.c.cluster_id == cluster_id)
                .order_by(RawIntelEvent.id.desc())
                .limit(limit)
            )
        ).all()
    )


async def _exposures(session: AsyncSession, lines: list[ClusterLine], clusters: dict[str, PivotedCluster]) -> list:
    out = []
    for line in lines:
        if not line.cluster_key.endswith(":credential-exposure"):
            continue
        accounts = (clusters[line.cluster_id].observables or {}).get("accounts") or []
        events = await _cluster_events(session, clusters[line.cluster_id].id)
        sources = sorted({SOURCE_LABEL.get(IntelSource(e.source), str(e.source)) for e in events})
        families = sorted({f for e in events for f in (e.raw_payload or {}).get("families", [])})
        masked = tuple(sorted({a.get("masked", "") for a in accounts if a.get("masked")})[:5])
        for tenant in line.tenants:
            out.append(ExposureItem(tenant, len(accounts), masked, tuple(sources), tuple(families)))
    return out


def _cves(lines: list[ClusterLine], clusters: dict[str, PivotedCluster]) -> list[CveItem]:
    out = []
    for line in lines:
        if line.vector is not AttackVector.EDGE_DEVICE_EXPLOIT:
            continue
        c = clusters[line.cluster_id]
        features = (c.pivot_graph or {}).get("features") or {}
        pct = features.get("epss_percentile")
        out.append(CveItem(line.label, c.title, float(pct) if pct is not None else None,
                           bool(features.get("credible_poc")), line.tenants))  # fmt: skip
    return out


async def _datasets(session: AsyncSession, prev: Marks, cap: Marks) -> list[DatasetItem]:
    if cap.max_link_at is None:
        return []
    stmt = (
        select(RawIntelEvent.raw_payload, cluster_event_links.c.linked_at)
        .join(cluster_event_links, cluster_event_links.c.event_id == RawIntelEvent.id)
        .where(RawIntelEvent.source.in_(DATASET_SOURCES), cluster_event_links.c.linked_at <= cap.max_link_at)
        .order_by(cluster_event_links.c.linked_at)
    )
    if prev.max_link_at is not None:
        stmt = stmt.where(cluster_event_links.c.linked_at > prev.max_link_at)
    latest: dict[str, int] = {}
    new: dict[str, int] = defaultdict(int)
    for payload, _ in (await session.execute(stmt)).all():
        name = str((payload or {}).get("dataset", "unknown"))
        latest[name] = int(payload.get("records", 0))
        new[name] += int(payload.get("new_count", len(payload.get("new") or [])))
    return [DatasetItem(name, latest[name], new[name]) for name in sorted(latest)]


async def _patches(session: AsyncSession, tenants_shown: Iterable[str], prev: Marks, cap: Marks,
                   with_pack: set[tuple[str, str]]) -> list[PatchItem]:  # fmt: skip
    """D-70: KEV entries for OS or desktop software linked in this window that match a shown tenant's tech stack.
    They normally get no hunting pack. A tenant that did get one in this window (AI tasks, or the product listed in
    its login portals) sees it in the edge CVE section instead; ``with_pack`` holds those (cluster id, slug) pairs."""
    if cap.max_link_at is None:
        return []
    stmt = (
        select(PivotedCluster)
        .join(cluster_event_links, cluster_event_links.c.cluster_id == PivotedCluster.id)
        .join(RawIntelEvent, RawIntelEvent.id == cluster_event_links.c.event_id)
        .where(RawIntelEvent.source == IntelSource.CISA_KEV, cluster_event_links.c.linked_at <= cap.max_link_at)
    )
    if prev.max_link_at is not None:
        stmt = stmt.where(cluster_event_links.c.linked_at > prev.max_link_at)
    clusters = {str(c.id): c for c in (await session.scalars(stmt)).all()}
    shown = set(tenants_shown)
    rows = (await session.execute(select(Tenant.slug, Tenant.tech_stack_tags).where(Tenant.is_active))).all()
    tenant_tags = [(slug, set(tags or [])) for slug, tags in rows if not shown or slug in shown]
    out = []
    for cid, c in clusters.items():
        features = (c.pivot_graph or {}).get("features") or {}
        if features.get("kev_class") != KEV_ENDPOINT:
            continue
        matched = (slug for slug, tags in tenant_tags if tags & set(c.tech_stack_tags or []))
        slugs = tuple(sorted(slug for slug in matched if (cid, slug) not in with_pack))
        if not slugs:
            continue
        pct = features.get("epss_percentile")
        cve = (c.cve_ids or [c.cluster_key.rsplit(":", 1)[-1]])[0]
        out.append(PatchItem(cve, c.title, float(pct) if pct is not None else None, slugs))
    return sorted(out, key=lambda p: p.cve)


async def collect_health(session: AsyncSession, redis: Any, settings: Settings, *, now: datetime,
                         since: datetime | None) -> HealthReport:  # fmt: skip
    """Collector heartbeats (Redis), LLM budget (Redis), AI verdicts since ``since`` and dead letters (DB)."""
    items: tuple = ()
    tokens = 0
    unavailable = None
    try:
        items = await read_heartbeats(redis, settings, now)
        tokens = int(await redis.get(f"hc:llm:tokens:{now.astimezone(UTC):%Y%m%d}") or 0)
    except Exception as exc:  # noqa: BLE001 — a Redis outage must not stop the digest
        unavailable = f"Redis: {type(exc).__name__}"
    stmt = select(AiCompilation.verdicts)
    if since is not None:
        stmt = stmt.where(AiCompilation.created_at > since)
    verdicts = [v for row in (await session.scalars(stmt)).all() for v in row or []]
    dead = await session.scalar(
        select(func.count(HuntingPack.id)).where(HuntingPack.delivery_status == DeliveryStatus.DEAD_LETTER)
    )
    return HealthReport(
        items=items, llm_enabled=settings.llm_enabled, llm_tokens_today=tokens,
        llm_budget=settings.llm_daily_token_budget, ai_accepted=sum(bool(v.get("accepted")) for v in verdicts),
        ai_rejected=sum(not v.get("accepted") for v in verdicts), dead_letters=int(dead or 0), unavailable=unavailable,
    )  # fmt: skip


async def build_digest(session: AsyncSession, settings: Settings, *, prev: Marks, cap: Marks,
                       window_start: datetime | None, now: datetime, health: HealthReport) -> DigestData:  # fmt: skip
    rows = await _pack_rows(session, settings.tgbot_tenants, after=prev.max_pack_seq, upto=cap.max_pack_seq)
    cluster_ids = sorted({r[2].id for r in rows}, key=str)
    old = await _older_clusters(session, cluster_ids, settings.tgbot_tenants, prev.max_pack_seq)
    lines = build_lines(rows, old)
    clusters = {str(r[2].id): r[2] for r in rows}
    packed = {(str(r[2].id), r[1]) for r in rows}
    return DigestData(
        window_start=window_start, window_end=now, lines=tuple(lines),
        exposures=tuple(await _exposures(session, lines, clusters)), cves=tuple(_cves(lines, clusters)),
        datasets=tuple(await _datasets(session, prev, cap)), health=health,
        patches=tuple(await _patches(session, settings.tgbot_tenants, prev, cap, packed)),
    )  # fmt: skip


def digest_json(d: DigestData, rows_summary: dict[str, str]) -> bytes:
    body = {
        "window_start": d.window_start.isoformat() if d.window_start else None,
        "window_end": d.window_end.isoformat(),
        "clusters": [
            {"cluster_id": line.cluster_id, "label": defang_text(line.label), "vector": line.vector.value,
             "severity": line.severity, "confidence": line.confidence, "pack_id": line.pack_id,
             "tenants": list(line.tenants), "summary": defang_text(rows_summary.get(line.pack_id, ""))[:1500]}
            for line in d.lines
        ],
    }  # fmt: skip
    return json.dumps(body, indent=2, ensure_ascii=False, sort_keys=True).encode()


# --- send -----------------------------------------------------------------------------------------------
async def run_digest(sessionmaker: async_sessionmaker[AsyncSession], client: TelegramClient, redis: Any,
                     settings: Settings, *, now: datetime | None = None, preview_chat_id: int | None = None,
                     sleep: Callable[[float], Awaitable[None]] = asyncio.sleep) -> dict[str, Any]:  # fmt: skip
    """Scheduled digest, or a preview of the next one when ``preview_chat_id`` is given."""
    now = now or datetime.now(UTC)
    preview = preview_chat_id is not None
    if preview:
        chat_id = preview_chat_id
    elif settings.tgbot_chat_ids:
        chat_id = settings.tgbot_chat_ids[0]
    else:
        return {"status": "no_chat"}
    tz = ZoneInfo(settings.tgbot_timezone)
    async with sessionmaker() as session:
        last = await last_sent(session)
        prev = Marks(last.max_pack_seq, last.max_link_at) if last else Marks(0, None)
        window_start = last.window_end if last else None
        cap = await current_marks(session)
        health = await collect_health(session, redis, settings, now=now, since=window_start)
        data = await build_digest(session, settings, prev=prev, cap=cap, window_start=window_start, now=now,
                                  health=health)  # fmt: skip
        if data.is_empty and not preview and not settings.tgbot_send_empty_digest:
            return {"status": "empty"}
        messages = render_digest(data, top=settings.tgbot_digest_top, tz=tz, preview=preview)
        summaries = {}
        if settings.tgbot_attach_json and data.lines:
            ids = [line.pack_id for line in data.lines]
            summaries = {str(i): s for i, s in (await session.execute(
                select(HuntingPack.id, HuntingPack.payload["threat_summary"].astext).where(HuntingPack.id.in_(ids))
            )).all()}  # fmt: skip
        row = TelegramDigest(scheduled_for=now, window_start=window_start, window_end=now,
                             max_pack_seq=cap.max_pack_seq, max_link_at=cap.max_link_at,
                             status=DigestStatus.PREVIEW if preview else DigestStatus.SENDING)  # fmt: skip
        session.add(row)
        await session.commit()

        sent: list[int] = []
        try:
            for i, text in enumerate(messages):
                if i and chat_id < 0:  # groups: at least 1 s between parts
                    await sleep(1.0)
                sent += await client.send_message(chat_id, text)
            if settings.tgbot_attach_json and data.lines:
                name = f"digest-{now.astimezone(tz):%Y-%m-%d}.json"
                sent.append(await client.send_document(chat_id, name, digest_json(data, summaries),
                                                       mime="application/json"))  # fmt: skip
        except Exception as exc:  # noqa: BLE001 — recorded on the row; the window is re-covered next time
            row.error = client.scrub(scrub(f"{type(exc).__name__}: {exc}"))[:2000]
            row.message_ids = sent
            if not preview:
                row.status = DigestStatus.FAILED
            await session.commit()
            log.warning("telegram digest failed: %s", row.error)
            return {"status": "failed", "error": row.error}
        row.message_ids = sent
        if not preview:
            row.status = DigestStatus.SENT
        await session.commit()
        return {"status": row.status.value, "messages": len(sent), "clusters": len(data.lines)}


# --- Celery -----------------------------------------------------------------------------------------------
async def _digest_task(engine: AsyncEngine) -> dict[str, Any]:
    s = get_settings()
    if s.tgbot_token is None:  # checked by the task already; explicit because asserts vanish under -O
        return {"status": "disabled"}
    redis = aioredis.from_url(s.redis_url, socket_timeout=3)
    try:
        async with TelegramClient(s.tgbot_token.get_secret_value()) as client:
            return await run_digest(async_sessionmaker(engine, expire_on_commit=False), client, redis, s)
    finally:
        await redis.aclose()


@celery_app.task(name="notify.telegram_digest", soft_time_limit=600, time_limit=660)
def telegram_digest() -> dict[str, Any]:
    s = get_settings()
    if not (s.tgbot_enabled and s.tgbot_token and s.tgbot_chat_ids):
        log.info("telegram digest skipped: HC_TGBOT_ENABLED, HC_TGBOT_TOKEN or HC_TGBOT_CHAT_IDS not set")
        return {"status": "disabled"}
    with single_flight("telegram_digest", 900) as ok:
        return run_with_engine(_digest_task) if ok else {"status": "locked"}


def digest_crontabs(times: list[str], tz_name: str, today: date | None = None) -> list[crontab]:
    """Local HH:MM times -> UTC crontabs (Celery runs in UTC). Converted with today's offset, so zones with DST
    shift by an hour until beat restarts; Asia/Ho_Chi_Minh has no DST."""
    tz = ZoneInfo(tz_name)
    day = today or datetime.now(tz).date()
    utc = set()
    for t in times:
        hour, minute = (int(x) for x in t.split(":"))
        local = datetime.combine(day, time(hour, minute), tzinfo=tz).astimezone(UTC)
        utc.add((local.hour, local.minute))
    return [crontab(hour=str(h), minute=str(m)) for h, m in sorted(utc)]


_s = get_settings()
if _s.tgbot_enabled:
    celery_app.conf.beat_schedule.update(
        {
            f"telegram-digest-{i}": {"task": "notify.telegram_digest", "schedule": schedule}
            for i, schedule in enumerate(digest_crontabs(_s.tgbot_digest_times, _s.tgbot_timezone))
        }
    )
