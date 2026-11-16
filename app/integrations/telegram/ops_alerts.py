"""Opt-in operations alerts (D-65): tell the owner when a collector or job keeps failing or stops reporting.

Off unless ``HC_TGBOT_OPS_ALERTS=true``. These messages carry **no intelligence**: only the job's label, its state and
the short heartbeat note (an exception type or a partial-failure note such as "GitHub PoC search: HTTP 403"). The
digest-only rule for intelligence is unchanged.

* A job is a problem when it has failed ``HC_TGBOT_OPS_ALERT_AFTER_FAILURES`` runs in a row (default 3), or when it is
  stale (no success for more than twice its interval). ``unknown`` and ``not_configured`` never alert.
* One alert per job per ``HC_TGBOT_OPS_ALERT_COOLDOWN_HOURS`` (default 6); a "recovered" message when it is ok again.
* Sent to the single configured destination (``HC_TGBOT_CHAT_IDS``), like the digest.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from zoneinfo import ZoneInfo

import redis.asyncio as aioredis
from celery.schedules import crontab
from sqlalchemy.ext.asyncio import AsyncEngine

from app.core.config import Settings, get_settings
from app.integrations.telegram.client import TelegramClient
from app.integrations.telegram.format import escape
from app.worker import health
from app.worker.celery_app import celery_app
from app.worker.runtime import run_with_engine, single_flight

log = logging.getLogger(__name__)
OPEN_KEY = "hc:ops:open:{}"  # present while an alert is open for the job
SENT_KEY = "hc:ops:sent:{}"  # cooldown marker, expires after the cooldown


@dataclass(frozen=True, slots=True)
class OpsEvent:
    name: str
    label: str
    kind: str  # "problem" | "recovered"
    state: str
    failures: int
    note: str | None
    last_success: datetime | None


def ops_events(items: Sequence[tuple[health.HealthItem, int]], open_jobs: set[str], *,
               min_failures: int) -> list[OpsEvent]:  # fmt: skip
    """Pure decision: which jobs to announce now. ``items`` pairs each heartbeat with its consecutive failures."""
    events = []
    for item, failures in items:
        problem = (item.state == "failing" and failures >= min_failures) or item.state == "stale"
        if problem:
            events.append(OpsEvent(item.name, item.label, "problem", item.state, failures, item.note,
                                   item.last_success))  # fmt: skip
        elif item.name in open_jobs and item.state == "ok":
            events.append(OpsEvent(item.name, item.label, "recovered", item.state, 0, None, item.last_success))
    return events


def render_ops(event: OpsEvent, tz: ZoneInfo) -> str:
    label = escape(event.label)
    if event.kind == "recovered":
        return f"✅ <b>Ops: recovered</b>\n{label} is OK again."
    if event.state == "stale":
        since = event.last_success.astimezone(tz).strftime("%Y-%m-%d %H:%M") if event.last_success else "never"
        detail = f"no successful run since {escape(since)}"
    else:
        detail = f"failed {event.failures} runs in a row"
    note = f"\nLast error: <code>{escape(event.note[:200])}</code>" if event.note else ""
    return f"⚠️ <b>Ops alert</b>\n{label} is {escape(event.state)}: {detail}.{note}\n<i>Check with /status.</i>"


def _text(v: Any) -> str:
    return v.decode() if isinstance(v, bytes) else str(v)


async def run_ops_alerts(client: TelegramClient, redis: Any, settings: Settings, *,
                         now: datetime | None = None) -> dict[str, Any]:  # fmt: skip
    if not settings.tgbot_ops_alerts:
        return {"status": "disabled"}
    if not settings.tgbot_chat_ids:
        return {"status": "no_chat"}
    now = now or datetime.now(UTC)
    items, open_jobs = [], set()
    for src in health.sources(settings):
        raw = {_text(k): _text(v) for k, v in (await redis.hgetall(health.KEY.format(src.name))).items()}
        items.append((health.derive(src, raw, now), int(raw.get("consecutive_failures") or 0)))
        if await redis.get(OPEN_KEY.format(src.name)):
            open_jobs.add(src.name)
    tz = ZoneInfo(settings.tgbot_timezone)
    chat_id = settings.tgbot_chat_ids[0]
    sent = 0
    for event in ops_events(items, open_jobs, min_failures=settings.tgbot_ops_alert_after_failures):
        if event.kind == "problem" and await redis.get(SENT_KEY.format(event.name)):
            continue  # still in its cooldown
        await client.send_message(chat_id, render_ops(event, tz))
        sent += 1
        if event.kind == "problem":
            await redis.set(SENT_KEY.format(event.name), "1", ex=settings.tgbot_ops_alert_cooldown_hours * 3600)
            await redis.set(OPEN_KEY.format(event.name), event.state)
        else:
            await redis.delete(OPEN_KEY.format(event.name), SENT_KEY.format(event.name))
    return {"status": "ok", "sent": sent}


# --- Celery -----------------------------------------------------------------------------------------------
async def _ops_task(engine: AsyncEngine) -> dict[str, Any]:  # engine unused: heartbeats live in Redis
    s = get_settings()
    if s.tgbot_token is None:
        return {"status": "disabled"}
    redis = aioredis.from_url(s.redis_url, socket_timeout=3)
    try:
        async with TelegramClient(s.tgbot_token.get_secret_value()) as client:
            return await run_ops_alerts(client, redis, s)
    finally:
        await redis.aclose()


@celery_app.task(name="notify.ops_alerts", soft_time_limit=120, time_limit=150)
def ops_alerts() -> dict[str, Any]:
    s = get_settings()
    if not (s.tgbot_enabled and s.tgbot_ops_alerts and s.tgbot_token and s.tgbot_chat_ids):
        return {"status": "disabled"}
    with single_flight("ops_alerts", 240) as ok:
        return run_with_engine(_ops_task) if ok else {"status": "locked"}


def ops_schedule(settings: Settings) -> dict[str, dict[str, Any]]:
    """The beat entry exists only when the alerts are switched on."""
    if not (settings.tgbot_enabled and settings.tgbot_ops_alerts):
        return {}
    return {"telegram-ops-alerts": {"task": "notify.ops_alerts", "schedule": crontab(minute="*/5")}}


celery_app.conf.beat_schedule.update(ops_schedule(get_settings()))
