"""Collector heartbeats for the Telegram Health section (TELEGRAM.md §4).

One Redis hash per scheduled job, ``hc:health:<name>``, written by the job itself:
``state`` (ok | failing | not_configured), ``last_success_at``, ``last_failure_at``, ``last_error`` (exception type
or a short partial-failure note, never a raw message: messages can carry URLs or keys). Readers derive two more
states: ``stale`` (no success for more than 2x the job's interval) and ``unknown`` (never ran).
Redis already runs with AOF; no database table is involved.
"""

from __future__ import annotations

import logging
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

import redis

from app.core.config import Settings, get_settings

log = logging.getLogger(__name__)
KEY = "hc:health:{}"


class Outcome(StrEnum):
    OK = "ok"
    FAILING = "failing"
    NOT_CONFIGURED = "not_configured"


class NotConfigured(Exception):  # noqa: N818 — a state, not an error
    """Raised by a job that skips itself because its API key or settings are missing."""


@dataclass(frozen=True, slots=True)
class Source:
    name: str
    label: str
    interval_seconds: int


def sources(settings: Settings) -> tuple[Source, ...]:
    """Every heartbeat the digest reports, with the interval it is expected to run at."""
    every = settings.collector_interval_minutes * 60
    return (
        Source("urlscan_sweep", "URLScan", every),
        Source("edge_exploit_sweep", "Edge exploits (KEV/EPSS/GitHub)", every),
        Source("telegram_sweep", "Telegram CTI", every),
        Source("hibp_sweep", "HIBP", 24 * 3600),
        Source("malwarebazaar_sweep", "MalwareBazaar", 2 * 3600),
        Source("reference_sync", "Reference datasets", settings.reference_sync_hours * 3600),
        Source("certstream", "CertStream", 5 * 60),
        Source("cluster_events", "Clustering", 5 * 60),
        Source("build_packs", "Pack building", 10 * 60),
        Source("deliver_due", "Push dispatch", 60),
    )


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat()


def record(name: str, outcome: Outcome, note: str | None = None, *, client: Any = None,
           now: datetime | None = None) -> None:  # fmt: skip
    """Best effort: a Redis problem is logged, never raised into the job."""
    ts = _iso(now or datetime.now(UTC))
    fields = {"state": outcome.value, "updated_at": ts}
    if outcome is Outcome.OK:
        fields |= {"last_success_at": ts, "last_error": ""}
    elif outcome is Outcome.FAILING:
        fields |= {"last_failure_at": ts, "last_error": (note or "")[:300]}
    else:
        fields |= {"last_error": (note or "")[:300]}
    own = client is None
    c = client or redis.Redis.from_url(get_settings().redis_url, socket_timeout=3)
    try:
        c.hset(KEY.format(name), mapping=fields)
    except redis.RedisError as exc:
        log.warning("health heartbeat %s not recorded: %s", name, type(exc).__name__)
    finally:
        if own:
            c.close()


@dataclass
class Heartbeat:
    failures: list[str] = field(default_factory=list)

    def fail(self, note: str) -> None:
        """A partial failure: the job finished, but part of it did not work (reported as failing)."""
        self.failures.append(note)


@contextmanager
def track(name: str, *, client: Any = None) -> Iterator[Heartbeat]:
    """Wraps one scheduled job run. ``NotConfigured`` is recorded and swallowed; other exceptions are recorded
    (type only) and re-raised."""
    hb = Heartbeat()
    try:
        yield hb
    except NotConfigured as exc:
        record(name, Outcome.NOT_CONFIGURED, str(exc), client=client)
        return
    except Exception as exc:
        record(name, Outcome.FAILING, type(exc).__name__, client=client)
        raise
    if hb.failures:
        record(name, Outcome.FAILING, "; ".join(hb.failures), client=client)
    else:
        record(name, Outcome.OK, client=client)


@dataclass(frozen=True, slots=True)
class HealthItem:
    name: str
    label: str
    state: str  # ok | failing | not_configured | stale | unknown
    last_success: datetime | None
    last_failure: datetime | None
    note: str | None

    @property
    def is_problem(self) -> bool:
        return self.state in ("failing", "stale")


class AsyncHashReader(Protocol):
    async def hgetall(self, name: str) -> dict[Any, Any]: ...


def _text(v: Any) -> str:
    return v.decode() if isinstance(v, bytes) else str(v)


def _parse(v: str | None) -> datetime | None:
    try:
        return datetime.fromisoformat(v) if v else None
    except ValueError:
        return None


def derive(source: Source, fields: dict[str, str], now: datetime) -> HealthItem:
    last_ok, last_fail = _parse(fields.get("last_success_at")), _parse(fields.get("last_failure_at"))
    state = fields.get("state")
    if not fields:
        derived = "unknown"
    elif state == Outcome.NOT_CONFIGURED:
        derived = "not_configured"
    elif last_fail and (last_ok is None or last_fail >= last_ok):
        derived = "failing"
    elif last_ok and (now - last_ok).total_seconds() > 2 * source.interval_seconds:
        derived = "stale"
    else:
        derived = "ok"
    return HealthItem(source.name, source.label, derived, last_ok, last_fail, fields.get("last_error") or None)


async def read_heartbeats(client: AsyncHashReader, settings: Settings, now: datetime) -> tuple[HealthItem, ...]:
    items = []
    for src in sources(settings):
        raw = await client.hgetall(KEY.format(src.name))
        items.append(derive(src, {_text(k): _text(v) for k, v in raw.items()}, now))
    return tuple(items)
