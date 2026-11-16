from __future__ import annotations

import asyncio
import hashlib
import logging
import uuid
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field

from app.core.config import get_settings
from app.core.signing import canonical_json
from app.schemas.enums import AttackVector, IntelSource

log = logging.getLogger(__name__)


class Observable(BaseModel):
    model_config = ConfigDict(frozen=True)
    type: str  # domain | ip | url | sha256 | jarm | favicon_mmh3 | cve | package | repo
    value: str


class IntelSignal(BaseModel):
    """What a collector emits; persisted 1:1 as a ``raw_intel_events`` row."""

    model_config = ConfigDict(extra="forbid")

    source: IntelSource
    external_id: str | None = None
    tenant_id: uuid.UUID | None = None
    attack_vector: AttackVector | None = None
    title: str | None = Field(default=None, max_length=1024)
    source_url: str | None = Field(default=None, max_length=2048)
    observed_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))
    raw_payload: dict[str, Any] = Field(default_factory=dict)
    observables: list[Observable] = Field(default_factory=list)
    redacted: bool = False

    def dedup_sha256(self) -> str:
        """Stable identity: provider id when there is one, otherwise the observable set."""
        if self.external_id:
            basis: Any = {"s": self.source.value, "id": self.external_id, "t": str(self.tenant_id or "")}
        else:
            basis = {
                "s": self.source.value,
                "t": str(self.tenant_id or ""),
                "o": sorted((o.type, o.value) for o in self.observables),
            }
        return hashlib.sha256(canonical_json(basis)).hexdigest()


def http_client(**headers: str) -> httpx.AsyncClient:
    settings = get_settings()
    return httpx.AsyncClient(
        timeout=settings.http_timeout_seconds,
        headers={"User-Agent": settings.user_agent, **headers},
        follow_redirects=False,
        limits=httpx.Limits(max_connections=10),
    )


MAX_RETRY_AFTER_SECONDS = 120


def retry_after_seconds(value: str | None, default: float, *, now: datetime | None = None) -> float:
    """``Retry-After`` as delay-seconds or as an HTTP-date (RFC 9110 §10.2.3). Anything unreadable -> ``default``."""
    if not value or not value.strip():
        return default
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value.strip())
    except (TypeError, ValueError, IndexError):
        return default
    if when.tzinfo is None:
        when = when.replace(tzinfo=UTC)
    return max(0.0, (when - (now or datetime.now(UTC))).total_seconds())


async def get_json(client: httpx.AsyncClient, url: str, *, retries: int = 3, **kwargs: Any) -> Any:
    """GET with polite back-off on 429/5xx (honours Retry-After)."""
    for attempt in range(retries + 1):
        resp = await client.get(url, **kwargs)
        if resp.status_code == 429 or resp.status_code >= 500:
            if attempt == retries:
                resp.raise_for_status()
            backoff = float(2 ** (attempt + 1))
            wait = min(retry_after_seconds(resp.headers.get("Retry-After"), backoff), MAX_RETRY_AFTER_SECONDS)
            log.warning("GET %s -> %s, retrying in %.0fs", url, resp.status_code, wait)
            await asyncio.sleep(wait)
            continue
        resp.raise_for_status()
        return resp.json()
    raise RuntimeError("unreachable")
