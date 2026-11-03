"""Push delivery with HMAC signing, exponential back-off and a dead-letter state."""

from __future__ import annotations

import random
from datetime import UTC, datetime, timedelta

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.signing import build_signed_headers, canonical_json
from app.db.models import HuntingPack, Tenant
from app.schemas.enums import DeliveryStatus
from app.schemas.manifest import TenantManifest

RETRYABLE = {408, 425, 429}
MAX_BACKOFF = 3600


def backoff_seconds(attempt: int) -> float:
    return min(MAX_BACKOFF, 30 * 2 ** max(0, attempt - 1)) * random.uniform(0.8, 1.2)


async def deliver_due(session: AsyncSession, client: httpx.AsyncClient, *, batch: int = 20,
                      now: datetime | None = None) -> dict[str, int]:  # fmt: skip
    now = now or datetime.now(UTC)
    counts = {"delivered": 0, "retrying": 0, "dead_letter": 0, "skipped": 0}
    packs = (
        await session.scalars(
            select(HuntingPack)
            .where(
                HuntingPack.delivery_status.in_([DeliveryStatus.PENDING, DeliveryStatus.RETRYING]),
                or_(HuntingPack.next_attempt_at.is_(None), HuntingPack.next_attempt_at <= now),
            )
            .order_by(HuntingPack.created_at)
            .limit(batch)
            .with_for_update(skip_locked=True)
        )
    ).all()
    for pack in packs:
        if pack.expires_at <= now:
            pack.delivery_status = DeliveryStatus.SKIPPED
            counts["skipped"] += 1
            continue
        tenant = await session.get(Tenant, pack.tenant_id)
        assert tenant is not None and tenant.webhook_url
        delivery = TenantManifest.model_validate(tenant.manifest).delivery
        body = canonical_json(pack.payload)
        headers = build_signed_headers(tenant.webhook_secret, body, pack_id=str(pack.id), tenant_slug=tenant.slug)
        pack.delivery_attempts += 1
        try:
            resp = await client.post(
                tenant.webhook_url, content=body, headers=headers, timeout=delivery.timeout_seconds
            )
            pack.last_http_status = resp.status_code
            retry = resp.status_code in RETRYABLE or resp.status_code >= 500
            ok = 200 <= resp.status_code < 300
            pack.last_delivery_error = None if ok else resp.text[:500]
        except httpx.HTTPError as exc:
            ok, retry = False, True
            pack.last_delivery_error = f"{type(exc).__name__}: {str(exc)[:300]}"
        if ok:
            pack.delivery_status, pack.delivered_at, pack.next_attempt_at = DeliveryStatus.DELIVERED, now, None
        elif retry and pack.delivery_attempts < delivery.max_attempts:
            pack.delivery_status = DeliveryStatus.RETRYING
            pack.next_attempt_at = now + timedelta(seconds=backoff_seconds(pack.delivery_attempts))
        else:
            pack.delivery_status = DeliveryStatus.DEAD_LETTER
        counts[pack.delivery_status.value if pack.delivery_status.value in counts else "dead_letter"] += 1
    return counts
