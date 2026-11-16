"""Tenant-facing API: pull packs (bearer token) and post 1-bit sighting feedback (HMAC)."""

from __future__ import annotations

import secrets
import time
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.ratelimit import RateLimiter, client_ip, get_limiter, too_many
from app.core.config import get_settings
from app.core.crypto import sha256_hex
from app.core.signing import SignatureError, canonical_json, compute_signature, verify_signature
from app.db.models import HuntingPack, PivotedCluster, Tenant
from app.db.session import get_session
from app.schemas.enums import DeliveryStatus
from app.schemas.feedback import SightingFeedback

router = APIRouter(prefix="/api/v1")
Session = Annotated[AsyncSession, Depends(get_session)]
Limiter = Annotated[RateLimiter, Depends(get_limiter)]
# Verifies feedback for an unknown tenant slug, so that it fails exactly like a wrong signature (no enumeration, D-56).
_UNKNOWN_TENANT_SECRET = secrets.token_hex(32)


async def _check_ip(request: Request, limiter: RateLimiter) -> None:
    if retry := await limiter.ip_blocked(client_ip(request)):
        raise too_many(retry, "too many failed authentications")


async def _denied(request: Request, limiter: RateLimiter, detail: str) -> HTTPException:
    await limiter.auth_failed(client_ip(request))
    return HTTPException(status.HTTP_401_UNAUTHORIZED, detail)


async def _admit(limiter: RateLimiter, tenant: Tenant) -> None:
    if retry := await limiter.tenant_over_limit(tenant.slug):
        raise too_many(retry)


async def tenant_from_bearer(request: Request, session: Session, limiter: Limiter,
                             authorization: Annotated[str | None, Header()] = None) -> Tenant:  # fmt: skip
    await _check_ip(request, limiter)
    if not authorization or not authorization.startswith("Bearer "):
        raise await _denied(request, limiter, "missing bearer token")
    tenant = await session.scalar(
        select(Tenant).where(Tenant.api_token_sha256 == sha256_hex(authorization[7:].strip()), Tenant.is_active)
    )
    if tenant is None:
        raise await _denied(request, limiter, "invalid token")
    await _admit(limiter, tenant)
    return tenant


@router.get("/packs")
async def pull_packs(
    session: Session,
    tenant: Annotated[Tenant, Depends(tenant_from_bearer)],
    after: Annotated[int, Query(ge=0)] = 0,
    limit: Annotated[int, Query(ge=1, le=100)] = 50,
) -> dict[str, Any]:
    now = datetime.now(UTC)
    packs = (
        await session.scalars(
            select(HuntingPack)
            .where(
                HuntingPack.tenant_id == tenant.id,
                HuntingPack.seq > after,
                HuntingPack.expires_at > now,
                HuntingPack.delivery_status.in_([DeliveryStatus.AWAITING_PULL, DeliveryStatus.PULLED]),
            )
            .order_by(HuntingPack.seq)
            .limit(limit)
        )
    ).all()
    ts = int(time.time())
    items = []
    for p in packs:
        items.append({"seq": p.seq, "timestamp": ts, "signature": compute_signature(tenant.webhook_secret, ts,
                      canonical_json(p.payload)), "pack": p.payload})  # fmt: skip
        if p.delivery_status is DeliveryStatus.AWAITING_PULL:
            p.delivery_status, p.delivered_at = DeliveryStatus.PULLED, now
    await session.commit()
    return {"items": items, "next_cursor": packs[-1].seq if packs else after}


@router.post("/feedback")
async def post_feedback(
    request: Request,
    session: Session,
    limiter: Limiter,
    x_huntcompiler_tenant: Annotated[str, Header()],
    x_huntcompiler_timestamp: Annotated[str, Header()],
    x_huntcompiler_signature: Annotated[str, Header()],
) -> dict[str, str]:
    await _check_ip(request, limiter)
    body = await request.body()
    tenant = await session.scalar(select(Tenant).where(Tenant.slug == x_huntcompiler_tenant, Tenant.is_active))
    # An unknown slug is verified against a random secret: same work, same error as a wrong signature.
    secret = tenant.webhook_secret if tenant is not None else _UNKNOWN_TENANT_SECRET
    try:
        verify_signature(secret, body, x_huntcompiler_signature, x_huntcompiler_timestamp,
                         tolerance_seconds=get_settings().signature_tolerance_seconds)  # fmt: skip
    except SignatureError as exc:
        raise await _denied(request, limiter, str(exc)) from exc
    if tenant is None:  # unreachable with a random secret; kept as a hard stop
        raise await _denied(request, limiter, "signature mismatch")
    await _admit(limiter, tenant)
    try:
        feedback = SightingFeedback.model_validate_json(body)
    except ValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "invalid feedback body") from exc
    pack = await session.scalar(
        select(HuntingPack).where(HuntingPack.id == feedback.pack_id, HuntingPack.tenant_id == tenant.id)
    )
    if pack is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown pack")
    if pack.feedback_received_at is not None:
        return {"status": "duplicate"}
    pack.sighting, pack.evaluable, pack.feedback_received_at = feedback.sighting, feedback.evaluable, datetime.now(UTC)
    column = PivotedCluster.sighting_count if feedback.sighting else PivotedCluster.clean_count
    if feedback.sighting or feedback.evaluable:
        await session.execute(update(PivotedCluster).where(PivotedCluster.id == pack.cluster_id)
                              .values({column.key: column + 1}))  # fmt: skip
    await session.commit()
    return {"status": "recorded"}
