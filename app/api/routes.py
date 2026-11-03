"""Tenant-facing API: pull packs (bearer token) and post 1-bit sighting feedback (HMAC)."""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import ValidationError
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.crypto import sha256_hex
from app.core.signing import SignatureError, canonical_json, compute_signature, verify_signature
from app.db.models import HuntingPack, PivotedCluster, Tenant
from app.db.session import get_session
from app.schemas.enums import DeliveryStatus
from app.schemas.feedback import SightingFeedback

router = APIRouter(prefix="/api/v1")
Session = Annotated[AsyncSession, Depends(get_session)]


async def tenant_from_bearer(session: Session, authorization: Annotated[str | None, Header()] = None) -> Tenant:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "missing bearer token")
    tenant = await session.scalar(
        select(Tenant).where(Tenant.api_token_sha256 == sha256_hex(authorization[7:].strip()), Tenant.is_active)
    )
    if tenant is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid token")
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
    x_huntcompiler_tenant: Annotated[str, Header()],
    x_huntcompiler_timestamp: Annotated[str, Header()],
    x_huntcompiler_signature: Annotated[str, Header()],
) -> dict[str, str]:
    body = await request.body()
    tenant = await session.scalar(select(Tenant).where(Tenant.slug == x_huntcompiler_tenant, Tenant.is_active))
    if tenant is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown tenant")
    try:
        verify_signature(tenant.webhook_secret, body, x_huntcompiler_signature, x_huntcompiler_timestamp,
                         tolerance_seconds=get_settings().signature_tolerance_seconds)  # fmt: skip
        feedback = SightingFeedback.model_validate_json(body)
    except SignatureError as exc:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, str(exc)) from exc
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
