from __future__ import annotations

import uuid
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Tenant
from app.schemas.manifest import TenantManifest


@dataclass(frozen=True, slots=True)
class TenantContext:
    id: uuid.UUID
    slug: str
    manifest: TenantManifest


async def load_active_tenants(session: AsyncSession) -> list[TenantContext]:
    rows = await session.scalars(select(Tenant).where(Tenant.is_active.is_(True)))
    return [TenantContext(t.id, t.slug, TenantManifest.model_validate(t.manifest)) for t in rows]
