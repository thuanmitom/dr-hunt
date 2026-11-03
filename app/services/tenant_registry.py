from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.crypto import sha256_hex
from app.db.models import Tenant
from app.schemas.manifest import TenantManifest

MIN_SECRET_LENGTH = 32


class ManifestSecretError(ValueError):
    pass


def _check_secret(name: str, value: str | None) -> str:
    if not value:
        raise ManifestSecretError(f"environment variable {name} is not set")
    if len(value) < MIN_SECRET_LENGTH:
        raise ManifestSecretError(f"{name} must be at least {MIN_SECRET_LENGTH} characters")
    return value


async def upsert_tenant(
    session: AsyncSession,
    manifest: TenantManifest,
    *,
    webhook_secret: str | None,
    api_token: str | None,
) -> tuple[Tenant, bool]:
    """Create or update a tenant from a validated manifest. Returns (tenant, created)."""
    secret = _check_secret(manifest.delivery.secret_env, webhook_secret)
    token_hash = None
    if manifest.delivery.api_token_env:
        token_hash = sha256_hex(_check_secret(manifest.delivery.api_token_env, api_token))

    tenant = await session.scalar(select(Tenant).where(Tenant.slug == manifest.tenant.slug))
    created = tenant is None
    if tenant is None:
        tenant = Tenant(slug=manifest.tenant.slug)
        session.add(tenant)

    if created or tenant.webhook_secret != secret:
        tenant.webhook_secret = secret
        tenant.secret_rotated_at = datetime.now(UTC)
    tenant.display_name = manifest.tenant.display_name
    tenant.manifest = manifest.model_dump(mode="json")
    tenant.manifest_sha256 = manifest.sha256()
    tenant.tech_stack_tags = list(manifest.tech_stack_tags)
    tenant.delivery_mode = manifest.delivery.mode
    tenant.webhook_url = str(manifest.delivery.webhook_url) if manifest.delivery.webhook_url else None
    tenant.api_token_sha256 = token_hash
    tenant.is_active = True

    await session.flush()
    return tenant, created
