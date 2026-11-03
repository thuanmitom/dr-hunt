from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import Boolean, CheckConstraint, DateTime, Index, String, Uuid, func, true
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, str_enum
from app.db.types import EncryptedString
from app.schemas.enums import DeliveryMode

if TYPE_CHECKING:
    from app.db.models.hunting_pack import HuntingPack


class Tenant(TimestampMixin, Base):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    slug: Mapped[str] = mapped_column(String(63), unique=True)
    display_name: Mapped[str] = mapped_column(String(255))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, server_default=true())

    # Full validated manifest (no secrets — only env-var names) + its hash for change detection.
    manifest: Mapped[dict[str, Any]] = mapped_column(JSONB)
    manifest_sha256: Mapped[str] = mapped_column(String(64))
    # Denormalised for fast "which tenants run the product in this CVE?" lookups (GIN).
    tech_stack_tags: Mapped[list[str]] = mapped_column(ARRAY(String(128)), default=list, server_default="{}")

    delivery_mode: Mapped[DeliveryMode] = mapped_column(str_enum(DeliveryMode, 16))
    webhook_url: Mapped[str | None] = mapped_column(String(2048))
    webhook_secret: Mapped[str] = mapped_column(EncryptedString())  # HMAC key, Fernet-encrypted
    api_token_sha256: Mapped[str | None] = mapped_column(String(64), unique=True)
    secret_rotated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    hunting_packs: Mapped[list[HuntingPack]] = relationship(back_populates="tenant", passive_deletes=True)

    __table_args__ = (
        CheckConstraint("delivery_mode <> 'push' OR webhook_url IS NOT NULL", name="push_requires_webhook"),
        CheckConstraint("delivery_mode <> 'pull' OR api_token_sha256 IS NOT NULL", name="pull_requires_token"),
        Index("ix_tenants_tech_stack_tags", "tech_stack_tags", postgresql_using="gin"),
    )

    def __repr__(self) -> str:
        return f"<Tenant {self.slug} mode={self.delivery_mode}>"
