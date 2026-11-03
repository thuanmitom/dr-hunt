from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Identity,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, str_enum
from app.schemas.enums import AttackVector, DeliveryMode, DeliveryStatus, Severity
from app.schemas.hunting_pack import HuntingPackV2

if TYPE_CHECKING:
    from app.db.models.pivoted_cluster import PivotedCluster
    from app.db.models.tenant import Tenant


class HuntingPack(TimestampMixin, Base):
    """A compiled, tenant-specific pack. ``payload`` is the exact validated wire document."""

    __tablename__ = "hunting_packs"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)  # == payload.pack_id
    seq: Mapped[int] = mapped_column(BigInteger, Identity(always=True), unique=True)  # pull cursor
    tenant_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("tenants.id", ondelete="CASCADE"))
    cluster_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("pivoted_clusters.id", ondelete="RESTRICT"))
    version: Mapped[int] = mapped_column(Integer, default=1, server_default="1")
    supersedes_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("hunting_packs.id", ondelete="SET NULL"))

    schema_version: Mapped[str] = mapped_column(String(8))
    attack_vector: Mapped[AttackVector] = mapped_column(str_enum(AttackVector, 48))
    severity: Mapped[Severity] = mapped_column(str_enum(Severity, 16))
    confidence_score: Mapped[int] = mapped_column(SmallInteger)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    content_sha256: Mapped[str] = mapped_column(String(64))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))

    delivery_status: Mapped[DeliveryStatus] = mapped_column(str_enum(DeliveryStatus, 16))
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_http_status: Mapped[int | None] = mapped_column(SmallInteger)
    last_delivery_error: Mapped[str | None] = mapped_column(Text)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # 1-bit anonymous feedback (+ evaluable flag: telemetry was present to answer at all).
    sighting: Mapped[bool | None] = mapped_column(Boolean)
    evaluable: Mapped[bool | None] = mapped_column(Boolean)
    feedback_received_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    tenant: Mapped[Tenant] = relationship(back_populates="hunting_packs")
    cluster: Mapped[PivotedCluster] = relationship(back_populates="hunting_packs")

    __table_args__ = (
        UniqueConstraint("tenant_id", "cluster_id", "version"),
        UniqueConstraint("tenant_id", "content_sha256"),  # never deliver identical intel twice
        CheckConstraint("confidence_score BETWEEN 0 AND 100", name="confidence_range"),
        CheckConstraint("version >= 1", name="version_positive"),
        Index(
            "ix_hunting_packs_dispatch_queue",
            "next_attempt_at",
            postgresql_where=text("delivery_status IN ('pending', 'retrying')"),
        ),
        Index("ix_hunting_packs_tenant_seq", "tenant_id", "seq"),
    )

    @classmethod
    def from_contract(
        cls,
        pack: HuntingPackV2,
        *,
        tenant_id: uuid.UUID,
        cluster_id: uuid.UUID,
        delivery_mode: DeliveryMode,
        version: int = 1,
        supersedes_id: uuid.UUID | None = None,
    ) -> HuntingPack:
        assert pack.expires_at is not None  # always set by the contract validator
        return cls(
            id=pack.pack_id,
            tenant_id=tenant_id,
            cluster_id=cluster_id,
            version=version,
            supersedes_id=supersedes_id,
            schema_version=pack.schema_version,
            attack_vector=pack.attack_vector,
            severity=pack.severity,
            confidence_score=pack.confidence_score,
            payload=pack.wire_dict(),
            content_sha256=pack.content_sha256(),
            expires_at=pack.expires_at,
            delivery_status=(
                DeliveryStatus.PENDING if delivery_mode is DeliveryMode.PUSH else DeliveryStatus.AWAITING_PULL
            ),
        )

    def to_contract(self) -> HuntingPackV2:
        return HuntingPackV2.model_validate(self.payload)
