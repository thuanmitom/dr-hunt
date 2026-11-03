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
    String,
    UniqueConstraint,
    Uuid,
    false,
    func,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, str_enum
from app.schemas.enums import AttackVector, EventStatus, IntelSource

if TYPE_CHECKING:
    from app.db.models.pivoted_cluster import PivotedCluster


class RawIntelEvent(Base):
    """One external signal (a matched certificate, a URLScan verdict, a KEV entry, a PoC
    commit...). Only *matched/relevant* signals are stored — never the full firehose."""

    __tablename__ = "raw_intel_events"

    id: Mapped[int] = mapped_column(BigInteger, Identity(always=True), primary_key=True)
    source: Mapped[IntelSource] = mapped_column(str_enum(IntelSource))
    external_id: Mapped[str | None] = mapped_column(String(512))  # CVE id, urlscan uuid, repo/sha...
    dedup_sha256: Mapped[str] = mapped_column(String(64))
    # Set when the signal targets a specific tenant (brand lookalike, leak mention).
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("tenants.id", ondelete="CASCADE"))
    attack_vector: Mapped[AttackVector | None] = mapped_column(str_enum(AttackVector, 48))

    title: Mapped[str | None] = mapped_column(String(1024))
    source_url: Mapped[str | None] = mapped_column(String(2048))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())

    raw_payload: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict)
    # [{"type": "domain|ip|url|sha256|jarm|favicon_mmh3|cve|package", "value": "..."}]
    observables: Mapped[list[dict[str, str]]] = mapped_column(JSONB, default=list, server_default="[]")
    # True when credential material was redacted before persisting (stealer logs, leaks).
    redacted: Mapped[bool] = mapped_column(Boolean, default=False, server_default=false())

    status: Mapped[EventStatus] = mapped_column(
        str_enum(EventStatus, 16), default=EventStatus.NEW, server_default=EventStatus.NEW.value
    )
    status_reason: Mapped[str | None] = mapped_column(String(512))
    attempts: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    processed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    clusters: Mapped[list[PivotedCluster]] = relationship(secondary="cluster_event_links", back_populates="events")

    __table_args__ = (
        UniqueConstraint("source", "dedup_sha256"),
        CheckConstraint("char_length(dedup_sha256) = 64", name="dedup_sha256_len"),
        Index("ix_raw_intel_events_pending", "ingested_at", postgresql_where=text("status IN ('new', 'failed')")),
        Index("ix_raw_intel_events_tenant_id", "tenant_id"),
        Index(
            "ix_raw_intel_events_observables",
            "observables",
            postgresql_using="gin",
            postgresql_ops={"observables": "jsonb_path_ops"},
        ),
    )
