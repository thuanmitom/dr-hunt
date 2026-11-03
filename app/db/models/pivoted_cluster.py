from __future__ import annotations

import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import (
    BigInteger,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Table,
    Text,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base, TimestampMixin, str_enum
from app.schemas.enums import AttackVector, ClusterStatus

if TYPE_CHECKING:
    from app.db.models.hunting_pack import HuntingPack
    from app.db.models.raw_intel_event import RawIntelEvent


# Many-to-many: one cluster aggregates many events; one event can feed several clusters.
cluster_event_links = Table(
    "cluster_event_links",
    Base.metadata,
    Column("cluster_id", Uuid, ForeignKey("pivoted_clusters.id", ondelete="CASCADE"), primary_key=True),
    Column("event_id", BigInteger, ForeignKey("raw_intel_events.id", ondelete="CASCADE"), primary_key=True),
    Column("linked_at", DateTime(timezone=True), server_default=func.now(), nullable=False),
    Index("ix_cluster_event_links_event_id", "event_id"),
)


class PivotedCluster(TimestampMixin, Base):
    """A campaign/infrastructure cluster produced by pivoting (JARM, favicon hash, shared
    certs, unpacked C2) — the unit that gets compiled into hunting packs."""

    __tablename__ = "pivoted_clusters"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    # Deterministic key for idempotent upserts, e.g. "v3:c2:evil.example" or "v2:cve:CVE-2026-1234".
    cluster_key: Mapped[str] = mapped_column(String(255), unique=True)
    attack_vector: Mapped[AttackVector] = mapped_column(str_enum(AttackVector, 48))
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("tenants.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String(512))
    summary: Mapped[str | None] = mapped_column(Text)
    status: Mapped[ClusterStatus] = mapped_column(
        str_enum(ClusterStatus, 16), default=ClusterStatus.ACTIVE, server_default=ClusterStatus.ACTIVE.value
    )

    # Scoring inputs for the Time-Decay model (Phase 3): score(t) = base * 0.5 ** (age_h / half_life_h)
    base_confidence: Mapped[int] = mapped_column(SmallInteger)
    current_confidence: Mapped[int] = mapped_column(SmallInteger)
    decay_half_life_hours: Mapped[int] = mapped_column(Integer, default=168, server_default="168")
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    # {"domains": [], "ips": [], "hashes": [], "jarm": [], "urls": [], "favicon_mmh3": []}
    observables: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    # Explainability: {"nodes": [...], "edges": [{"from":..,"to":..,"via":"jarm|favicon|cert|unpack"}]}
    pivot_graph: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, server_default="{}")
    mitre_techniques: Mapped[list[str]] = mapped_column(ARRAY(String(16)), default=list, server_default="{}")
    cve_ids: Mapped[list[str]] = mapped_column(ARRAY(String(32)), default=list, server_default="{}")
    tech_stack_tags: Mapped[list[str]] = mapped_column(ARRAY(String(128)), default=list, server_default="{}")

    merged_into_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid, ForeignKey("pivoted_clusters.id", ondelete="SET NULL")
    )
    # Aggregated anonymous feedback across tenants (feeds back into confidence).
    sighting_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    clean_count: Mapped[int] = mapped_column(Integer, default=0, server_default="0")

    events: Mapped[list[RawIntelEvent]] = relationship(secondary=cluster_event_links, back_populates="clusters")
    hunting_packs: Mapped[list[HuntingPack]] = relationship(back_populates="cluster")

    __table_args__ = (
        CheckConstraint("base_confidence BETWEEN 0 AND 100", name="base_confidence_range"),
        CheckConstraint("current_confidence BETWEEN 0 AND 100", name="current_confidence_range"),
        CheckConstraint("decay_half_life_hours > 0", name="half_life_positive"),
        CheckConstraint("last_seen_at >= first_seen_at", name="seen_order"),
        Index("ix_pivoted_clusters_status_last_seen", "status", "last_seen_at"),
        Index("ix_pivoted_clusters_tech_stack_tags", "tech_stack_tags", postgresql_using="gin"),
        Index("ix_pivoted_clusters_cve_ids", "cve_ids", postgresql_using="gin"),
        Index(
            "ix_pivoted_clusters_observables",
            "observables",
            postgresql_using="gin",
            postgresql_ops={"observables": "jsonb_path_ops"},
        ),
    )
