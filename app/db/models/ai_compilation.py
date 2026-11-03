from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class AiCompilation(TimestampMixin, Base):
    """Audit + cache of every LLM call: what went in (hash, size, redactions), what came out,
    and why each proposed rule was accepted or rejected."""

    __tablename__ = "ai_compilations"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    cluster_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("pivoted_clusters.id", ondelete="CASCADE"))
    provider: Mapped[str] = mapped_column(String(32))
    model: Mapped[str] = mapped_column(String(128))
    prompt_version: Mapped[str] = mapped_column(String(32))
    input_sha256: Mapped[str] = mapped_column(String(64))
    input_chars: Mapped[int] = mapped_column(Integer)
    redactions: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    status: Mapped[str] = mapped_column(String(24))
    prompt_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    output_tokens: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    raw_output: Mapped[dict[str, Any] | None] = mapped_column(JSONB)
    verdicts: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, server_default="[]")
    accepted_tasks: Mapped[list[dict[str, Any]]] = mapped_column(JSONB, default=list, server_default="[]")
    error: Mapped[str | None] = mapped_column(Text)

    __table_args__ = (
        UniqueConstraint("cluster_id", "input_sha256", "prompt_version", "model"),
        Index("ix_ai_compilations_cluster_created", "cluster_id", "created_at"),
    )
