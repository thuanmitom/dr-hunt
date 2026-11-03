from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, DateTime, Index, Text, Uuid
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin, str_enum
from app.schemas.enums import DigestStatus


class TelegramDigest(TimestampMixin, Base):
    """One Telegram digest attempt or preview. The high-water marks of the newest *sent* row define the next
    window: ``max_pack_seq`` (hunting_packs.seq) and ``max_link_at`` (cluster_event_links.linked_at). A failed
    attempt or a preview never moves them (TELEGRAM.md §4, §6)."""

    __tablename__ = "telegram_digests"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    scheduled_for: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    window_start: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))  # None: first digest
    window_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    max_pack_seq: Mapped[int] = mapped_column(BigInteger, default=0, server_default="0")
    max_link_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    status: Mapped[DigestStatus] = mapped_column(str_enum(DigestStatus, 16))
    message_ids: Mapped[list[int]] = mapped_column(ARRAY(BigInteger), default=list, server_default="{}")
    error: Mapped[str | None] = mapped_column(Text)  # token-scrubbed

    __table_args__ = (Index("ix_telegram_digests_status_created", "status", "created_at"),)
