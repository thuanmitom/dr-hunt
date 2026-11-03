from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Integer, String, Uuid
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TimestampMixin


class ReferenceDataset(TimestampMixin, Base):
    """Latest normalised copy of a public reference dataset (LOLDrivers, LOLRMM, HijackLibs, OSV MAL)."""

    __tablename__ = "reference_datasets"

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    version: Mapped[str] = mapped_column(String(64))
    record_count: Mapped[int] = mapped_column(Integer)
    records: Mapped[list[dict[str, Any]]] = mapped_column(JSONB)
    fetched_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
