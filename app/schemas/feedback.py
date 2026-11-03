"""Sighting feedback (SOAR -> HuntCompiler). Deliberately minimal: no hit counts, hostnames,
usernames or log lines ever leave the tenant."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, field_validator


class SightingFeedback(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["1.0"] = "1.0"
    pack_id: uuid.UUID
    sighting: bool = Field(description="True if any hunting task returned at least one hit")
    evaluable: bool = Field(
        default=True,
        description="False if the tenant lacked the telemetry a task required; sighting=false is then not 'clean'.",
    )
    evaluated_at: AwareDatetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("evaluated_at")
    @classmethod
    def _to_utc(cls, v: datetime) -> datetime:
        return v.astimezone(UTC)
