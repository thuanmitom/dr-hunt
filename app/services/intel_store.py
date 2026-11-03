from __future__ import annotations

from collections.abc import Sequence

from sqlalchemy import func
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.base import IntelSignal
from app.db.models import RawIntelEvent

MAX_PAYLOAD_BYTES = 256 * 1024


async def store_signals(session: AsyncSession, signals: Sequence[IntelSignal]) -> int:
    """Insert signals idempotently (unique on source + dedup hash). Returns rows inserted."""
    if not signals:
        return 0
    rows = []
    for s in signals:
        payload = s.raw_payload
        if len(s.model_dump_json(include={"raw_payload"})) > MAX_PAYLOAD_BYTES:
            payload = {"truncated": True, "keys": sorted(payload)[:50]}
        rows.append(
            {
                "source": s.source,
                "external_id": s.external_id,
                "dedup_sha256": s.dedup_sha256(),
                "tenant_id": s.tenant_id,
                "attack_vector": s.attack_vector,
                "title": s.title,
                "source_url": s.source_url,
                "observed_at": s.observed_at,
                "raw_payload": payload,
                "observables": [o.model_dump() for o in s.observables],
                "redacted": s.redacted,
            }
        )
    stmt = (
        insert(RawIntelEvent)
        .values(rows)
        .on_conflict_do_nothing(index_elements=["source", "dedup_sha256"])
        .returning(RawIntelEvent.id)
    )
    result = await session.execute(stmt)
    return len(result.scalars().all())


async def count_events(session: AsyncSession) -> int:
    return int(await session.scalar(func.count(RawIntelEvent.id).select()) or 0)
