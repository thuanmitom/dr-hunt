"""Data retention (D-57): raw intelligence and AI audit rows do not grow forever.

* ``raw_intel_events`` older than ``retention_raw_event_days`` (by ingestion time) are deleted unless they belong to a
  cluster that is still active. Their cluster links go with them (``ON DELETE CASCADE``); clusters and packs stay.
* ``ai_compilations`` older than ``retention_ai_compilation_days`` are deleted.
A value of 0 keeps that table forever. Packs, clusters, tenants, reference datasets and digests are never purged.
"""

from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AiCompilation, PivotedCluster, RawIntelEvent
from app.db.models.pivoted_cluster import cluster_event_links
from app.schemas.enums import ClusterStatus


async def purge_old_data(session: AsyncSession, *, now: datetime, raw_event_days: int,
                         ai_compilation_days: int) -> dict[str, int]:  # fmt: skip
    deleted = {"raw_intel_events": 0, "ai_compilations": 0}
    if raw_event_days > 0:
        in_active_cluster = (
            select(cluster_event_links.c.event_id)
            .join(PivotedCluster, PivotedCluster.id == cluster_event_links.c.cluster_id)
            .where(PivotedCluster.status == ClusterStatus.ACTIVE)
        )
        result = await session.execute(
            delete(RawIntelEvent).where(
                RawIntelEvent.ingested_at < now - timedelta(days=raw_event_days),
                RawIntelEvent.id.not_in(in_active_cluster),
            )
        )
        deleted["raw_intel_events"] = result.rowcount or 0
    if ai_compilation_days > 0:
        result = await session.execute(
            delete(AiCompilation).where(AiCompilation.created_at < now - timedelta(days=ai_compilation_days))
        )
        deleted["ai_compilations"] = result.rowcount or 0
    return deleted
