"""Daily retry of the GitHub enrichment for KEV entries still in the lookback window (D-71).

A KEV entry is stored once (deduplicated by CVE). When GitHub failed on that first run, or no token was set, the entry
kept empty PoC and Nuclei data, and with it a lower score, for good. This job retries those entries, at most
``max_attempts`` times each, then updates the stored event and its cluster's features and score. A cluster that was
below a tenant's delivery threshold gets its pack at the next pack build; packs already sent are not re-issued because
of a score change (substance rule).

GitHub stays enrichment only (D-54): failures are reported on the health page and never undo data found earlier.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, time, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession

from app.collectors.base import Observable
from app.collectors.edge_exploits import NO_TOKEN_NOTE, EdgeIntelClient, github_enrichment
from app.compiler.scoring import base_confidence
from app.db.models import PivotedCluster, RawIntelEvent, cluster_event_links
from app.db.session import session_scope
from app.schemas.enums import AttackVector, IntelSource

POC_FAILED, NUCLEI_FAILED = "PoC search failed", "nuclei lookup failed"
MAX_EVENTS_PER_RUN = 50  # unauthenticated GitHub allows 60 core requests an hour; one CVE can use ~10


@dataclass
class ReenrichResult:
    retried: int = 0
    improved: int = 0  # clusters whose PoC or Nuclei feature turned true
    errors: list[str] = field(default_factory=list)


def needs_retry(notes: list[str], *, has_token: bool) -> bool:
    """Retry after a real failure. A missing token alone is worth a retry only once a token is set."""
    return any(note != NO_TOKEN_NOTE or has_token for note in notes)


def merge_enrichment(payload: dict[str, Any], pocs: list[dict[str, Any]], templates: list[str], notes: list[str],
                     *, now: datetime) -> dict[str, Any]:  # fmt: skip
    """A part that failed again keeps what was stored before; a part that worked replaces it."""
    out = dict(payload)
    if not any(n.startswith(POC_FAILED) for n in notes):
        out["pocs"] = pocs
    if not any(n == NO_TOKEN_NOTE or n.startswith(NUCLEI_FAILED) for n in notes):
        out["nuclei_templates"] = templates
    out["enrichment_notes"] = notes
    out["reenrich_attempts"] = int(payload.get("reenrich_attempts", 0)) + 1
    out["reenriched_at"] = now.astimezone(UTC).isoformat()
    return out


async def candidates(session: AsyncSession, *, now: datetime, lookback_days: int, max_attempts: int,
                     has_token: bool, limit: int = MAX_EVENTS_PER_RUN) -> list[tuple[Any, str]]:  # fmt: skip
    """(event id, CVE) of KEV events in the window whose GitHub data is incomplete and still worth a retry."""
    cutoff = datetime.combine((now - timedelta(days=lookback_days)).date(), time.min, tzinfo=UTC)
    events = (
        await session.scalars(
            select(RawIntelEvent)
            .where(RawIntelEvent.source == IntelSource.CISA_KEV, RawIntelEvent.observed_at >= cutoff)
            .order_by(RawIntelEvent.observed_at.desc(), RawIntelEvent.id)
        )
    ).all()
    out = []
    for event in events:
        payload = event.raw_payload or {}
        notes = list(payload.get("enrichment_notes") or [])
        if "kev" not in payload or not event.external_id or not notes:  # truncated, or nothing missing
            continue
        if int(payload.get("reenrich_attempts", 0)) >= max_attempts or not needs_retry(notes, has_token=has_token):
            continue
        out.append((event.id, event.external_id))
    return out[:limit]


async def apply_enrichment(session: AsyncSession, event_id: Any, pocs: list[dict[str, Any]], templates: list[str],
                           notes: list[str], *, now: datetime) -> bool:  # fmt: skip
    """Store the retry result on the event and its cluster. True when the cluster gained a PoC or Nuclei feature."""
    event = await session.get(RawIntelEvent, event_id, with_for_update=True)
    if event is None:  # removed by retention meanwhile
        return False
    payload = merge_enrichment(event.raw_payload or {}, pocs, templates, notes, now=now)
    event.raw_payload = payload
    repos = [Observable(type="repo", value=p["repo"]).model_dump() for p in payload.get("pocs", []) if p["likely_fake"]]
    event.observables = [o for o in event.observables if o["type"] != "repo"] + repos
    credible = any(not p.get("likely_fake") for p in payload.get("pocs", []))
    nuclei = bool(payload.get("nuclei_templates"))
    clusters = (
        await session.scalars(
            select(PivotedCluster)
            .join(cluster_event_links, cluster_event_links.c.cluster_id == PivotedCluster.id)
            .where(cluster_event_links.c.event_id == event.id)
            .with_for_update(of=PivotedCluster)
        )
    ).all()
    improved = False
    for cluster in clusters:  # not clustered yet: the cluster builder reads the updated payload
        graph = dict(cluster.pivot_graph or {})
        features = dict(graph.get("features") or {})
        before = (bool(features.get("credible_poc")), bool(features.get("nuclei_template")))
        features["credible_poc"], features["nuclei_template"] = before[0] or credible, before[1] or nuclei
        if (features["credible_poc"], features["nuclei_template"]) == before:
            continue
        graph["features"] = features
        cluster.pivot_graph = graph
        cluster.base_confidence = base_confidence(AttackVector(cluster.attack_vector), features)
        cluster.current_confidence = cluster.base_confidence  # decayed again by the next pack build
        improved = True
    return improved


async def reenrich_kev(engine: AsyncEngine, edge: EdgeIntelClient, *, now: datetime, lookback_days: int,
                       max_attempts: int, limit: int = MAX_EVENTS_PER_RUN) -> ReenrichResult:  # fmt: skip
    """One run. GitHub calls happen outside any database transaction; each event is stored in its own."""
    async with session_scope(engine) as session:
        todo = await candidates(session, now=now, lookback_days=lookback_days, max_attempts=max_attempts,
                                has_token=edge.has_github_token, limit=limit)  # fmt: skip
    result = ReenrichResult()
    for event_id, cve in todo:
        pocs, templates, notes, failures = await github_enrichment(edge, cve)
        result.errors.extend(f for f in failures if f not in result.errors)
        async with session_scope(engine) as session:
            result.improved += await apply_enrichment(session, event_id, pocs, templates, notes, now=now)
        result.retried += 1
    return result
