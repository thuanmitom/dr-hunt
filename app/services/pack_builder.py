"""Cluster x tenant -> Hunting Pack v2.0. Blocklists, scores and hints are computed here, never by the LLM."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from datetime import UTC, datetime

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.collectors.edge_exploits import KEV_EDGE
from app.compiler.scoring import EXPIRY_FLOOR, decayed, severity_for, with_feedback
from app.compiler.templates import MITRE_DEFAULTS, baseline_tasks, edge_lateral_movement_tasks, safe, tenant_tasks
from app.db.models import HuntingPack, PivotedCluster, ReferenceDataset
from app.schemas.enums import AttackVector, ClusterStatus
from app.schemas.hunting_pack import AUTO_BLOCK_MIN_CONFIDENCE, HuntingPackV2, HuntingTask, PreventionBlocklist
from app.services.tenant_context import TenantContext, load_active_tenants

TTL_DAYS = {AttackVector.IDENTITY_AITM_INFOSTEALER: 7, AttackVector.CLICKFIX_FILELESS: 14,
            AttackVector.EDGE_DEVICE_EXPLOIT: 30}  # fmt: skip
AiTasks = Callable[[PivotedCluster], Awaitable[list[HuntingTask]]]


def eligible(cluster: PivotedCluster, tenant: TenantContext) -> bool:
    if cluster.attack_vector not in tenant.manifest.hunting.enabled_vectors:
        return False
    if cluster.tenant_id is not None:
        return cluster.tenant_id == tenant.id
    if cluster.attack_vector is AttackVector.EDGE_DEVICE_EXPLOIT:
        return bool(set(cluster.tech_stack_tags) & set(tenant.manifest.tech_stack_tags))
    return True


def kev_is_edge_for(cluster: PivotedCluster, tenant: TenantContext) -> bool:
    """D-70: the edge-appliance hunts apply when the KEV product is internet-facing, or when this tenant lists the
    matched product in its login portals. Clusters built before D-70 have no ``kev_class``: old behaviour."""
    features = (cluster.pivot_graph or {}).get("features") or {}
    if features.get("kev_class", KEV_EDGE) == KEV_EDGE:
        return True
    portals = {p.product for p in tenant.manifest.login_portals if p.product}
    return bool(set(cluster.tech_stack_tags) & set(tenant.manifest.tech_stack_tags) & portals)


def substance_sha256(payload: dict) -> str:
    """Identity of a pack for re-issue decisions: confidence drift alone never triggers a new version."""
    import hashlib

    from app.core.signing import canonical_json

    body = {k: v for k, v in payload.items() if k not in {"pack_id", "timestamp", "expires_at", "confidence_score"}}
    return hashlib.sha256(canonical_json(body)).hexdigest()


def _summary(cluster: PivotedCluster) -> str:
    text = cluster.title
    if ai := (cluster.pivot_graph or {}).get("ai_summary"):
        text += f"\n[AI-assisted summary] {ai['text']}"
    return text[:4000]


async def load_reference(session: AsyncSession) -> dict[str, list[dict]]:
    rows = (await session.scalars(select(ReferenceDataset))).all()
    return {r.name: r.records for r in rows}


async def build_packs(session: AsyncSession, *, ai_tasks: AiTasks | None = None, now: datetime | None = None) -> int:
    now = now or datetime.now(UTC)
    tenants = await load_active_tenants(session)
    ref = await load_reference(session)
    created = 0
    clusters = (
        await session.scalars(select(PivotedCluster).where(PivotedCluster.status == ClusterStatus.ACTIVE))
    ).all()
    for cluster in clusters:
        conf = with_feedback(
            decayed(cluster.base_confidence, cluster.last_seen_at, now, cluster.decay_half_life_hours),
            cluster.sighting_count,
        )
        cluster.current_confidence = conf
        if conf < EXPIRY_FLOOR:
            cluster.status = ClusterStatus.EXPIRED
            continue
        targets = [t for t in tenants if eligible(cluster, t) and conf >= t.manifest.hunting.min_confidence_to_deliver]
        if not targets:
            continue
        lookback = 30 if cluster.attack_vector is AttackVector.EDGE_DEVICE_EXPLOIT else 14
        obs = cluster.observables or {}
        is_v2 = cluster.attack_vector is AttackVector.EDGE_DEVICE_EXPLOIT
        base = baseline_tasks(cluster.attack_vector, obs, lookback, ref, edge_hunts=False)
        edge = safe(edge_lateral_movement_tasks, lookback) if is_v2 else []
        ai = await ai_tasks(cluster) if ai_tasks is not None else []
        blocklist = PreventionBlocklist(
            ttl_days=TTL_DAYS.get(cluster.attack_vector, 14),
            domains=obs.get("domains_block", []),
            ips=obs.get("ips_block", []),
            hashes=obs.get("hashes", [])[:5000],
        )
        for tenant in targets:
            # same task order as before D-70: templates, edge hunts, AI tasks, tenant tasks
            tasks = base + (edge if is_v2 and kev_is_edge_for(cluster, tenant) else []) + ai
            tasks += tenant_tasks(cluster.attack_vector, obs, tenant.manifest.approved_rmm_tools, lookback, ref)
            if not tasks:  # e.g. an endpoint KEV without AI tasks: listed in the digest as a patch reminder instead
                continue
            accounts = obs.get("accounts", []) if cluster.tenant_id == tenant.id else []
            auto_block = (
                tenant.manifest.hunting.allow_auto_block_hint
                and conf >= AUTO_BLOCK_MIN_CONFIDENCE
                and not blocklist.is_empty()
            )
            pack = HuntingPackV2(
                attack_vector=cluster.attack_vector,
                severity=severity_for(cluster.attack_vector, conf),
                confidence_score=conf,
                mitre_attack=MITRE_DEFAULTS[cluster.attack_vector],
                threat_summary=_summary(cluster),
                prevention_blocklist=blocklist,
                internal_hunting_tasks=tasks[:25],
                affected_accounts=accounts[:1000],
                soar_playbook_hints={
                    "auto_block_pre_iocs": auto_block,
                    # exposed credentials are an incident on their own: notify even with zero hits
                    "notify_only_on_sighting": not accounts,
                    "suggested_remediation": (
                        ["Resolve affected_accounts refs against the directory; reset passwords and revoke sessions."]
                        if accounts
                        else []
                    ),
                },
                timestamp=now,
            )
            exists = await session.scalar(
                select(HuntingPack.id).where(
                    HuntingPack.tenant_id == tenant.id, HuntingPack.content_sha256 == pack.content_sha256()
                )
            )
            if exists:
                continue
            prev = await session.scalar(
                select(HuntingPack)
                .where(HuntingPack.tenant_id == tenant.id, HuntingPack.cluster_id == cluster.id)
                .order_by(HuntingPack.version.desc())
                .limit(1)
            )
            if prev is not None and substance_sha256(prev.payload) == substance_sha256(pack.wire_dict()):
                continue
            session.add(
                HuntingPack.from_contract(
                    pack,
                    tenant_id=tenant.id,
                    cluster_id=cluster.id,
                    delivery_mode=tenant.manifest.delivery.mode,
                    version=(prev.version + 1) if prev else 1,
                    supersedes_id=prev.id if prev else None,
                )  # fmt: skip
            )
            await session.flush()
            created += 1
    return created


async def pack_count(session: AsyncSession) -> int:
    return int(await session.scalar(select(func.count(HuntingPack.id))) or 0)
