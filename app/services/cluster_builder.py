"""Groups NEW events into pivoted clusters with deterministic keys and features."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import or_, select
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.compiler.scoring import DEFAULT_HALF_LIFE_HOURS, base_confidence
from app.db.models import PivotedCluster, RawIntelEvent, cluster_event_links
from app.processors.whitelist_filter import Action, WhitelistFilter, registrable
from app.schemas.enums import AttackVector, ClusterStatus, EventStatus, IntelSource

ENRICHMENT_GRACE = timedelta(minutes=30)
OBS_KEYS = ("domains_block", "domains_hunt", "ips_block", "ips_hunt", "urls", "hashes")
DATASET_CLUSTERS = {
    IntelSource.LOLDRIVERS: "v5:reference",
    IntelSource.HIJACKLIBS: "v5:reference",
    IntelSource.LOLRMM: "v4:reference",
    IntelSource.OSV: "v6:reference",
}


def _observables(event: RawIntelEvent, wl: WhitelistFilter) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {k: [] for k in OBS_KEYS}
    domains = [o["value"] for o in event.observables if o["type"] == "domain"]
    ips = [o["value"] for o in event.observables if o["type"] == "ip"]
    out["urls"] = [o["value"] for o in event.observables if o["type"] == "url"]
    out["hashes"] = [o["value"].lower() for o in event.observables if o["type"] == "sha256" and len(o["value"]) == 64]
    for action, results in wl.partition(domains, ips).items():
        for r in results:
            if action is Action.BLOCK:
                out[f"{r.kind}s_block"].append(r.value)
            elif action is Action.HUNT_ONLY:
                out[f"{r.kind}s_hunt"].append(r.value)
    return out


def derive(event: RawIntelEvent, obs: dict[str, list[str]]) -> tuple[str, dict[str, Any], list[str], list[str]]:
    """-> (cluster_key, features, cve_ids, tech_tags)"""
    p = event.raw_payload or {}
    vector = event.attack_vector
    if event.source in DATASET_CLUSTERS:
        return DATASET_CLUSTERS[event.source], {"generic": 65}, [], []
    if event.source in (IntelSource.TELEGRAM_CTI, IntelSource.LEAK_API):
        accounts = p.get("accounts", [])
        return f"v1:{event.tenant_id}:credential-exposure", {"credential_exposure": True,
                                                             "exposed_accounts": len(accounts)}, [], []  # fmt: skip
    if event.source is IntelSource.MALWAREBAZAAR:
        return f"v1:mb:{p.get('tag', 'unknown')}", {"generic": 60}, [], []
    if event.source is IntelSource.CISA_KEV and event.external_id:
        kev = p.get("kev", {})
        tags = sorted({t for tags in p.get("matched_tenants", {}).values() for t in tags})
        features = {
            "in_kev": True,
            "epss_alert": bool(p.get("epss_alert")),
            "epss_percentile": float((p.get("epss") or {}).get("percentile", 0.0)),
            "credible_poc": any(not x.get("likely_fake") for x in p.get("pocs", [])),
            "nuclei_template": bool(p.get("nuclei_templates")),
            "ransomware_use": kev.get("knownRansomwareCampaignUse") == "Known",
        }
        return f"v2:cve:{event.external_id}", features, [event.external_id], tags
    if vector is AttackVector.CLICKFIX_FILELESS:
        lure_host = (urlsplit(p.get("lure_page") or "").hostname or "").lower()
        c2 = sorted(d for d in obs["domains_block"] if d != lure_host)
        key = f"v3:c2:{c2[0]}" if c2 else f"v3:lure:{lure_host or event.dedup_sha256[:16]}"
        return key, {"clipboard_lure": True, "unpacked_c2": bool(c2), "layers": len(p.get("unpack_layers", []))}, [], []
    if vector is AttackVector.IDENTITY_AITM_INFOSTEALER:
        hosts = obs["domains_block"] + obs["domains_hunt"]
        host = registrable(hosts[0], private=True) if hosts else event.dedup_sha256[:16]
        features = {
            "aitm_score": int((p.get("aitm") or {}).get("score", 0)),
            "lookalike_cert": event.source is IntelSource.CERTSTREAM,
        }
        return f"v1:{event.tenant_id}:{host}", features, [], []
    return f"{vector}:{event.source}:{event.dedup_sha256[:16]}", {"generic": 40}, [], []


def _merge_features(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    merged = dict(old)
    for k, v in new.items():
        if isinstance(v, bool):
            merged[k] = bool(merged.get(k)) or v
        elif isinstance(v, int | float):
            merged[k] = max(merged.get(k, 0), v)
        else:
            merged[k] = v
    merged["event_count"] = int(old.get("event_count", 0)) + 1
    merged["lure_count"] = merged["event_count"] if "clipboard_lure" in merged else 0
    return merged


async def cluster_pending_events(session: AsyncSession, wl: WhitelistFilter, *, now: datetime | None = None,
                                 limit: int = 200) -> int:  # fmt: skip
    now = now or datetime.now(UTC)
    events = (
        await session.scalars(
            select(RawIntelEvent)
            .where(
                RawIntelEvent.status == EventStatus.NEW,
                RawIntelEvent.attack_vector.is_not(None),
                or_(
                    RawIntelEvent.raw_payload.has_key("enrichment"), RawIntelEvent.ingested_at < now - ENRICHMENT_GRACE
                ),
            )
            .order_by(RawIntelEvent.id)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
    ).all()
    for event in events:
        obs = _observables(event, wl)
        key, features, cves, tags = derive(event, obs)
        cluster = await session.scalar(select(PivotedCluster).where(PivotedCluster.cluster_key == key))
        vector = AttackVector(event.attack_vector)
        if cluster is None:
            cluster = PivotedCluster(
                cluster_key=key, attack_vector=vector, tenant_id=event.tenant_id, title=(event.title or key)[:512],
                base_confidence=0, current_confidence=0, first_seen_at=event.observed_at,
                last_seen_at=event.observed_at, decay_half_life_hours=DEFAULT_HALF_LIFE_HOURS[vector],
                observables={k: [] for k in OBS_KEYS}, pivot_graph={"features": {}, "edges": []},
            )  # fmt: skip
            session.add(cluster)
            await session.flush()
        elif cluster.status is ClusterStatus.EXPIRED:
            cluster.status = ClusterStatus.ACTIVE  # fresh evidence revives an expired cluster
        merged_obs = {k: sorted(set(cluster.observables.get(k, [])) | set(obs[k])) for k in OBS_KEYS}
        accounts = {a["ref"]: a for a in cluster.observables.get("accounts", [])}
        for a in (event.raw_payload or {}).get("accounts", []):
            accounts.setdefault(a["ref"], {"ref": a["ref"], "masked": a["masked"], "host": a.get("host")})
        if accounts:
            merged_obs["accounts"] = sorted(accounts.values(), key=lambda a: a["ref"])
        cluster.observables = merged_obs
        graph = dict(cluster.pivot_graph or {})
        graph["features"] = _merge_features(graph.get("features", {}), features)
        jarm = ((event.raw_payload or {}).get("enrichment") or {}).get("jarm", {})
        graph["edges"] = graph.get("edges", []) + [{"from": h, "to": j, "via": "jarm"} for h, j in jarm.items()]
        cluster.pivot_graph = graph
        cluster.cve_ids = sorted(set(cluster.cve_ids) | set(cves))
        cluster.tech_stack_tags = sorted(set(cluster.tech_stack_tags) | set(tags))
        cluster.first_seen_at = min(cluster.first_seen_at, event.observed_at)
        cluster.last_seen_at = max(cluster.last_seen_at, event.observed_at)
        cluster.base_confidence = base_confidence(vector, graph["features"])
        cluster.current_confidence = cluster.base_confidence
        await session.execute(
            insert(cluster_event_links).values(cluster_id=cluster.id, event_id=event.id).on_conflict_do_nothing()
        )
        event.status, event.processed_at = EventStatus.CLUSTERED, now
    return len(events)
