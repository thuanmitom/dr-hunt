"""Builds the evidence the LLM may read, enforces cache/budget, and records every call."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.compiler.ai_compiler import compile_with_llm
from app.compiler.llm import LLMProvider
from app.compiler.prompt import PROMPT_VERSION, EvidenceBlock, evidence_sha256
from app.db.models import AiCompilation, PivotedCluster, RawIntelEvent, cluster_event_links
from app.processors.whitelist_filter import WhitelistFilter
from app.schemas.enums import AttackVector
from app.schemas.hunting_pack import HuntingTask

MAX_FILES = 3


async def build_evidence(session: AsyncSession, cluster: PivotedCluster) -> list[EvidenceBlock]:
    """The complete list of what the model reads. Tenant data is never included."""
    events = (
        await session.scalars(
            select(RawIntelEvent)
            .join(cluster_event_links, cluster_event_links.c.event_id == RawIntelEvent.id)
            .where(cluster_event_links.c.cluster_id == cluster.id)
            .order_by(RawIntelEvent.id.desc())
            .limit(5)
        )
    ).all()
    blocks: list[EvidenceBlock] = []
    for ev in events:
        p = ev.raw_payload or {}
        if cluster.attack_vector is AttackVector.EDGE_DEVICE_EXPLOIT:
            kev = p.get("kev", {})
            facts = {
                k: kev.get(k) for k in ("cveID", "vendorProject", "product", "vulnerabilityName", "shortDescription")
            }
            blocks.append(EvidenceBlock("cisa-kev", "trusted", json.dumps(facts, ensure_ascii=False)))
            if p.get("nuclei_templates"):
                blocks.append(EvidenceBlock("nuclei-template-paths", "trusted", "\n".join(p["nuclei_templates"])))
            for poc in [x for x in p.get("pocs", []) if not x.get("likely_fake")][:2]:
                for path, content in list(poc.get("files", {}).items())[:MAX_FILES]:
                    blocks.append(EvidenceBlock(f"poc:{poc['repo']}/{path}", "untrusted", content))
        elif cluster.attack_vector is AttackVector.CLICKFIX_FILELESS:
            for preview in p.get("payload_previews", [])[:3]:
                blocks.append(EvidenceBlock("clipboard-payload", "untrusted", preview))
            techniques = sorted({layer["technique"] for layer in p.get("unpack_layers", [])})
            blocks.append(EvidenceBlock("unpack-techniques", "trusted", ", ".join(techniques)))
    obs = cluster.observables or {}
    iocs = obs.get("domains_block", []) + obs.get("ips_block", []) + obs.get("domains_hunt", [])
    if iocs:
        blocks.append(EvidenceBlock("cluster-indicators", "trusted", "\n".join(sorted(iocs)[:100])))
    return blocks


async def ai_tasks_for_cluster(
    session: AsyncSession,
    cluster: PivotedCluster,
    provider: LLMProvider,
    whitelist: WhitelistFilter,
    *,
    enabled_vectors: set[str],
    reserve_tokens=None,
) -> list[HuntingTask]:
    if cluster.attack_vector.value not in enabled_vectors:
        return []
    evidence = await build_evidence(session, cluster)
    if not any(b.trust == "untrusted" for b in evidence):
        return []  # nothing for the model to add beyond templates
    key = evidence_sha256(cluster.attack_vector.value, evidence)
    cached = await session.scalar(
        select(AiCompilation).where(
            AiCompilation.cluster_id == cluster.id,
            AiCompilation.input_sha256 == key,
            AiCompilation.prompt_version == PROMPT_VERSION,
            AiCompilation.model == provider.model,
        )
    )
    if cached is not None:
        return [HuntingTask.model_validate(t) for t in cached.accepted_tasks]
    obs = cluster.observables or {}
    allowed = set(obs.get("domains_block", []) + obs.get("domains_hunt", []) + obs.get("ips_block", [])
                  + obs.get("ips_hunt", []))  # fmt: skip
    outcome = await compile_with_llm(
        provider, vector=cluster.attack_vector.value, cluster_key=cluster.cluster_key, evidence=evidence,
        allowed_iocs=allowed, whitelist=whitelist, reserve_tokens=reserve_tokens,
    )  # fmt: skip
    session.add(
        AiCompilation(
            cluster_id=cluster.id,
            provider=provider.name,
            model=provider.model,
            prompt_version=PROMPT_VERSION,
            input_sha256=key,
            input_chars=outcome.input_chars,
            redactions=outcome.redactions,
            status=outcome.status,
            prompt_tokens=outcome.prompt_tokens,
            output_tokens=outcome.output_tokens,
            raw_output=outcome.raw_output,
            error=outcome.error,
            verdicts=[{"title": v.title, "accepted": v.accepted, "reasons": v.reasons} for v in outcome.verdicts],
            accepted_tasks=[t.model_dump(mode="json") for t in outcome.tasks],
        )  # fmt: skip
    )
    if outcome.summary and outcome.tasks:
        graph = dict(cluster.pivot_graph or {})
        graph["ai_summary"] = {"text": outcome.summary[:1500], "at": datetime.now(UTC).isoformat()}
        cluster.pivot_graph = graph
    return outcome.tasks
