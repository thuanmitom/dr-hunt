"""LLM-assisted detection compilation with layered guardrails.

The model only *proposes* detection logic. Code decides everything that matters:
  1. input: only cluster evidence (no tenant data), redacted, nonce-fenced, size-capped
  2. output: strict schema; YAML/queries rendered by us; no blocklist/score/hint fields exist
  3. per rule: breadth check -> indicator provenance -> whitelist -> compile -> lint -> harness
A rejected rule is recorded with reasons; nothing rejected ever reaches a pack.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from app.compiler.draft import CompilationDraft, RuleDraft
from app.compiler.harness import matches, sample_to_doc
from app.compiler.llm import LLMProvider
from app.compiler.prompt import SYSTEM_PROMPT, EvidenceBlock, build_user_content, evidence_sha256
from app.compiler.sigma_render import render_sigma
from app.compiler.translate import translate
from app.processors.stager_unpacker import extract_iocs
from app.processors.whitelist_filter import Action, WhitelistFilter
from app.schemas.hunting_pack import HuntingTask
from app.schemas.validators import validate_mitre

GENERIC_TOKENS = frozenset(
    {"powershell", "powershell.exe", "cmd", "cmd.exe", "http", "https", ".exe", ".dll", "exe", "dll", "c:\\",
     "\\windows\\", "\\users\\", "rundll32.exe", "explorer.exe", "svchost.exe"}
)  # fmt: skip
MAX_EVIDENCE_CHARS = 40_000


@dataclass
class RuleVerdict:
    title: str
    accepted: bool
    reasons: list[str] = field(default_factory=list)
    task: HuntingTask | None = None


@dataclass
class CompilationOutcome:
    status: str  # accepted | partial | rejected | invalid_output | error | budget_exhausted
    input_sha256: str
    input_chars: int
    redactions: int
    model: str = ""
    prompt_tokens: int = 0
    output_tokens: int = 0
    raw_output: dict[str, Any] | None = None
    verdicts: list[RuleVerdict] = field(default_factory=list)
    summary: str = ""
    error: str | None = None

    @property
    def tasks(self) -> list[HuntingTask]:
        return [v.task for v in self.verdicts if v.accepted and v.task]


def _value_text(value: str) -> str:
    return value.strip("*").strip().lower()


def breadth_issues(draft: RuleDraft) -> list[str]:
    issues = []
    for sel in draft.selections:
        for v in sel.values:
            t = _value_text(v)
            if len(t) < 3:
                issues.append(f"{sel.name}: value {v!r} is too short")
            elif t in GENERIC_TOKENS and sel.modifier != "equals":
                lone = len(draft.selections) == 1 or " and " not in f" {draft.condition} "
                if lone:
                    issues.append(f"{sel.name}: generic token {v!r} without an AND-ed qualifier")
    if " or " in f" {draft.condition} " and " and " not in f" {draft.condition} " and len(draft.selections) > 2:
        issues.append("pure OR across many selections is too broad")
    return issues


def provenance_issues(draft: RuleDraft, allowed_iocs: set[str], wl: WhitelistFilter) -> list[str]:
    issues = []
    for sel in draft.selections:
        for v in sel.values:
            _, domains, ips = extract_iocs(v.strip("*"))
            for ioc in domains | ips:
                if ioc not in allowed_iocs:
                    issues.append(f"indicator {ioc!r} is not part of the cluster evidence")
                    continue
                verdict = wl.check_domain(ioc) if ioc in domains else wl.check_ip(ioc)
                if verdict.action is Action.DROP:
                    issues.append(f"indicator {ioc!r} is benign/owned infrastructure ({verdict.reason})")
    return issues


def harness_issues(draft: RuleDraft, dsl: dict[str, Any]) -> list[str]:
    issues = []
    query = dsl["query"]
    for i, sample in enumerate(draft.positive_samples):
        if not matches(query, sample_to_doc({fv.field: fv.value for fv in sample}, draft.category)):
            issues.append(f"positive sample #{i + 1} does not match")
    for i, sample in enumerate(draft.negative_samples):
        if matches(query, sample_to_doc({fv.field: fv.value for fv in sample}, draft.category)):
            issues.append(f"negative sample #{i + 1} matches")
    return issues


def evaluate_rule(draft: RuleDraft, *, cluster_key: str, allowed_iocs: set[str], wl: WhitelistFilter,
                  lookback_days: int) -> RuleVerdict:  # fmt: skip
    verdict = RuleVerdict(title=draft.title, accepted=False)
    verdict.reasons += breadth_issues(draft)
    verdict.reasons += provenance_issues(draft, allowed_iocs, wl)
    if verdict.reasons:
        return verdict
    sigma_yaml = render_sigma(draft, cluster_key=cluster_key)
    result = translate(sigma_yaml)
    if result.queries is None or result.queries.wazuh_es_dsl is None:
        verdict.reasons += result.issues or ["no testable Wazuh query"]
        return verdict
    verdict.reasons += harness_issues(draft, result.queries.wazuh_es_dsl)
    if verdict.reasons:
        return verdict
    telemetry = [f"sysmon:{draft.category}"]
    slug = hashlib.sha256(f"{cluster_key}:{draft.title}".encode()).hexdigest()[:10]
    verdict.task = HuntingTask(
        task_id=f"ai-{draft.category.replace('_', '-')}-{slug}",
        description=f"[AI-assisted] {draft.title}: {draft.rationale}"[:2000],
        lookback_days=lookback_days,
        sigma_yaml=sigma_yaml,
        compiled_queries=result.queries,
        target_scope=draft.target_scope,
        required_telemetry=telemetry,
    )
    verdict.accepted = True
    verdict.reasons = [f"note: {i}" for i in result.issues]
    return verdict


async def compile_with_llm(
    provider: LLMProvider,
    *,
    vector: str,
    cluster_key: str,
    evidence: list[EvidenceBlock],
    allowed_iocs: set[str],
    whitelist: WhitelistFilter,
    lookback_days: int = 30,
    reserve_tokens: Callable[[int], Awaitable[bool]] | None = None,
) -> CompilationOutcome:
    user, redactions = build_user_content(vector, evidence, max_chars=MAX_EVIDENCE_CHARS)
    input_sha = evidence_sha256(vector, evidence)
    outcome = CompilationOutcome(status="error", input_sha256=input_sha, input_chars=len(user), redactions=redactions)
    if reserve_tokens is not None and not await reserve_tokens(len(user) // 3 + 8192):
        outcome.status = "budget_exhausted"
        return outcome
    try:
        result = await provider.generate_json(
            system=SYSTEM_PROMPT, user=user, json_schema=CompilationDraft.model_json_schema()
        )
    except Exception as exc:  # noqa: BLE001 — provider errors are recorded, never raised into the pipeline
        outcome.error = f"{type(exc).__name__}: {str(exc)[:300]}"
        return outcome
    outcome.model, outcome.prompt_tokens, outcome.output_tokens = (
        result.model,
        result.prompt_tokens,
        result.output_tokens,
    )
    try:
        outcome.raw_output = json.loads(result.text)
    except json.JSONDecodeError as exc:
        outcome.status, outcome.error = "invalid_output", f"not JSON: {exc}"
        return outcome
    try:
        draft = CompilationDraft.model_validate(outcome.raw_output)
    except ValidationError as exc:
        outcome.status, outcome.error = "invalid_output", str(exc)[:1000]
        return outcome
    outcome.summary = draft.summary
    for rule in draft.rules:
        rule.mitre_techniques = [t for t in rule.mitre_techniques if _valid_mitre(t)]
        outcome.verdicts.append(
            evaluate_rule(
                rule, cluster_key=cluster_key, allowed_iocs=allowed_iocs, wl=whitelist, lookback_days=lookback_days
            )  # fmt: skip
        )
    accepted = sum(v.accepted for v in outcome.verdicts)
    outcome.status = (
        "accepted" if accepted and accepted == len(outcome.verdicts) else "partial" if accepted else "rejected"
    )
    return outcome


def _valid_mitre(t: str) -> bool:
    try:
        validate_mitre(t)
        return True
    except ValueError:
        return False
