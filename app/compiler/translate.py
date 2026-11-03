"""Sigma YAML -> CompiledQueries (Wazuh DSL via our emitter, Defender KQL via pySigma Kusto),
with post-compile lint. Each backend parses its own fresh copy of the rule."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaError

from app.compiler.wazuh_dsl import UnsupportedSigma, compile_rule_to_dsl
from app.schemas.hunting_pack import CompiledQueries

# EntraIdSignInEvents replaced AADSignInEventsBeta on 2026-10-19 (Microsoft Learn); the old name is not accepted.
KQL_TABLES = frozenset(
    {"DeviceProcessEvents", "DeviceRegistryEvents", "DeviceNetworkEvents", "DeviceFileEvents",
     "DeviceImageLoadEvents", "DeviceEvents", "DeviceLogonEvents", "EntraIdSignInEvents"}
)  # fmt: skip
# A literal '*' inside these operators is NOT a wildcard in KQL: the clause can never match.
_KQL_STAR_LITERAL = re.compile(r"\b(endswith|startswith|contains|has|==|=~)\s*\"[^\"]*\*\"", re.I)


@dataclass
class TranslationResult:
    queries: CompiledQueries | None
    issues: list[str] = field(default_factory=list)


def lint_kql(kql: str) -> list[str]:
    issues = []
    first = kql.strip().split("\n", 1)[0].split("|", 1)[0].strip()
    if first not in KQL_TABLES:
        issues.append(f"unexpected KQL table {first!r}")
    if m := _KQL_STAR_LITERAL.search(kql):
        issues.append(f"literal '*' in '{m.group(1)}' never matches: {m.group(0)[:80]}")
    return issues


def compile_kql(sigma_yaml: str) -> str:
    from sigma.backends.kusto import KustoBackend
    from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

    return KustoBackend(processing_pipeline=microsoft_xdr_pipeline()).convert(SigmaCollection.from_yaml(sigma_yaml))[0]


def translate(sigma_yaml: str, *, kql_override: str | None = None) -> TranslationResult:
    issues: list[str] = []
    dsl = None
    try:
        dsl = compile_rule_to_dsl(sigma_yaml)
    except (SigmaError, UnsupportedSigma) as exc:
        issues.append(f"wazuh: {exc}")
    kql = kql_override
    if kql is None:
        try:
            kql = compile_kql(sigma_yaml)
        except (SigmaError, IndexError) as exc:
            issues.append(f"defender: {type(exc).__name__}: {str(exc)[:200]}")
    if kql is not None and (kql_issues := lint_kql(kql)):
        issues += [f"defender: {i}" for i in kql_issues]
        kql = None
    if dsl is None and kql is None:
        return TranslationResult(None, issues)
    return TranslationResult(CompiledQueries(wazuh_es_dsl=dsl, kql_defender=kql), issues)
