"""Sigma YAML -> CompiledQueries: the Wazuh DSL from our emitter (``wazuh_dsl.py``).

Packs carry no Microsoft Defender KQL (D-63, owner 2026-11-10): Defender XDR is out of scope, and integrators on
Elastic or Splunk convert the Sigma rule themselves (D-49). ``CompiledQueries.kql_defender`` stays in the contract,
always empty, so that packs issued before D-63 remain valid.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sigma.exceptions import SigmaError

from app.compiler.wazuh_dsl import UnsupportedSigma, compile_rule_to_dsl
from app.schemas.hunting_pack import CompiledQueries


@dataclass
class TranslationResult:
    queries: CompiledQueries | None
    issues: list[str] = field(default_factory=list)


def translate(sigma_yaml: str) -> TranslationResult:
    try:
        dsl = compile_rule_to_dsl(sigma_yaml)
    except (SigmaError, UnsupportedSigma) as exc:
        return TranslationResult(None, [f"wazuh: {exc}"])
    return TranslationResult(CompiledQueries(wazuh_es_dsl=dsl))
