"""What the LLM is allowed to return. Deliberately narrow: the model fills a constrained structure
(category, allow-listed fields, a closed set of modifiers, sample events) and the Sigma YAML is
rendered by our code. The model never writes YAML, queries, IOCs for blocking, scores or hints."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.compiler.fields import ALLOWED_FIELDS
from app.schemas.enums import TargetScope

Category = Literal[
    "process_creation", "network_connection", "driver_load", "image_load", "file_event", "registry_set", "dns_query"
]  # fmt: skip
Modifier = Literal["equals", "contains", "startswith", "endswith"]
_SEL_NAME = re.compile(r"^sel_[a-z0-9_]{1,30}$")
_CONDITION = re.compile(r"^(?:not\s+)?sel_[a-z0-9_]+(?:\s+(?:and|or)\s+(?:not\s+)?sel_[a-z0-9_]+)*$")


class _Draft(BaseModel):
    model_config = ConfigDict(extra="forbid")


class FieldValue(_Draft):
    field: str
    value: str = Field(max_length=500)


class Selection(_Draft):
    name: str = Field(description="sel_<name>, lowercase")
    field: str = Field(description="One of the allowed Sigma fields for the category")
    modifier: Modifier
    values: list[str] = Field(min_length=1, max_length=20)


class RuleDraft(_Draft):
    title: str = Field(max_length=120)
    rationale: str = Field(max_length=600, description="Why this behaviour indicates the threat")
    category: Category
    selections: list[Selection] = Field(min_length=1, max_length=6)
    condition: str = Field(description="Boolean expression over selection names, e.g. 'sel_parent and sel_child'")
    target_scope: TargetScope = TargetScope.ALL_ENDPOINTS
    positive_samples: list[list[FieldValue]] = Field(min_length=1, max_length=3)
    negative_samples: list[list[FieldValue]] = Field(min_length=1, max_length=3)
    mitre_techniques: list[str] = Field(default_factory=list, max_length=8)
    falsepositives: list[str] = Field(default_factory=list, max_length=5)

    @model_validator(mode="after")
    def _structure(self) -> RuleDraft:
        allowed = ALLOWED_FIELDS[self.category]
        names = set()
        for s in self.selections:
            if not _SEL_NAME.match(s.name):
                raise ValueError(f"bad selection name {s.name!r}")
            if s.field not in allowed:
                raise ValueError(f"field {s.field!r} not allowed for {self.category}")
            names.add(s.name)
        if not _CONDITION.match(self.condition.strip()):
            raise ValueError("condition must combine selection names with and/or/not only")
        used = set(re.findall(r"sel_[a-z0-9_]+", self.condition))
        if used - names:
            raise ValueError(f"condition references unknown selections {sorted(used - names)}")
        for sample in self.positive_samples + self.negative_samples:
            if bad := {fv.field for fv in sample} - allowed:
                raise ValueError(f"sample uses fields outside the category: {sorted(bad)}")
        return self


class ExploitExtraction(_Draft):
    """Vector 2: facts pulled from PoC code — informational, used in the summary only."""

    uri_paths: list[str] = Field(default_factory=list, max_length=20)
    webshell_paths: list[str] = Field(default_factory=list, max_length=20)
    post_exploitation_processes: list[str] = Field(default_factory=list, max_length=20)


class CompilationDraft(_Draft):
    summary: str = Field(max_length=1500)
    rules: list[RuleDraft] = Field(default_factory=list, max_length=4)
    extraction: ExploitExtraction | None = None
