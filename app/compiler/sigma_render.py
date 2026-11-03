from __future__ import annotations

import uuid
from datetime import UTC, datetime

import yaml

from app.compiler.draft import RuleDraft

_MODIFIER_SUFFIX = {"equals": "", "contains": "|contains", "startswith": "|startswith", "endswith": "|endswith"}
NAMESPACE = uuid.UUID("6f2b1c7e-5a0d-4b8e-9c3f-1d2e3f4a5b6c")


def render_sigma(draft: RuleDraft, *, cluster_key: str, author: str = "OutSight HuntCompiler (AI-assisted)") -> str:
    detection: dict[str, object] = {}
    for sel in draft.selections:
        key = f"{sel.field}{_MODIFIER_SUFFIX[sel.modifier]}"
        detection.setdefault(sel.name, {})[key] = sel.values if len(sel.values) > 1 else sel.values[0]  # type: ignore[index]
    detection["condition"] = draft.condition.strip()
    doc = {
        "title": draft.title,
        "id": str(uuid.uuid5(NAMESPACE, f"{cluster_key}:{draft.title}")),
        "status": "experimental",
        "description": draft.rationale,
        "author": author,
        "date": datetime.now(UTC).strftime("%Y-%m-%d"),
        "logsource": {"product": "windows", "category": draft.category},
        "detection": detection,
        "falsepositives": draft.falsepositives or ["Unknown"],
        "level": "high",
        "tags": [f"attack.{t.lower()}" for t in draft.mitre_techniques],
    }
    return yaml.safe_dump(doc, sort_keys=False, allow_unicode=True)
