"""Re-validate every pack before running anything, even when its signature is valid.

A valid signature proves the pack came from HuntCompiler, not that it is safe: a compromised HuntCompiler host signs
whatever it wants (ARCHITECTURE.md §9, threat T4). So the consumer checks the published JSON Schema (a copy of
``contracts/hunting_pack_v2.schema.json``) and the guardrails a schema cannot express.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).with_name("hunting_pack_v2.schema.json")
KNOWN_PLACEHOLDERS = frozenset({"EDGE_DEVICE_INTERNAL_IPS", "DMZ_HOST_IPS", "AFFECTED_UPNS", "AFFECTED_SAM_ACCOUNTS"})
# Keys that would run code inside OpenSearch/Elasticsearch or reshape the index at query time.
FORBIDDEN_DSL_KEYS = frozenset({"script", "script_score", "script_fields", "runtime_mappings", "stored_fields"})
MAX_QUERY_BYTES = 64 * 1024
MAX_DSL_SIZE = 500
MAX_TASKS = 25
_PLACEHOLDER = re.compile(r"\$\{HC_([A-Z0-9_]+)\}")


class PackRejected(ValueError):
    """The pack must not be run. The message says why."""


@lru_cache(maxsize=1)
def _validator() -> Draft202012Validator:
    return Draft202012Validator(json.loads(SCHEMA_PATH.read_text(encoding="utf-8")))


def _walk_dsl(node: Any, depth: int = 0) -> None:
    if depth > 32:
        raise PackRejected("DSL nesting too deep")
    if isinstance(node, dict):
        for key, value in node.items():
            if key in FORBIDDEN_DSL_KEYS:
                raise PackRejected(f"forbidden DSL key {key!r}")
            _walk_dsl(value, depth + 1)
    elif isinstance(node, list):
        for item in node:
            _walk_dsl(item, depth + 1)


def validate_pack(pack: Any, *, now: datetime | None = None) -> None:
    """Raises ``PackRejected`` unless the pack may be executed."""
    if not isinstance(pack, dict):
        raise PackRejected("a pack must be a JSON object")
    errors = sorted(_validator().iter_errors(pack), key=lambda e: list(e.absolute_path))
    if errors:
        e = errors[0]
        where = "/".join(str(p) for p in e.absolute_path) or "(root)"
        raise PackRejected(f"schema: {where}: {e.message[:200]}")
    expires = datetime.fromisoformat(str(pack.get("expires_at") or pack["timestamp"]).replace("Z", "+00:00"))
    if expires <= (now or datetime.now(UTC)):
        raise PackRejected("pack expired")
    tasks = pack["internal_hunting_tasks"]
    if len(tasks) > MAX_TASKS:
        raise PackRejected("too many tasks")
    for task in tasks:
        tid = task["task_id"]
        if len(task["sigma_yaml"].encode("utf-8")) > MAX_QUERY_BYTES:
            raise PackRejected(f"{tid}: sigma_yaml too large")
        dsl = (task.get("compiled_queries") or {}).get("wazuh_es_dsl")
        if dsl is not None:
            if len(json.dumps(dsl)) > MAX_QUERY_BYTES:
                raise PackRejected(f"{tid}: DSL too large")
            if not isinstance(dsl.get("size", 0), int) or dsl.get("size", 0) > MAX_DSL_SIZE:
                raise PackRejected(f"{tid}: DSL size above {MAX_DSL_SIZE}")
            _walk_dsl(dsl)
        text = json.dumps(task.get("compiled_queries") or {}) + task["sigma_yaml"]
        used = set(_PLACEHOLDER.findall(text))
        declared = set(task.get("scope_placeholders") or [])
        if unknown := used - KNOWN_PLACEHOLDERS:
            raise PackRejected(f"{tid}: unknown placeholders {sorted(unknown)}")
        if undeclared := used - declared:
            raise PackRejected(f"{tid}: placeholders not declared {sorted(undeclared)}")
