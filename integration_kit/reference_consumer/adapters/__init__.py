"""Platform adapters: each runs one pack task on your SIEM and returns the hit count."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class TaskRun:
    hits: int
    samples: list[dict[str, Any]] = field(default_factory=list)  # a few event ids/timestamps for local triage
    query: str = ""  # what was sent, for the local report


class Adapter(Protocol):
    name: str

    def run(self, task: dict[str, Any], values: dict[str, list[str]], lookback_days: int) -> TaskRun: ...


class NoQueryForPlatform(ValueError):
    """The task has nothing this platform can run (e.g. no Wazuh DSL)."""
