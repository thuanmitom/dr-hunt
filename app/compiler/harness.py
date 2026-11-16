"""Executes the DSL subset we emit against sample documents, so a rule that cannot match its own
positive sample (or matches its negative one) is rejected before it ships."""

from __future__ import annotations

import fnmatch
import re
from typing import Any

from app.compiler.fields import SYSMON_CATEGORY_EVENT_ID, SYSMON_CHANNEL, wazuh_field
from app.compiler.wazuh_dsl import wazuh_stored

EVENTDATA = "data.win.eventdata."


def sample_to_doc(sample: dict[str, Any], category: str | None, service: str | None = None) -> dict[str, str]:
    """A sample event (plain Sysmon/Windows values) as Wazuh indexes it: event data values keep Wazuh's doubled
    backslashes, so the harness evaluates queries against what the indexer really holds (D-53)."""
    doc = {}
    for k, v in sample.items():
        field = wazuh_field(k)
        doc[field] = wazuh_stored(str(v)) if field.startswith(EVENTDATA) else str(v)
    if category in SYSMON_CATEGORY_EVENT_ID:
        doc.setdefault(wazuh_field("EventID"), str(SYSMON_CATEGORY_EVENT_ID[category]))
        doc.setdefault(wazuh_field("Channel"), SYSMON_CHANNEL)
    elif service == "security":
        doc.setdefault(wazuh_field("Channel"), "Security")
    elif service == "system":
        doc.setdefault(wazuh_field("Channel"), "System")
    return doc


def _wildcard_regex(pattern: str) -> re.Pattern[str]:
    out, i = "", 0
    while i < len(pattern):
        c = pattern[i]
        if c == "\\" and i + 1 < len(pattern):
            out += re.escape(pattern[i + 1])
            i += 2
            continue
        out += ".*" if c == "*" else "." if c == "?" else re.escape(c)
        i += 1
    return re.compile(out, re.S)


def matches(query: dict[str, Any], doc: dict[str, str]) -> bool:
    ((kind, body),) = query.items()
    if kind == "bool":
        if any(not matches(q, doc) for q in body.get("filter", []) + body.get("must", [])):
            return False
        if any(matches(q, doc) for q in body.get("must_not", [])):
            return False
        should = body.get("should", [])
        if should:
            need = int(body.get("minimum_should_match", 1))
            return sum(matches(q, doc) for q in should) >= need
        return True
    if kind == "exists":
        return body["field"] in doc
    ((field, spec),) = body.items()
    value = doc.get(field)
    if kind == "terms":
        return value is not None and value in [str(v) for v in spec]
    if value is None:
        return False
    if kind == "term":
        expected = str(spec["value"])
        return value.lower() == expected.lower() if spec.get("case_insensitive") else value == expected
    if kind == "wildcard":
        flags_value = value.lower() if spec.get("case_insensitive") else value
        pattern = spec["value"].lower() if spec.get("case_insensitive") else spec["value"]
        return bool(_wildcard_regex(pattern).fullmatch(flags_value))
    raise ValueError(f"harness does not support query type {kind!r}")


def fnmatch_compat(value: str, pattern: str) -> bool:  # kept for callers comparing simple globs
    return fnmatch.fnmatchcase(value, pattern)
