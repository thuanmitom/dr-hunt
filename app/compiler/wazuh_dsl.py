"""Sigma -> OpenSearch DSL for the Wazuh indexer.

The stock Lucene backend emits ``query_string`` wildcards, which are case-sensitive on Wazuh's
keyword fields while Sigma ``contains``/``endswith`` are case-insensitive (``*powershell*`` would miss
``PowerShell``). This emitter walks pySigma's parsed condition tree after the processing pipeline
and produces ``term``/``wildcard`` queries with ``case_insensitive: true``.
"""

from __future__ import annotations

import re
from typing import Any

from sigma.collection import SigmaCollection
from sigma.conditions import ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT, ConditionOR
from sigma.processing.conditions import LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import AddConditionTransformation
from sigma.rule import SigmaRule
from sigma.types import SigmaBool, SigmaNull, SigmaNumber, SigmaString, SpecialChars

from app.compiler.fields import SYSMON_CATEGORY_EVENT_ID, SYSMON_CHANNEL, wazuh_field

PLACEHOLDER = re.compile(r"^\$\{HC_[A-Z0-9_]+\}$")


class UnsupportedSigma(ValueError):
    pass


def wazuh_pipeline() -> ProcessingPipeline:
    from sigma.pipelines.sysmon import sysmon_pipeline

    sysmon_channel = ProcessingItem(
        identifier="wazuh_sysmon_channel",
        transformation=AddConditionTransformation({"Channel": SYSMON_CHANNEL}),
        rule_conditions=[LogsourceCondition(product="windows", category=c) for c in SYSMON_CATEGORY_EVENT_ID],
        rule_condition_linking=any,
    )
    security_channel = ProcessingItem(
        identifier="wazuh_security_channel",
        transformation=AddConditionTransformation({"Channel": "Security"}),
        rule_conditions=[LogsourceCondition(product="windows", service="security")],
    )
    system_channel = ProcessingItem(
        identifier="wazuh_system_channel",
        transformation=AddConditionTransformation({"Channel": "System"}),
        rule_conditions=[LogsourceCondition(product="windows", service="system")],
    )
    items = [sysmon_channel, security_channel, system_channel]
    return sysmon_pipeline() + ProcessingPipeline(name="wazuh", priority=50, items=items)


def _escape(part: str) -> str:
    return part.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?")


def _string_query(field: str, value: SigmaString) -> dict[str, Any]:
    plain = "".join(p for p in value.s if isinstance(p, str))
    if not value.contains_special():
        if PLACEHOLDER.match(plain):
            return {"terms": {field: [plain]}}  # SOAR expands the placeholder into the value list
        return {"term": {field: {"value": plain, "case_insensitive": True}}}
    pattern = ""
    for p in value.s:
        if p is SpecialChars.WILDCARD_MULTI:
            pattern += "*"
        elif p is SpecialChars.WILDCARD_SINGLE:
            pattern += "?"
        elif isinstance(p, str):
            pattern += _escape(p)
        else:
            raise UnsupportedSigma(f"unsupported string part {p!r}")
    return {"wildcard": {field: {"value": pattern, "case_insensitive": True}}}


def _emit(node: Any) -> dict[str, Any]:
    if isinstance(node, ConditionAND):
        return {"bool": {"filter": [_emit(a) for a in node.args]}}
    if isinstance(node, ConditionOR):
        return {"bool": {"should": [_emit(a) for a in node.args], "minimum_should_match": 1}}
    if isinstance(node, ConditionNOT):
        return {"bool": {"must_not": [_emit(a) for a in node.args]}}
    if isinstance(node, ConditionFieldEqualsValueExpression):
        field, value = wazuh_field(node.field), node.value
        if isinstance(value, SigmaString):
            return _string_query(field, value)
        if isinstance(value, SigmaNumber):
            return {"term": {field: {"value": str(value.number)}}}  # Wazuh stores these as keyword strings
        if isinstance(value, SigmaBool):
            return {"term": {field: {"value": str(value.boolean).lower(), "case_insensitive": True}}}
        if isinstance(value, SigmaNull):
            return {"bool": {"must_not": [{"exists": {"field": field}}]}}
        raise UnsupportedSigma(f"value type {type(value).__name__} is not supported for Wazuh")
    raise UnsupportedSigma(f"condition {type(node).__name__} (e.g. keyword search) is not supported")


def compile_rule_to_dsl(sigma_yaml: str) -> dict[str, Any]:
    rules = SigmaCollection.from_yaml(sigma_yaml).rules  # fresh parse: pipelines mutate rules in place
    if len(rules) != 1:
        raise UnsupportedSigma("exactly one Sigma rule per task")
    rule: SigmaRule = rules[0]
    wazuh_pipeline().apply(rule)
    queries = [_emit(c.parsed) for c in rule.detection.parsed_condition]
    query = queries[0] if len(queries) == 1 else {"bool": {"should": queries, "minimum_should_match": 1}}
    return {"query": query, "sort": [{"timestamp": "desc"}], "size": 100}
