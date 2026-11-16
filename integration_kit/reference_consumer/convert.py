"""Convert a pack task's Sigma rule for platforms whose query language the pack does not carry (owner decision IQ1,
2026-11-05: integrators convert the included Sigma with pySigma; packs stay at schema 2.0).

* Splunk: ``SplunkBackend`` with ``sysmon_pipeline()`` + ``splunk_windows_pipeline()``. Splunk field matching in the
  ``search`` command is case-insensitive, like Sigma.
* Elastic: ``EqlBackend`` (default) with an ECS pipeline. EQL's ``:`` and ``like~`` match case-insensitively, like
  Sigma; Lucene ``query_string`` wildcards are case-sensitive on keyword fields (the reason for DECISIONS.md D-25), so
  the Lucene option is only for clusters without EQL.

Always substitute placeholders first (``placeholders.substitute_sigma``).
"""

from __future__ import annotations

from typing import Literal

from sigma.collection import SigmaCollection

ElasticLanguage = Literal["eql", "lucene"]
ElasticPipeline = Literal["ecs_windows", "ecs_windows_old"]


def _one(rules: list) -> str:
    if len(rules) != 1:
        raise ValueError(f"expected one query, got {len(rules)}")
    return str(rules[0])


def to_splunk(sigma_yaml: str, *, xml_source: bool = False) -> str:
    """SPL search terms. ``xml_source`` targets ``XmlWinEventLog:`` sources (rendered XML events)."""
    from sigma.backends.splunk import SplunkBackend
    from sigma.pipelines.splunk import splunk_windows_pipeline
    from sigma.pipelines.sysmon import sysmon_pipeline

    spl = _one(SplunkBackend(processing_pipeline=sysmon_pipeline() + splunk_windows_pipeline())
               .convert(SigmaCollection.from_yaml(sigma_yaml)))  # fmt: skip
    return spl.replace('source="WinEventLog:', 'source="XmlWinEventLog:') if xml_source else spl


def to_elastic(sigma_yaml: str, *, language: ElasticLanguage = "eql", pipeline: ElasticPipeline = "ecs_windows") -> str:
    from sigma.backends.elasticsearch import EqlBackend, LuceneBackend
    from sigma.pipelines.elasticsearch import ecs_windows, ecs_windows_old

    chosen = {"ecs_windows": ecs_windows, "ecs_windows_old": ecs_windows_old}[pipeline]()
    backend = EqlBackend(processing_pipeline=chosen) if language == "eql" else LuceneBackend(processing_pipeline=chosen)
    return _one(backend.convert(SigmaCollection.from_yaml(sigma_yaml)))
