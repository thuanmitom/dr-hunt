"""Elasticsearch / Elastic Security: convert the task's Sigma rule (after placeholder substitution) and run it.

* ``eql`` (default): ``POST <index>/_eql/search``. EQL returns at most ``size`` events, so the consumer asks for
  ``max_hits + 1`` to tell "many" from "too many" without fetching sources.
* ``lucene``: ``POST <index>/_search`` with ``query_string``. Case-sensitive wildcards: use only without EQL.
"""

from __future__ import annotations

from typing import Any

import httpx

from integration_kit.reference_consumer.adapters import TaskRun
from integration_kit.reference_consumer.convert import to_elastic
from integration_kit.reference_consumer.placeholders import substitute_sigma


class ElasticAdapter:
    name = "elastic"

    def __init__(self, http: httpx.Client, *, url: str, index: str = "logs-*", api_key: str = "",
                 language: str = "eql", pipeline: str = "ecs_windows", max_hits: int = 1000,
                 max_samples: int = 5) -> None:  # fmt: skip
        if language not in ("eql", "lucene"):
            raise ValueError("language must be 'eql' or 'lucene'")
        self._http = http
        self._url = url.rstrip("/")
        self._index = index or "logs-*"
        self._headers = {"Authorization": f"ApiKey {api_key}"} if api_key else {}
        self._language = language
        self._pipeline = pipeline
        self._max_hits = max_hits
        self._max_samples = max_samples

    def query(self, task: dict[str, Any], values: dict[str, list[str]]) -> str:
        return to_elastic(substitute_sigma(task["sigma_yaml"], values), language=self._language,  # type: ignore[arg-type]
                          pipeline=self._pipeline)  # type: ignore[arg-type]  # fmt: skip

    def run(self, task: dict[str, Any], values: dict[str, list[str]], lookback_days: int) -> TaskRun:
        q = self.query(task, values)
        window = {"range": {"@timestamp": {"gte": f"now-{int(lookback_days)}d"}}}
        if self._language == "eql":
            body = {"query": q, "filter": window, "size": self._max_hits + 1, "fields": ["@timestamp", "host.name"]}
            resp = self._http.post(f"{self._url}/{self._index}/_eql/search", json=body, headers=self._headers,
                                   params={"filter_path": "hits.total,hits.events._id,hits.events.fields"})  # fmt: skip
            resp.raise_for_status()
            hits = resp.json().get("hits") or {}
            events = hits.get("events") or []
            total = int((hits.get("total") or {}).get("value", len(events)))
            return TaskRun(
                total, [{"_id": e.get("_id"), **(e.get("fields") or {})} for e in events[: self._max_samples]], q
            )
        lucene = {"query_string": {"query": q, "analyze_wildcard": True}}
        body = {"query": {"bool": {"filter": [lucene, window]}}, "size": self._max_samples, "track_total_hits": True,
                "_source": ["@timestamp", "host.name"]}  # fmt: skip
        resp = self._http.post(f"{self._url}/{self._index}/_search", json=body, headers=self._headers)
        resp.raise_for_status()
        hits = resp.json().get("hits") or {}
        samples = [{"_id": h.get("_id"), **(h.get("_source") or {})} for h in hits.get("hits") or []]
        return TaskRun(int((hits.get("total") or {}).get("value", 0)), samples, q)
