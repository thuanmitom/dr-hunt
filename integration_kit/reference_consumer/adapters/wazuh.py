"""Wazuh indexer (OpenSearch): run the pack's ``wazuh_es_dsl`` as is, inside a time-range filter.

Search ``wazuh-archives-*``, not ``wazuh-alerts-*``: by default Wazuh indexes only events that raised an alert, so most
raw Sysmon/Security events a hunt needs exist only in the archives (``logall_json`` plus the archives input in
Filebeat). See ``integration_kit/wazuh/GUIDE.md``.
"""

from __future__ import annotations

import json
from typing import Any

import httpx

from integration_kit.reference_consumer.adapters import NoQueryForPlatform, TaskRun
from integration_kit.reference_consumer.placeholders import substitute_dsl


class WazuhAdapter:
    name = "wazuh"

    def __init__(self, http: httpx.Client, *, url: str, index: str = "wazuh-archives-*", user: str = "",
                 password: str = "", max_samples: int = 5) -> None:  # fmt: skip
        self._http = http
        self._url = url.rstrip("/")
        self._index = index or "wazuh-archives-*"
        self._auth = (user, password) if user else None
        self._max_samples = max_samples

    def build_request(self, task: dict[str, Any], values: dict[str, list[str]], lookback_days: int) -> dict[str, Any]:
        dsl = (task.get("compiled_queries") or {}).get("wazuh_es_dsl")
        if not dsl:
            raise NoQueryForPlatform("the task has no Wazuh DSL")
        query = substitute_dsl(dsl["query"], values)
        return {
            "query": {"bool": {"filter": [query, {"range": {"timestamp": {"gte": f"now-{int(lookback_days)}d"}}}]}},
            "size": self._max_samples,
            "sort": dsl.get("sort") or [{"timestamp": "desc"}],
            "track_total_hits": True,
            "_source": ["timestamp", "agent.id", "agent.name"],
        }

    def run(self, task: dict[str, Any], values: dict[str, list[str]], lookback_days: int) -> TaskRun:
        body = self.build_request(task, values, lookback_days)
        resp = self._http.post(f"{self._url}/{self._index}/_search", json=body, auth=self._auth)
        resp.raise_for_status()
        hits = resp.json().get("hits") or {}
        samples = [{"_id": h.get("_id"), **(h.get("_source") or {})} for h in hits.get("hits") or []]
        return TaskRun(int((hits.get("total") or {}).get("value", 0)), samples, json.dumps(body["query"]))
