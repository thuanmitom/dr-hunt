"""Splunk: convert the task's Sigma rule to SPL (after placeholder substitution) and count matches through the REST
export endpoint (``/services/search/jobs/export``, newline-delimited JSON)."""

from __future__ import annotations

import json
from typing import Any

import httpx

from integration_kit.reference_consumer.adapters import TaskRun
from integration_kit.reference_consumer.convert import to_splunk
from integration_kit.reference_consumer.placeholders import substitute_sigma


class SplunkAdapter:
    name = "splunk"

    def __init__(self, http: httpx.Client, *, url: str, token: str, index: str = "", xml_source: bool = False) -> None:
        self._http = http
        self._url = url.rstrip("/")
        self._headers = {"Authorization": f"Bearer {token}"}
        self._index = index
        self._xml = xml_source

    def search(self, task: dict[str, Any], values: dict[str, list[str]], lookback_days: int) -> str:
        spl = to_splunk(substitute_sigma(task["sigma_yaml"], values), xml_source=self._xml)
        index = f"index={self._index} " if self._index else ""
        # Parentheses keep the converted expression intact next to the time and index terms.
        return f"search earliest=-{int(lookback_days)}d latest=now {index}({spl}) | stats count"

    def run(self, task: dict[str, Any], values: dict[str, list[str]], lookback_days: int) -> TaskRun:
        search = self.search(task, values, lookback_days)
        resp = self._http.post(f"{self._url}/services/search/jobs/export", headers=self._headers,
                               data={"search": search, "output_mode": "json"})  # fmt: skip
        resp.raise_for_status()
        count = 0
        for line in resp.text.splitlines():
            if not line.strip():
                continue
            row = json.loads(line)
            if (result := row.get("result")) and "count" in result:
                count = int(result["count"])
        return TaskRun(count, [], search)
