"""HuntCompiler API client: ``GET /api/v1/packs`` (bearer token) and ``POST /api/v1/feedback`` (HMAC)."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

import httpx

from integration_kit.reference_consumer.signing import SignatureError, canonical_json, signed_headers, verify

log = logging.getLogger("hc_kit.client")


@dataclass(frozen=True, slots=True)
class PulledItem:
    seq: int
    pack: dict[str, Any] | None  # None when the signature check failed
    error: str | None = None


class HuntCompilerClient:
    def __init__(self, http: httpx.Client, *, base_url: str, api_token: str, hmac_secret: str, tenant: str) -> None:
        self._http = http
        self._base = base_url.rstrip("/")
        self._token = api_token
        self._secret = hmac_secret
        self._tenant = tenant

    def pull(self, after: int, limit: int = 50) -> tuple[list[PulledItem], int]:
        """One page after ``after``. Every item's signature is checked here; a bad one is returned with ``error``."""
        resp = self._http.get(f"{self._base}/api/v1/packs", params={"after": after, "limit": limit},
                              headers={"Authorization": f"Bearer {self._token}"})  # fmt: skip
        resp.raise_for_status()
        body = resp.json()
        items = []
        for raw in body.get("items", []):
            seq = int(raw["seq"])
            try:
                verify(self._secret, canonical_json(raw["pack"]), raw.get("signature"), raw.get("timestamp"))
                items.append(PulledItem(seq, raw["pack"]))
            except (SignatureError, KeyError, TypeError) as exc:
                items.append(PulledItem(seq, None, f"signature: {exc}"))
        return items, int(body.get("next_cursor", after))

    def post_feedback(self, pack_id: str, *, sighting: bool, evaluable: bool, evaluated_at: str) -> str:
        """Only these bits leave your network: no counts, hosts, users or log lines."""
        body = canonical_json({"schema_version": "1.0", "pack_id": pack_id, "sighting": sighting,
                               "evaluable": evaluable, "evaluated_at": evaluated_at})  # fmt: skip
        resp = self._http.post(f"{self._base}/api/v1/feedback", content=body,
                               headers=signed_headers(self._secret, body, tenant=self._tenant))  # fmt: skip
        resp.raise_for_status()
        return str(resp.json().get("status", ""))
