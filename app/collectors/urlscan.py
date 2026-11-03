"""URLScan.io collectors: brand lookalikes with AiTM behaviour (V1) and ClickFix lures (V3)."""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass
from typing import Any

import httpx

from app.collectors.base import IntelSignal, Observable, get_json
from app.processors.pivot import assess_aitm
from app.processors.stager_unpacker import unpack
from app.schemas.enums import AttackVector, IntelSource

log = logging.getLogger(__name__)

_CLIPBOARD_API = re.compile(r"navigator\.clipboard\.writeText|execCommand\(\s*['\"]copy['\"]\s*\)", re.I)
_LOLBIN = re.compile(r"\b(mshta|powershell|pwsh|cmd(?:\.exe)?\s*/c|curl|bitsadmin|certutil|rundll32|msiexec)\b", re.I)
_STRING_LITERAL = re.compile(r"""(['"`])((?:\\.|(?!\1).){12,4000})\1""", re.S)
_TEXTAREA = re.compile(r"<textarea[^>]*>(.*?)</textarea>", re.I | re.S)


@dataclass(frozen=True, slots=True)
class ClipboardLure:
    payloads: tuple[str, ...]


def detect_clipboard_lure(html: str) -> ClipboardLure | None:
    """Find a page that writes a LOLBin command line to the clipboard (fake CAPTCHA / ClickFix)."""
    if not _CLIPBOARD_API.search(html):
        return None
    candidates = [m.group(2) for m in _STRING_LITERAL.finditer(html)] + _TEXTAREA.findall(html)
    payloads = tuple(dict.fromkeys(c.strip() for c in candidates if _LOLBIN.search(c)))
    if not payloads:
        # Payload may be encoded (atob/base64); let the unpacker try the whole script.
        unpacked = unpack(html)
        if any(_LOLBIN.search(layer.preview) for layer in unpacked.layers[1:]):
            payloads = (html,)
    return ClipboardLure(payloads) if payloads else None


class UrlscanClient:
    def __init__(self, client: httpx.AsyncClient, api_key: str, base_url: str = "https://urlscan.io") -> None:
        self._client = client
        self._base = base_url.rstrip("/")
        self._headers = {"API-Key": api_key}

    async def search(self, query: str, size: int = 100) -> list[dict[str, Any]]:
        data = await get_json(
            self._client, f"{self._base}/api/v1/search/", params={"q": query, "size": size}, headers=self._headers
        )
        return list(data.get("results", []))

    async def result(self, scan_id: str) -> dict[str, Any]:
        return await get_json(self._client, f"{self._base}/api/v1/result/{scan_id}/", headers=self._headers)

    async def dom(self, scan_id: str) -> str:
        resp = await self._client.get(f"{self._base}/dom/{scan_id}/", headers=self._headers)
        resp.raise_for_status()
        return resp.text


async def collect_brand_aitm(
    urlscan: UrlscanClient,
    *,
    tenant_id: uuid.UUID,
    keywords: list[str],
    query_template: str,
    size: int,
    bad_jarms: frozenset[str] = frozenset(),
) -> list[IntelSignal]:
    signals: list[IntelSignal] = []
    for keyword in keywords:
        for hit in await urlscan.search(query_template.format(keyword=keyword), size=size):
            scan_id = (hit.get("task") or {}).get("uuid") or hit.get("_id")
            if not scan_id:
                continue
            result = await urlscan.result(scan_id)
            assessment = assess_aitm(result, bad_jarms=bad_jarms)
            if not assessment.proxied_identity_paths:
                continue
            page = result.get("page") or {}
            signals.append(
                IntelSignal(
                    source=IntelSource.URLSCAN,
                    external_id=scan_id,
                    tenant_id=tenant_id,
                    attack_vector=AttackVector.IDENTITY_AITM_INFOSTEALER,
                    title=f"AiTM candidate impersonating '{keyword}': {assessment.page_host}",
                    source_url=f"https://urlscan.io/result/{scan_id}/",
                    raw_payload={
                        "keyword": keyword,
                        "aitm": {
                            "score": assessment.score,
                            "paths": assessment.proxied_identity_paths,
                            "loads_ms_identity_assets": assessment.loads_microsoft_identity_assets,
                        },
                        "page": {k: page.get(k) for k in ("url", "domain", "ip", "asn", "asnname", "tlsIssuer")},
                    },
                    observables=[Observable(type="domain", value=assessment.page_host)]
                    + ([Observable(type="ip", value=page["ip"])] if page.get("ip") else []),
                )
            )
    return signals


async def collect_clickfix(urlscan: UrlscanClient, *, query: str, size: int) -> list[IntelSignal]:
    signals: list[IntelSignal] = []
    for hit in await urlscan.search(query, size=size):
        scan_id = (hit.get("task") or {}).get("uuid") or hit.get("_id")
        if not scan_id:
            continue
        try:
            html = await urlscan.dom(scan_id)
        except httpx.HTTPStatusError:
            continue
        lure = detect_clipboard_lure(html)
        if lure is None:
            continue
        urls: set[str] = set()
        domains: set[str] = set()
        ips: set[str] = set()
        layers: list[dict[str, Any]] = []
        for payload in lure.payloads:
            res = unpack(payload)
            urls.update(res.urls)
            domains.update(res.domains)
            ips.update(res.ips)
            layers.extend({"depth": layer.depth, "technique": layer.technique} for layer in res.layers)
        page = hit.get("page") or {}
        lure_host = page.get("domain")
        if lure_host:
            domains.add(lure_host)
        signals.append(
            IntelSignal(
                source=IntelSource.URLSCAN,
                external_id=scan_id,
                attack_vector=AttackVector.CLICKFIX_FILELESS,
                title=f"ClickFix clipboard lure on {lure_host or 'unknown host'}",
                source_url=f"https://urlscan.io/result/{scan_id}/",
                raw_payload={
                    "lure_page": page.get("url"),
                    "payload_previews": [p[:500] for p in lure.payloads[:5]],
                    "unpack_layers": layers[:50],
                },
                observables=[Observable(type="url", value=u) for u in sorted(urls)]
                + [Observable(type="domain", value=d) for d in sorted(domains)]
                + [Observable(type="ip", value=i) for i in sorted(ips)],
            )
        )
    return signals
