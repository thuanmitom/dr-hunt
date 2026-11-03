"""Active pivoting on suspicious infrastructure: JARM, favicon MurmurHash3, Shodan/URLScan lookups,
and AiTM (Evilginx-style) indicators from URLScan results.

Operational notes:
* Only hosts that are already suspicious are touched, at low rate, from the HuntCompiler egress IP
  (never from a tenant network). Active probes can tip off an operator — keep volumes small.
* JARM alone is weak evidence: Go-based phishing kits share the Go TLS stack's JARM with many
  legitimate Go servers. Combine with path indicators before raising confidence.
* Every probe goes through ``app.core.netguard``: public addresses only, ports 443/80, the validated IP is
  pinned for the connection, and redirects are re-validated (SSRF defence).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
import mmh3

from app.core.netguard import BlockedTarget, Resolver, guarded_get, resolve_public
from app.schemas.validators import normalize_jarm

log = logging.getLogger(__name__)

MAX_FAVICON_BYTES = 512 * 1024  # applies to the page and to the icon
_ICON_LINK = re.compile(
    r"<link[^>]+rel=[\"'](?:shortcut\s+)?icon[\"'][^>]*href=[\"']([^\"']+)[\"']"
    r"|<link[^>]+href=[\"']([^\"']+)[\"'][^>]*rel=[\"'](?:shortcut\s+)?icon[\"']",
    re.I,
)

# Microsoft identity endpoints that an AiTM reverse proxy relays on a non-Microsoft hostname.
AITM_PATH_MARKERS: tuple[str, ...] = (
    "/common/oauth2/v2.0/authorize",
    "/common/oauth2/authorize",
    "/common/getcredentialtype",
    "/common/sas/beginauth",
    "/common/sas/processauth",
    "/common/login",
    "/kmsi",
    "/common/devicecode",
)
MICROSOFT_IDENTITY_HOSTS = frozenset(
    {"login.microsoftonline.com", "login.live.com", "login.microsoft.com", "aadcdn.msftauth.net",
     "aadcdn.msauth.net", "logincdn.msauth.net", "login.windows.net"}
)  # fmt: skip


# --- JARM ---------------------------------------------------------------------------------------
async def jarm_fingerprint(host: str, port: int = 443, *, timeout: int = 10,
                           resolver: Resolver | None = None) -> str | None:  # fmt: skip
    """Returns the 62-char JARM, or None when the host gives no TLS answer or is not a public target."""
    try:
        target = await resolve_public(host, port, resolver=resolver)
    except BlockedTarget as exc:
        log.warning("jarm probe refused: %s", exc)
        return None
    try:
        value = await asyncio.wait_for(_pinned_jarm(target.host, target.ip, port, timeout), timeout=timeout * 12)
    except (TimeoutError, OSError):
        return None
    try:
        return normalize_jarm(value)
    except ValueError:  # all-zero JARM => no TLS response
        return None


async def _pinned_jarm(sni_host: str, ip: str, port: int, timeout: int) -> str:
    """``Scanner.scan_async`` uses one ``dest_host`` both for the SNI in the hellos and for the TCP connection,
    which it resolves again. This re-assembles it from pyjarm's own building blocks so the hellos carry the
    hostname while the connection goes to the validated IP. pyjarm is hash-pinned at 0.0.5; these internal helpers
    are covered by tests/test_netguard.py."""
    from jarm.connection.connection import Connection
    from jarm.constants import TOTAL_FAILURE
    from jarm.hashing.hashing import Hasher
    from jarm.scanner.scanner import Scanner

    packets = Scanner._generate_packets(dest_host=sni_host, dest_port=port)
    connect_args = {"address_family": Connection.AddressFamily.AF_ANY, "proxy": None, "proxy_auth": None,
                    "verify": True, "timeout": timeout}  # fmt: skip
    tasks = [Connection.jarm_connect((ip, port), connect_args, data, name) for name, data in packets]
    try:
        results = await Scanner.gather_with_concurrency(2, *tasks)
    except Exception:  # noqa: BLE001 — same contract as Scanner.scan_async(suppress=True)
        return Hasher.jarm(TOTAL_FAILURE)
    parsed = [Scanner._parse_server_hello(r[1], p) for p in packets for r in results if p[0] == r[0]]
    return Hasher.jarm(",".join(parsed))


# --- Favicon --------------------------------------------------------------------------------------
def favicon_mmh3(data: bytes) -> int:
    """Shodan-compatible favicon hash: signed MurmurHash3 of base64 with 76-char line breaks."""
    return mmh3.hash(base64.encodebytes(data))


def find_icon_url(page_url: str, html: str) -> str:
    m = _ICON_LINK.search(html)
    href = (m.group(1) or m.group(2)) if m else "/favicon.ico"
    return urljoin(page_url, href)


async def fetch_favicon_hash(client: httpx.AsyncClient, page_url: str, *,
                             resolver: Resolver | None = None) -> tuple[str, int] | None:  # fmt: skip
    """(icon URL, Shodan favicon hash). Both requests go through the SSRF guard; an icon over the cap is ignored."""
    try:
        page = await guarded_get(client, page_url, max_bytes=MAX_FAVICON_BYTES, resolver=resolver)
        icon_url = find_icon_url(page.url, page.text if page.status_code == 200 else "")
        icon = await guarded_get(client, icon_url, max_bytes=MAX_FAVICON_BYTES, resolver=resolver)
    except BlockedTarget as exc:
        log.warning("favicon probe refused: %s", exc)
        return None
    except httpx.HTTPError:
        return None
    if icon.status_code != 200 or icon.truncated or not icon.body:
        return None
    return icon.url, favicon_mmh3(icon.body)


# --- Pivot search adapters -------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class PivotHit:
    ip: str
    port: int | None
    hostnames: tuple[str, ...]
    via: str  # "shodan:jarm" | "shodan:favicon" | "urlscan:<query>"


class PivotUnavailable(RuntimeError):
    """Provider refused the query (plan limits, missing key) — not an empty result."""


class ShodanPivot:
    def __init__(self, client: httpx.AsyncClient, api_key: str, base_url: str = "https://api.shodan.io") -> None:
        self._client, self._key, self._base = client, api_key, base_url.rstrip("/")

    async def _search(self, query: str, via: str, limit: int) -> list[PivotHit]:
        resp = await self._client.get(f"{self._base}/shodan/host/search", params={"key": self._key, "query": query})
        if resp.status_code in (401, 403):
            raise PivotUnavailable(f"shodan refused filter query ({resp.status_code}); a paid plan is required")
        resp.raise_for_status()
        return [
            PivotHit(m.get("ip_str", ""), m.get("port"), tuple(m.get("hostnames") or ()), via)
            for m in resp.json().get("matches", [])[:limit]
        ]

    async def by_jarm(self, jarm: str, limit: int = 100) -> list[PivotHit]:
        return await self._search(f"ssl.jarm:{normalize_jarm(jarm)}", "shodan:jarm", limit)

    async def by_favicon(self, favicon_hash: int, limit: int = 100) -> list[PivotHit]:
        return await self._search(f"http.favicon.hash:{int(favicon_hash)}", "shodan:favicon", limit)


# --- AiTM analysis of a URLScan result -----------------------------------------------------------
@dataclass
class AitmAssessment:
    page_host: str
    proxied_identity_paths: list[str] = field(default_factory=list)
    loads_microsoft_identity_assets: bool = False
    suspicious_jarm: bool = False
    score: int = 0

    @property
    def is_aitm_candidate(self) -> bool:
        return self.score >= 60


def assess_aitm(
    result: dict[str, Any], *, jarm: str | None = None, bad_jarms: frozenset[str] = frozenset()
) -> AitmAssessment:
    """Score a URLScan result (``/api/v1/result/<uuid>/`` JSON) for reverse-proxy phishing."""
    page_url = (result.get("page") or {}).get("url") or (result.get("task") or {}).get("url") or ""
    page_host = (urlsplit(page_url).hostname or "").lower()
    assessment = AitmAssessment(page_host=page_host)
    if not page_host or page_host in MICROSOFT_IDENTITY_HOSTS:
        return assessment

    paths: set[str] = set()
    for entry in (result.get("data") or {}).get("requests", []):
        url = ((entry.get("request") or {}).get("request") or {}).get("url", "")
        parts = urlsplit(url)
        host, path = (parts.hostname or "").lower(), parts.path.lower()
        if host in MICROSOFT_IDENTITY_HOSTS:
            assessment.loads_microsoft_identity_assets = True
        elif host == page_host or host.endswith("." + page_host):
            paths.update(marker for marker in AITM_PATH_MARKERS if path.startswith(marker))

    assessment.proxied_identity_paths = sorted(paths)
    assessment.suspicious_jarm = bool(jarm and jarm in bad_jarms)
    score = 0
    if paths:
        score += 50 + 10 * min(len(paths) - 1, 3)
    if assessment.loads_microsoft_identity_assets:
        score += 15
    if assessment.suspicious_jarm:
        score += 15  # corroborating only
    assessment.score = min(score, 100)
    return assessment
