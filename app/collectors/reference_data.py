"""Reference datasets for Vectors 4/5/6 (+ MalwareBazaar for V1), normalised to compact records.

Parsers were written against the real published formats (Oct 2026):
* LOLDrivers  loldrivers.io/content/api/drivers.json — list; KnownVulnerableSamples[].SHA256, Tags, Category, Created
* LOLRMM      website/public/api/rmm_tools.json — list; Details.PEMetadata is a dict, a list or null;
              Artifacts.Network[].Domains
* HijackLibs  repository archive, yml/**/*.yml — Name, Created, VulnerableExecutables[].Type/Path
* OSV         <ecosystem>/modified_id.csv — "<RFC 3339 modified>,<ID>" per line, newest first (verified 2026-11-02);
              then <ecosystem>/<ID>.json per malicious-package advisory. The ecosystem all.zip is not used:
              npm/all.zip is ~220 MB, far above the 64 MB archive cap.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import re
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import yaml

from app.collectors.base import IntelSignal, Observable
from app.core.signing import canonical_json
from app.processors.stager_unpacker import extract_iocs
from app.schemas.enums import AttackVector, IntelSource

log = logging.getLogger(__name__)

MAX_ARCHIVE_BYTES = 64 * 1024 * 1024
OSV_RECORD_MAX_BYTES = 64 * 1024  # the "files 64 KB" cap; real MAL-* records are ~1-20 KB
OSV_FETCH_CONCURRENCY = 8
_OSV_MAL_ID = re.compile(r"^MAL-\d{4}-\d{1,9}$")
_SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
_TG_TOKEN = re.compile(r"\b(\d{8,10}):AA[A-Za-z0-9_-]{30,}\b")
_DISCORD_HOOK = re.compile(r"discord(?:app)?\.com/api/webhooks/(\d{15,20})/[A-Za-z0-9_-]{30,}")


@dataclass
class Dataset:
    name: str
    records: list[dict[str, Any]]
    version: str = ""
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    errors: list[str] = field(default_factory=list)  # partial failures (not part of the version hash)

    def __post_init__(self) -> None:
        self.version = hashlib.sha256(canonical_json(self.records)).hexdigest()


async def _download(client: httpx.AsyncClient, url: str, *, limit: int = MAX_ARCHIVE_BYTES) -> bytes:
    buf = bytearray()
    async with client.stream("GET", url, follow_redirects=True) as resp:
        resp.raise_for_status()
        async for chunk in resp.aiter_bytes():
            buf.extend(chunk)
            if len(buf) > limit:
                raise ValueError(f"{url} exceeds {limit} bytes")
    return bytes(buf)


# --- parsers (pure) ------------------------------------------------------------------------------
def parse_loldrivers(data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for d in data:
        hashes = sorted(
            {s["SHA256"].lower() for s in d.get("KnownVulnerableSamples") or [] if _SHA256.match(s.get("SHA256") or "")}
        )
        if hashes:
            out.append({"id": d.get("Id"), "category": d.get("Category", ""), "created": d.get("Created", ""),
                        "filenames": sorted({t.lower() for t in d.get("Tags") or [] if isinstance(t, str)}),
                        "sha256": hashes})  # fmt: skip
    return sorted(out, key=lambda r: (r["created"], r["id"] or ""), reverse=True)


def parse_lolrmm(data: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out = []
    for t in data:
        pe = (t.get("Details") or {}).get("PEMetadata")
        pes = pe if isinstance(pe, list) else [pe] if isinstance(pe, dict) else []
        files = {(p.get(k) or "").strip().lower() for p in pes for k in ("Filename", "OriginalFileName")}
        domains = {
            d.strip().lower().removeprefix("*.").rstrip(".")
            for n in (t.get("Artifacts") or {}).get("Network") or []
            for d in n.get("Domains") or []
            if isinstance(d, str) and "." in d and " " not in d.strip()
        }
        out.append({"name": t.get("Name", ""), "filenames": sorted(f for f in files if f.endswith(".exe")),
                    "domains": sorted(d for d in domains if "*" not in d)})  # fmt: skip
    return out


def parse_hijacklibs(archive: bytes) -> list[dict[str, Any]]:
    out = []
    with zipfile.ZipFile(io.BytesIO(archive)) as z:
        for name in z.namelist():
            if "/yml/" not in name or not name.endswith(".yml"):
                continue
            doc = yaml.safe_load(z.read(name)) or {}
            types = sorted({v.get("Type", "") for v in doc.get("VulnerableExecutables") or []})
            if "Sideloading" not in types or not str(doc.get("Name", "")).lower().endswith(".dll"):
                continue
            out.append({"dll": doc["Name"].lower(), "vendor": doc.get("Vendor", ""), "created": str(doc.get("Created", "")),
                        "expected_locations": doc.get("ExpectedLocations") or [], "types": types})  # fmt: skip
    return sorted(out, key=lambda r: (r["created"], r["dll"]), reverse=True)


def parse_osv_modified_index(text: str, since: datetime, limit: int) -> list[tuple[str, str]]:
    """OSV ``<ecosystem>/modified_id.csv`` -> ``[(id, modified)]`` for malicious-package advisories (MAL-*)
    modified at or after ``since``, newest first, at most ``limit``. The whole file is filtered, so the result does
    not depend on the file being strictly sorted. IDs must match ``MAL-YYYY-N`` because they become URL paths."""
    cutoff = since.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S")
    newest: dict[str, str] = {}
    for line in text.splitlines():
        modified, _, osv_id = line.strip().partition(",")
        osv_id = osv_id.strip()
        if not _OSV_MAL_ID.match(osv_id) or len(modified) < 19 or modified[:19] < cutoff:
            continue
        if modified > newest.get(osv_id, ""):
            newest[osv_id] = modified
    return sorted(newest.items(), key=lambda r: (r[1], r[0]), reverse=True)[:limit]


def parse_osv_record(adv: dict[str, Any], ecosystem: str) -> list[dict[str, Any]]:
    """One OSV advisory -> one ``{id, ecosystem, package, modified}`` record per affected package."""
    out: dict[str, dict[str, Any]] = {}
    for aff in adv.get("affected") or []:
        pkg = ((aff.get("package") or {}).get("name") or "").strip().lower()
        if pkg and adv.get("id"):
            out[pkg] = {"id": adv["id"], "ecosystem": ecosystem, "package": pkg, "modified": adv.get("modified", "")}
    return [out[k] for k in sorted(out)]


def parse_malwarebazaar(response: dict[str, Any], tag: str) -> IntelSignal | None:
    """Hashes + C2 hosts from MalwareBazaar metadata. Samples are never downloaded. Bot tokens and
    Discord webhooks are minimised to their numeric IDs plus a hash (never used, never stored whole)."""
    rows = response.get("data") or [] if response.get("query_status") == "ok" else []
    if not rows:
        return None
    observables: list[Observable] = []
    bots: set[str] = set()
    hooks: set[str] = set()
    for row in rows:
        if _SHA256.match(row.get("sha256_hash") or ""):
            observables.append(Observable(type="sha256", value=row["sha256_hash"].lower()))
        intel = json.dumps(row.get("vendor_intel") or {})
        for tok in _TG_TOKEN.finditer(intel):
            bots.add(f"{tok.group(1)}:{hashlib.sha256(tok.group(0).encode()).hexdigest()[:16]}")
        for hook in _DISCORD_HOOK.finditer(intel):
            hooks.add(hook.group(1))
        for text in _c2_strings(row.get("vendor_intel") or {}):
            _, domains, ips = extract_iocs(text)
            observables += [Observable(type="domain", value=d) for d in domains]
            observables += [Observable(type="ip", value=i) for i in ips]
    newest = max((r.get("first_seen") or "" for r in rows), default="")
    return IntelSignal(
        source=IntelSource.MALWAREBAZAAR, external_id=f"mb:{tag}:{newest}",
        attack_vector=AttackVector.IDENTITY_AITM_INFOSTEALER, title=f"MalwareBazaar recent samples tagged {tag}",
        raw_payload={"tag": tag, "samples": len(rows), "telegram_bot_ids": sorted(bots), "discord_webhook_ids": sorted(hooks)},
        observables=sorted(set(observables), key=lambda o: (o.type, o.value)),
    )  # fmt: skip


def _c2_strings(node: Any, under_c2: bool = False) -> list[str]:
    out: list[str] = []
    if isinstance(node, dict):
        for k, v in node.items():
            out += _c2_strings(v, under_c2 or bool(re.search(r"c2|c&c|server|host|url|domain|ip", str(k), re.I)))
    elif isinstance(node, list):
        for v in node:
            out += _c2_strings(v, under_c2)
    elif isinstance(node, str) and under_c2:
        out.append(node)
    return out


# --- fetchers -------------------------------------------------------------------------------------
async def fetch_loldrivers(client: httpx.AsyncClient, url: str) -> Dataset:
    return Dataset("loldrivers", parse_loldrivers(json.loads(await _download(client, url))))


async def fetch_lolrmm(client: httpx.AsyncClient, url: str) -> Dataset:
    return Dataset("lolrmm", parse_lolrmm(json.loads(await _download(client, url))))


async def fetch_hijacklibs(client: httpx.AsyncClient, url: str) -> Dataset:
    return Dataset("hijacklibs", parse_hijacklibs(await _download(client, url)))


async def _fetch_osv_ecosystem(client: httpx.AsyncClient, base_url: str, ecosystem: str, since: datetime,
                              max_ids: int, previous: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:  # fmt: skip
    """Index first, then only the advisories that are new or changed since ``previous``. Returns (records, skipped).
    A record that is missing (404), oversized or not JSON is skipped; any other error fails the whole ecosystem."""
    index = await _download(client, f"{base_url}/{ecosystem}/modified_id.csv")
    entries = parse_osv_modified_index(index.decode("utf-8", errors="replace"), since, max_ids)
    known: dict[str, list[dict[str, Any]]] = {}
    for r in previous:
        known.setdefault(r["id"], []).append(r)
    sem = asyncio.Semaphore(OSV_FETCH_CONCURRENCY)

    async def one(osv_id: str, modified: str) -> list[dict[str, Any]] | None:
        cached = known.get(osv_id)
        if cached and cached[0].get("modified") == modified:
            return cached
        async with sem:
            try:
                raw = await _download(client, f"{base_url}/{ecosystem}/{osv_id}.json", limit=OSV_RECORD_MAX_BYTES)
            except ValueError:  # over the per-record cap
                return None
            except httpx.HTTPStatusError as exc:
                if exc.response.status_code == 404:
                    return None
                raise
        try:
            return parse_osv_record(json.loads(raw), ecosystem)
        except (json.JSONDecodeError, AttributeError, TypeError):
            return None

    results = await asyncio.gather(*(one(i, m) for i, m in entries), return_exceptions=True)
    if failure := next((r for r in results if isinstance(r, BaseException)), None):
        raise failure
    records = [rec for r in results if isinstance(r, list) for rec in r]
    return records, sum(r is None for r in results)


async def fetch_osv_malicious(client: httpx.AsyncClient, base_url: str, ecosystems: list[str], lookback_days: int,
                              *, previous: list[dict[str, Any]] | None = None, max_ids: int = 1000) -> Dataset:  # fmt: skip
    """Malicious-package advisories (OSV MAL-*) modified in the lookback window, per ecosystem. A failing
    ecosystem keeps its previously stored records (so the dataset does not flap) and is reported in ``errors``."""
    since = datetime.now(UTC) - timedelta(days=lookback_days)
    base = base_url.rstrip("/")
    records: list[dict[str, Any]] = []
    errors: list[str] = []
    for eco in ecosystems:
        prev_eco = [r for r in previous or [] if r.get("ecosystem") == eco]
        try:
            recs, skipped = await _fetch_osv_ecosystem(client, base, eco, since, max_ids, prev_eco)
            if skipped:
                log.info("osv %s: %d advisories skipped (missing, oversized or invalid)", eco, skipped)
        except Exception as exc:  # noqa: BLE001 — one ecosystem must not drop the others
            log.warning("osv %s failed, keeping %d stored records: %s", eco, len(prev_eco), type(exc).__name__)
            errors.append(f"osv_malicious/{eco}: {type(exc).__name__}")
            recs = prev_eco
        records += recs
    unique = {(r["id"], r["package"]): r for r in records}
    ordered = sorted(unique.values(), key=lambda r: (r["modified"], r["package"], r["id"]), reverse=True)
    return Dataset("osv_malicious", ordered, errors=errors)


async def fetch_malwarebazaar(
    client: httpx.AsyncClient, url: str, auth_key: str, tag: str, limit: int = 100
) -> IntelSignal | None:
    resp = await client.post(
        url, data={"query": "get_taginfo", "tag": tag, "limit": str(limit)}, headers={"Auth-Key": auth_key}
    )
    resp.raise_for_status()
    return parse_malwarebazaar(resp.json(), tag)


DATASET_VECTOR = {
    "loldrivers": (IntelSource.LOLDRIVERS, AttackVector.BYOVD_DLL_SIDELOAD),
    "hijacklibs": (IntelSource.HIJACKLIBS, AttackVector.BYOVD_DLL_SIDELOAD),
    "lolrmm": (IntelSource.LOLRMM, AttackVector.LOTS_RMM_TUNNEL),
    "osv_malicious": (IntelSource.OSV, AttackVector.SUPPLY_CHAIN_SEO),
}


def dataset_signal(ds: Dataset, previous_ids: set[str]) -> IntelSignal:
    source, vector = DATASET_VECTOR[ds.name]
    key = {"loldrivers": "id", "hijacklibs": "dll", "lolrmm": "name", "osv_malicious": "id"}[ds.name]
    new = [r[key] for r in ds.records if r.get(key) and r[key] not in previous_ids]
    return IntelSignal(
        source=source, external_id=f"{ds.name}:{ds.version[:16]}", attack_vector=vector,
        title=f"{ds.name} updated: {len(ds.records)} records, {len(new)} new",
        raw_payload={"dataset": ds.name, "version": ds.version, "records": len(ds.records), "new": new[:50],
                     "new_count": len(new)},
    )  # fmt: skip
