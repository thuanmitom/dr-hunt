"""Decides what may go into an automated blocklist.

Why not "drop anything in Tranco Top 1M"? Measured against the bundled MISP warninglists, a
parent-domain lookup reports ``random-abc.trycloudflare.com``, ``evil.pages.dev``,
``attacker.github.io`` and ``evil.ngrok-free.app`` as Tranco Top-1M sites. Dropping those would
blind Vector 3/4 hunting precisely where attackers host. So the filter reasons per hostname:

* tenant-owned assets, CDN/anycast ranges, public resolvers, core vendor domains → ``drop``
* a customer subdomain on a shared platform (PSL private suffix or LOTS project entry)
  → ``block`` the exact FQDN only, never the parent
* a shared platform root or a popular (likely compromised) site → ``hunt_only``
* cloud-compute ranges (attackers rent VMs there, IPs churn) → ``hunt_only``
* everything else → ``block``
"""

from __future__ import annotations

import bisect
import ipaddress
import logging
import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from functools import lru_cache

import tldextract

from app.schemas.validators import normalize_domain

log = logging.getLogger(__name__)


class Action(StrEnum):
    BLOCK = "block"  # safe for an automated blocklist
    HUNT_ONLY = "hunt_only"  # keep as a hunting pivot, never auto-block
    DROP = "drop"  # benign / owned / unusable


@dataclass(frozen=True, slots=True)
class FilterResult:
    value: str
    kind: str  # "domain" | "ip"
    action: Action
    reason: str


# Shared services where malicious content lives at a URL path, not a hostname of its own.
SHARED_SERVICE_HOSTS = frozenset(
    {
        "api.telegram.org", "discord.com", "discordapp.com", "cdn.discordapp.com", "media.discordapp.net",
        "raw.githubusercontent.com", "objects.githubusercontent.com", "gist.githubusercontent.com",
        "github.com", "gitlab.com", "bitbucket.org", "pastebin.com", "paste.ee", "rentry.co",
        "drive.google.com", "docs.google.com", "storage.googleapis.com", "dl.dropboxusercontent.com",
        "dropbox.com", "www.dropbox.com", "onedrive.live.com", "1drv.ms", "mega.nz", "transfer.sh",
        "bit.ly", "t.co", "tinyurl.com", "is.gd",
    }
)  # fmt: skip

# Warninglist names (MISP) mapped to categories, matched case-insensitively.
CATEGORY_PATTERNS: dict[str, str] = {
    "cdn_anycast": r"cloudflare|akamai|fastly|cloudfront|imperva|incapsula|stackpath",
    "public_dns": r"dns resolver",
    "cloud_compute": r"amazon|\baws\b|azure|google cloud|\bgcp\b|oracle cloud|digitalocean|linode|ovh|vultr",
    "vendor_domains": r"known microsoft domains|known google domains",
    "top_hard": r"top 10k most-used sites from tranco",
    "popular": r"top 1,000,000 most-used sites from tranco|crux|majestic|umbrella",
    "lots": r"living off trusted sites",
}


def _intervals(networks: Iterable[str]) -> tuple[list[int], list[int]]:
    """Merge CIDRs into sorted, disjoint [start, end] integer intervals for bisect lookups."""
    spans = sorted(
        (int(n.network_address), int(n.broadcast_address))
        for n in (ipaddress.ip_network(x, strict=False) for x in networks)
    )
    starts: list[int] = []
    ends: list[int] = []
    for s, e in spans:
        if ends and s <= ends[-1] + 1:
            ends[-1] = max(ends[-1], e)
        else:
            starts.append(s)
            ends.append(e)
    return starts, ends


@dataclass
class RangeSet:
    v4: tuple[list[int], list[int]] = field(default_factory=lambda: ([], []))
    v6: tuple[list[int], list[int]] = field(default_factory=lambda: ([], []))

    @classmethod
    def from_cidrs(cls, cidrs: Iterable[str]) -> RangeSet:
        v4, v6 = [], []
        for c in cidrs:
            try:
                (v4 if ipaddress.ip_network(c.strip(), strict=False).version == 4 else v6).append(c.strip())
            except ValueError:
                continue
        return cls(_intervals(v4), _intervals(v6))

    def __contains__(self, ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
        starts, ends = self.v4 if ip.version == 4 else self.v6
        i = bisect.bisect_right(starts, int(ip)) - 1
        return i >= 0 and int(ip) <= ends[i]


@dataclass
class WhitelistSources:
    cdn_anycast: RangeSet = field(default_factory=RangeSet)
    public_dns: RangeSet = field(default_factory=RangeSet)
    cloud_compute: RangeSet = field(default_factory=RangeSet)
    vendor_domains: frozenset[str] = frozenset()
    top_hard: frozenset[str] = frozenset()
    popular: frozenset[str] = frozenset()
    lots: frozenset[str] = frozenset()
    loaded_lists: dict[str, list[str]] = field(default_factory=dict)

    @classmethod
    def from_misp(cls) -> WhitelistSources:
        """Load from the warninglists bundled with pymispwarninglists (~10 s; do it once per process)."""
        from pymispwarninglists import WarningLists

        wl = WarningLists(slow_search=False)
        buckets: dict[str, list[str]] = {k: [] for k in CATEGORY_PATTERNS}
        loaded: dict[str, list[str]] = {k: [] for k in CATEGORY_PATTERNS}
        for warninglist in wl.values():
            for category, pattern in CATEGORY_PATTERNS.items():
                if re.search(pattern, warninglist.name, re.I):
                    is_cidr = warninglist.type == "cidr"
                    if is_cidr != (category in {"cdn_anycast", "public_dns", "cloud_compute"}):
                        continue
                    buckets[category].extend(str(x) for x in warninglist.list)
                    loaded[category].append(warninglist.name)
        for category, names in loaded.items():
            log.info("whitelist category %s <- %s", category, names or "NONE")

        def domains(items: list[str]) -> frozenset[str]:
            return frozenset(d.strip().lower().lstrip("*.").rstrip(".") for d in items if d.strip())

        return cls(
            cdn_anycast=RangeSet.from_cidrs(buckets["cdn_anycast"]),
            public_dns=RangeSet.from_cidrs(buckets["public_dns"]),
            cloud_compute=RangeSet.from_cidrs(buckets["cloud_compute"]),
            vendor_domains=domains(buckets["vendor_domains"]),
            top_hard=domains(buckets["top_hard"]),
            popular=domains(buckets["popular"]),
            lots=domains(buckets["lots"]),
            loaded_lists=loaded,
        )


# Offline, deterministic PSL parsing (bundled snapshot; never fetches, never writes cache).
_PSL_PRIVATE = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=True)
_PSL_ICANN = tldextract.TLDExtract(cache_dir=None, suffix_list_urls=(), include_psl_private_domains=False)


def registrable(host: str, *, private: bool) -> str:
    r = (_PSL_PRIVATE if private else _PSL_ICANN)(host)
    return r.top_domain_under_public_suffix or host


class WhitelistFilter:
    def __init__(
        self,
        sources: WhitelistSources,
        *,
        tenant_domains: Iterable[str] = (),
        tenant_networks: Iterable[str] = (),
    ) -> None:
        self.sources = sources
        self.tenant_domains = frozenset(d.lower() for d in tenant_domains)
        self.tenant_networks = RangeSet.from_cidrs(tenant_networks)

    # --- domains ----------------------------------------------------------------------
    def check_domain(self, value: str) -> FilterResult:
        try:
            host = normalize_domain(value)
        except ValueError:
            return FilterResult(value, "domain", Action.DROP, "invalid_domain")
        s = self.sources
        parents = _parents(host)

        if any(p in self.tenant_domains for p in parents):
            return FilterResult(host, "domain", Action.DROP, "tenant_owned")
        if host in SHARED_SERVICE_HOSTS or host in s.lots:
            return FilterResult(host, "domain", Action.HUNT_ONLY, "shared_platform_root")

        reg_private = registrable(host, private=True)
        reg_icann = registrable(host, private=False)
        lots_parent = any(p in s.lots for p in parents[1:])
        if reg_private != reg_icann or lots_parent:
            # A tenant of a shared platform (evil.pages.dev, x.trycloudflare.com, a.github.io).
            return FilterResult(host, "domain", Action.BLOCK, "exact_fqdn_on_shared_platform")

        if reg_icann in s.vendor_domains:
            return FilterResult(host, "domain", Action.DROP, "vendor_core_domain")
        if reg_icann in s.top_hard or host in s.top_hard:
            return FilterResult(host, "domain", Action.DROP, "tranco_top10k")
        if reg_icann in s.popular or host in s.popular:
            # Popular but not top-tier: ClickFix lures are often injected into compromised sites.
            return FilterResult(host, "domain", Action.HUNT_ONLY, "popular_site_possible_compromise")
        return FilterResult(host, "domain", Action.BLOCK, "no_whitelist_match")

    # --- IPs --------------------------------------------------------------------------
    def check_ip(self, value: str) -> FilterResult:
        try:
            ip = ipaddress.ip_address(value.strip())
        except ValueError:
            return FilterResult(value, "ip", Action.DROP, "invalid_ip")
        v = str(ip)
        if not ip.is_global:
            return FilterResult(v, "ip", Action.DROP, "not_global")
        if ip in self.tenant_networks:
            return FilterResult(v, "ip", Action.DROP, "tenant_owned")
        if ip in self.sources.cdn_anycast:
            return FilterResult(v, "ip", Action.DROP, "cdn_anycast_range")
        if ip in self.sources.public_dns:
            return FilterResult(v, "ip", Action.DROP, "public_dns_resolver")
        if ip in self.sources.cloud_compute:
            return FilterResult(v, "ip", Action.HUNT_ONLY, "cloud_compute_range")
        return FilterResult(v, "ip", Action.BLOCK, "no_whitelist_match")

    def partition(self, domains: Iterable[str] = (), ips: Iterable[str] = ()) -> dict[Action, list[FilterResult]]:
        out: dict[Action, list[FilterResult]] = {a: [] for a in Action}
        for d in domains:
            r = self.check_domain(d)
            out[r.action].append(r)
        for i in ips:
            r = self.check_ip(i)
            out[r.action].append(r)
        return out


def _parents(host: str) -> list[str]:
    labels = host.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)]


@lru_cache(maxsize=1)
def default_sources() -> WhitelistSources:
    return WhitelistSources.from_misp()
