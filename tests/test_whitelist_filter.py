from __future__ import annotations

import pytest

from app.processors.whitelist_filter import Action, RangeSet, WhitelistFilter, WhitelistSources, default_sources


@pytest.fixture(scope="module")
def synthetic() -> WhitelistFilter:
    sources = WhitelistSources(
        cdn_anycast=RangeSet.from_cidrs(["104.16.0.0/13"]),
        public_dns=RangeSet.from_cidrs(["1.1.1.1/32", "8.8.8.8/32"]),
        cloud_compute=RangeSet.from_cidrs(["13.64.0.0/10"]),
        vendor_domains=frozenset({"microsoftonline.com", "google.com"}),
        top_hard=frozenset({"github.com", "wikipedia.org"}),
        popular=frozenset({"small-bakery-blog.com", "github.com"}),
        lots=frozenset({"pages.dev", "github.io", "trycloudflare.com", "sharepoint.com"}),
    )
    return WhitelistFilter(sources, tenant_domains=["tencongty.vn"], tenant_networks=["203.0.113.0/28"])


@pytest.mark.parametrize(
    "domain,action,reason",
    [
        ("sso.tencongty.vn", Action.DROP, "tenant_owned"),
        ("tencongty.vn.evil.example", Action.BLOCK, "no_whitelist_match"),
        ("evil.pages.dev", Action.BLOCK, "exact_fqdn_on_shared_platform"),
        ("random-abc.trycloudflare.com", Action.BLOCK, "exact_fqdn_on_shared_platform"),
        ("victim-tenant.sharepoint.com", Action.BLOCK, "exact_fqdn_on_shared_platform"),
        ("pages.dev", Action.HUNT_ONLY, "shared_platform_root"),
        ("api.telegram.org", Action.HUNT_ONLY, "shared_platform_root"),
        ("login.microsoftonline.com", Action.DROP, "vendor_core_domain"),
        ("en.wikipedia.org", Action.DROP, "tranco_top10k"),
        ("www.small-bakery-blog.com", Action.HUNT_ONLY, "popular_site_possible_compromise"),
        ("not a domain", Action.DROP, "invalid_domain"),
    ],
)
def test_domain_decisions(synthetic, domain, action, reason):
    r = synthetic.check_domain(domain)
    assert (r.action, r.reason) == (action, reason)


@pytest.mark.parametrize(
    "ip,action,reason",
    [
        ("104.16.1.1", Action.DROP, "cdn_anycast_range"),
        ("1.1.1.1", Action.DROP, "public_dns_resolver"),
        ("13.107.42.14", Action.HUNT_ONLY, "cloud_compute_range"),
        ("203.0.113.5", Action.DROP, "not_global"),
        ("10.0.0.5", Action.DROP, "not_global"),
        ("45.155.205.10", Action.BLOCK, "no_whitelist_match"),
    ],
)
def test_ip_decisions(synthetic, ip, action, reason):
    r = synthetic.check_ip(ip)
    assert (r.action, r.reason) == (action, reason)


def test_real_misp_warninglists_categories_and_shared_hosting():
    """Loads the real bundled warninglists (~10 s) and re-checks the cases that motivated the design."""
    sources = default_sources()
    for category in ("cdn_anycast", "public_dns", "cloud_compute", "vendor_domains", "top_hard", "popular", "lots"):
        assert sources.loaded_lists[category], f"no warninglist matched category {category}"
    wf = WhitelistFilter(sources)
    for host in ("random-abc.trycloudflare.com", "evil.pages.dev", "attacker.github.io", "evil.ngrok-free.app"):
        assert wf.check_domain(host).action is Action.BLOCK, host
    assert wf.check_domain("login.microsoftonline.com").action is Action.DROP
    assert wf.check_ip("104.16.1.1").action is Action.DROP
    assert wf.check_ip("1.1.1.1").action is Action.DROP
