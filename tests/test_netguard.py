"""SSRF guard for active probes. Resolver and transports are fakes: no real network."""

from __future__ import annotations

import httpx
import pytest

from app.core.netguard import BlockedTarget, guarded_get, is_public_ip, resolve_public
from app.processors import pivot

PUBLIC = "8.8.4.4"


def resolver(table: dict[str, list[str]]):
    async def resolve(host: str, port: int) -> list[str]:
        if host not in table:
            raise OSError("NXDOMAIN")
        return table[host]

    return resolve


async def never_resolve(host: str, port: int) -> list[str]:
    raise AssertionError("must not resolve")


@pytest.mark.parametrize(
    "ip",
    ["127.0.0.1", "10.0.0.5", "172.16.3.4", "192.168.1.1", "100.64.0.1", "169.254.169.254", "0.0.0.0",
     "224.0.0.1", "255.255.255.255", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.5", "nonsense"],
)  # fmt: skip
def test_non_global_addresses_are_not_public(ip):
    assert not is_public_ip(ip)


def test_global_addresses_are_public():
    assert is_public_ip(PUBLIC) and is_public_ip("2001:4860:4860::8844")


@pytest.mark.parametrize("ips", [["127.0.0.1"], ["10.0.0.5"], ["169.254.169.254"], [PUBLIC, "10.0.0.5"], []])
async def test_hosts_resolving_to_private_or_no_addresses_are_refused(ips):
    with pytest.raises(BlockedTarget):
        await resolve_public("evil.example", 443, resolver=resolver({"evil.example": ips}))


async def test_unresolvable_host_and_disallowed_port_are_refused():
    with pytest.raises(BlockedTarget, match="does not resolve"):
        await resolve_public("missing.example", 443, resolver=resolver({}))
    with pytest.raises(BlockedTarget, match="port 8080"):
        await resolve_public("evil.example", 8080, resolver=never_resolve)


async def test_private_ip_literal_is_refused_without_dns():
    with pytest.raises(BlockedTarget):
        await resolve_public("169.254.169.254", 80, resolver=never_resolve)
    assert (await resolve_public(PUBLIC, 443, resolver=never_resolve)).ip == PUBLIC


async def test_public_host_is_pinned_with_host_header_and_sni():
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, content=b"<html></html>")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resp = await guarded_get(client, "https://evil.example/login?a=1", max_bytes=100,
                                 resolver=resolver({"evil.example": [PUBLIC]}))  # fmt: skip
    [req] = seen
    assert req.url.host == PUBLIC and req.url.path == "/login" and req.url.query == b"a=1"
    assert req.headers["host"] == "evil.example" and req.extensions["sni_hostname"] == "evil.example"
    assert resp.url == "https://evil.example/login?a=1" and resp.status_code == 200 and not resp.truncated


@pytest.mark.parametrize("location", ["http://internal.example/admin", "http://169.254.169.254/latest/meta-data/",
                                      "http://127.0.0.1/", "https://evil.example:8443/"])  # fmt: skip
async def test_redirect_to_a_refused_target_stops_before_connecting(location):
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(302, headers={"Location": location})

    table = {"evil.example": [PUBLIC], "internal.example": ["10.0.0.5"]}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(BlockedTarget):
            await guarded_get(client, "https://evil.example/", max_bytes=100, resolver=resolver(table))
    assert seen == [f"https://{PUBLIC}/"]  # only the first, validated hop was contacted


async def test_redirect_chain_is_bounded_and_public_hops_are_followed():
    hops: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hops.append(request.headers["host"])
        if request.headers["host"] == "a.example":
            return httpx.Response(301, headers={"Location": "https://b.example/final"})
        if request.headers["host"] == "b.example":
            return httpx.Response(200, content=b"ok")
        return httpx.Response(302, headers={"Location": "https://loop.example/"})

    table = {"a.example": [PUBLIC], "b.example": [PUBLIC], "loop.example": [PUBLIC]}
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        resp = await guarded_get(client, "https://a.example/", max_bytes=100, resolver=resolver(table))
        assert resp.url == "https://b.example/final" and resp.body == b"ok"
        with pytest.raises(BlockedTarget, match="redirects"):
            await guarded_get(client, "https://loop.example/", max_bytes=100, resolver=resolver(table))
    assert hops.count("loop.example") == 4  # first request + 3 redirects


async def test_body_is_capped():
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, content=b"x" * 50))) as c:
        resp = await guarded_get(
            c, "https://evil.example/", max_bytes=10, resolver=resolver({"evil.example": [PUBLIC]})
        )
    assert resp.body == b"x" * 10 and resp.truncated


async def test_favicon_probe_never_contacts_a_private_target():
    seen: list[httpx.Request] = []
    transport = httpx.MockTransport(lambda r: seen.append(r) or httpx.Response(200, content=b"icon"))
    async with httpx.AsyncClient(transport=transport) as client:
        out = await pivot.fetch_favicon_hash(
            client, "https://evil.example/", resolver=resolver({"evil.example": ["127.0.0.1"]})
        )
    assert out is None and seen == []


async def test_favicon_probe_hashes_the_icon_of_a_public_host():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(200, text='<link rel="icon" href="/static/fav.ico">')
        return httpx.Response(200, content=b"\x00\x01icon-bytes")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        out = await pivot.fetch_favicon_hash(
            client, "https://evil.example/", resolver=resolver({"evil.example": [PUBLIC]})
        )
    assert out == ("https://evil.example/static/fav.ico", pivot.favicon_mmh3(b"\x00\x01icon-bytes"))


async def test_jarm_hellos_carry_the_hostname_but_go_to_the_validated_ip(monkeypatch):
    from jarm.connection.connection import Connection

    calls: list[tuple[tuple[str, int], bytes]] = []

    async def fake_connect(target, connect_args, data, check):
        calls.append((target, data))
        return check, None  # no ServerHello

    monkeypatch.setattr(Connection, "jarm_connect", staticmethod(fake_connect))
    out = await pivot.jarm_fingerprint("evil.example", resolver=resolver({"evil.example": [PUBLIC]}))
    assert out is None  # no TLS answer -> all-zero JARM -> None
    assert len(calls) == 10 and all(target == (PUBLIC, 443) for target, _ in calls)
    assert all(b"evil.example" in data for _, data in calls)


async def test_jarm_refuses_private_targets(monkeypatch):
    from jarm.connection.connection import Connection

    async def must_not_connect(*_args):
        raise AssertionError("connected to a refused target")

    monkeypatch.setattr(Connection, "jarm_connect", staticmethod(must_not_connect))
    assert await pivot.jarm_fingerprint("evil.example", resolver=resolver({"evil.example": ["10.0.0.5"]})) is None
    assert await pivot.jarm_fingerprint("evil.example", 8443, resolver=resolver({"evil.example": [PUBLIC]})) is None
