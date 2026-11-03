"""Outbound guard for active probes (SSRF defence).

HuntCompiler probes hosts taken from attacker-controlled intelligence (JARM, favicon). A "malicious" domain can
resolve to 127.0.0.1, an RFC 1918 address, a container on the backend network or 169.254.169.254. Rules:

* resolve first, and refuse the target unless **every** resolved address is globally routable;
* only ports 443 and 80;
* connect to the validated IP (pinned) with ``Host`` and TLS SNI set to the hostname, so DNS cannot change the
  destination between the check and the connection (no DNS-rebinding window);
* follow redirects manually, at most 3, re-validating every hop.
"""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

ALLOWED_PORTS = frozenset({80, 443})
MAX_REDIRECTS = 3
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

Resolver = Callable[[str, int], Awaitable[list[str]]]


class BlockedTarget(ValueError):
    """The destination is not a public address on an allowed port."""


async def system_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    return sorted({str(info[4][0]) for info in infos})


def is_public_ip(value: str) -> bool:
    """Globally routable unicast only: no loopback, RFC 1918, CGNAT, link-local (169.254/16, fe80::/10), ULA,
    multicast, reserved or unspecified. IPv4-mapped IPv6 is judged by its IPv4 address."""
    try:
        ip = ipaddress.ip_address(value.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (
        ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved or ip.is_unspecified
    )


def _ip_literal(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


@dataclass(frozen=True, slots=True)
class PinnedTarget:
    host: str
    port: int
    ips: tuple[str, ...]

    @property
    def ip(self) -> str:
        return self.ips[0]


async def resolve_public(host: str, port: int, *, resolver: Resolver | None = None) -> PinnedTarget:
    """Validated destination, or ``BlockedTarget``."""
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        raise BlockedTarget("empty host")
    if port not in ALLOWED_PORTS:
        raise BlockedTarget(f"port {port} is not allowed")
    if (literal := _ip_literal(host)) is not None:
        ips = [literal]
    else:
        try:
            ips = await (resolver or system_resolver)(host, port)
        except OSError as exc:
            raise BlockedTarget(f"{host} does not resolve ({type(exc).__name__})") from None
    if not ips:
        raise BlockedTarget(f"{host} has no address")
    if bad := sorted(ip for ip in ips if not is_public_ip(ip)):
        raise BlockedTarget(f"{host} resolves to non-global address(es) {bad}")
    return PinnedTarget(host, port, tuple(ips))


@dataclass(frozen=True, slots=True)
class GuardedResponse:
    url: str  # final URL, with the hostname (never the pinned IP)
    status_code: int
    body: bytes
    truncated: bool

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


async def guarded_get(
    client: httpx.AsyncClient,
    url: str,
    *,
    max_bytes: int,
    resolver: Resolver | None = None,
    max_redirects: int = MAX_REDIRECTS,
) -> GuardedResponse:
    """GET through the guard. The body is read up to ``max_bytes`` (``truncated`` tells if there was more).
    Raises ``BlockedTarget`` for a refused hop or too many redirects; transport errors are ``httpx.HTTPError``."""
    current = url
    for _ in range(max_redirects + 1):
        parts = urlsplit(current)
        if parts.scheme not in ("http", "https"):
            raise BlockedTarget(f"scheme {parts.scheme!r} is not allowed")
        host = (parts.hostname or "").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        target = await resolve_public(host, port, resolver=resolver)
        ip_netloc = f"[{target.ip}]" if ":" in target.ip else target.ip
        host_header = f"[{host}]" if ":" in host else host
        if parts.port:
            ip_netloc += f":{parts.port}"
            host_header += f":{parts.port}"
        pinned = urlunsplit((parts.scheme, ip_netloc, parts.path or "/", parts.query, ""))
        extensions = {"sni_hostname": host} if parts.scheme == "https" and _ip_literal(host) is None else {}
        headers = {"Host": host_header, "Connection": "close"}  # no pooled reuse across hostnames on one IP
        async with client.stream("GET", pinned, headers=headers, extensions=extensions, follow_redirects=False) as resp:
            location = resp.headers.get("location")
            if resp.status_code in REDIRECT_STATUSES and location:
                current = urljoin(current, location)
                continue
            buf = bytearray()
            truncated = False
            async for chunk in resp.aiter_bytes():
                buf.extend(chunk)
                if len(buf) > max_bytes:
                    del buf[max_bytes:]
                    truncated = True
                    break
            return GuardedResponse(urlunsplit(parts), resp.status_code, bytes(buf), truncated)
    raise BlockedTarget(f"more than {max_redirects} redirects starting at {url}")
