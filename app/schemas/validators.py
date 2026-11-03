"""Reusable normalisers/validators for observables. Pure functions, no I/O."""

from __future__ import annotations

import ipaddress
import re

import idna

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")
_HASH_RE = re.compile(r"^(?:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")  # md5/imphash, sha1, sha256
_JARM_RE = re.compile(r"^[0-9a-f]{62}$")
_MITRE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_TECH_TAG_RE = re.compile(r"^[a-z0-9][a-z0-9_.+-]*:[a-z0-9][a-z0-9_.+-]*$")
_TELEMETRY_RE = re.compile(r"^[a-z0-9_]+(?::[a-z0-9_.-]+)?$")

# Automated blocklists must never contain whole provider ranges.
_MIN_BLOCK_PREFIX = {4: 24, 6: 48}

_INTERNAL_V4 = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]
_INTERNAL_V6 = [ipaddress.ip_network("fc00::/7")]


def normalize_domain(value: str, *, allow_wildcard: bool = False) -> str:
    v = value.strip().lower().rstrip(".")
    prefix = ""
    if v.startswith("*."):
        if not allow_wildcard:
            raise ValueError(f"wildcard not allowed here: {value!r}")
        prefix, v = "*.", v[2:]
    try:
        ascii_name = idna.encode(v, uts46=True).decode("ascii")
    except idna.IDNAError as exc:
        raise ValueError(f"invalid domain {value!r}: {exc}") from exc
    if len(ascii_name) > 253 or not _DOMAIN_RE.match(ascii_name):
        raise ValueError(f"invalid domain {value!r}")
    return prefix + ascii_name


def normalize_block_ip(value: str) -> str:
    """Public, narrow IP or CIDR suitable for an automated blocklist."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid IP/CIDR {value!r}") from exc
    if not net.is_global:
        raise ValueError(f"{value!r} is not globally routable")
    if net.prefixlen < _MIN_BLOCK_PREFIX[net.version]:
        raise ValueError(f"{value!r} is too broad for an automated blocklist")
    return str(net.network_address) if net.num_addresses == 1 else str(net)


def normalize_owned_network(value: str) -> str:
    """A tenant-owned public range. Rejects RFC1918/CGNAT/ULA/loopback/link-local/multicast."""
    try:
        net = ipaddress.ip_network(value.strip(), strict=False)
    except ValueError as exc:
        raise ValueError(f"invalid IP/CIDR {value!r}") from exc
    internal = _INTERNAL_V4 if net.version == 4 else _INTERNAL_V6
    if (
        net.is_loopback
        or net.is_link_local
        or net.is_multicast
        or net.is_unspecified
        or any(net.overlaps(n) for n in internal)  # type: ignore[arg-type]
    ):
        raise ValueError(f"{value!r} is an internal/non-public range; the manifest holds public data only")
    return str(net)


def normalize_hash(value: str) -> str:
    v = value.strip().lower()
    if not _HASH_RE.match(v):
        raise ValueError(f"not an MD5/SHA1/SHA256/imphash hex digest: {value!r}")
    return v


def normalize_jarm(value: str) -> str:
    v = value.strip().lower()
    if not _JARM_RE.match(v):
        raise ValueError(f"not a 62-char JARM fingerprint: {value!r}")
    if set(v) == {"0"}:
        raise ValueError("all-zero JARM means 'no TLS response' and would match unrelated hosts")
    return v


def validate_mitre(value: str) -> str:
    v = value.strip().upper()
    if not _MITRE_RE.match(v):
        raise ValueError(f"invalid ATT&CK technique id {value!r} (expected T1234 or T1234.001)")
    return v


def normalize_tech_tag(value: str) -> str:
    v = value.strip().lower()
    if not _TECH_TAG_RE.match(v):
        raise ValueError(f"tech stack tag must be 'vendor:product' (CPE naming), got {value!r}")
    return v


def normalize_telemetry(value: str) -> str:
    v = value.strip().lower()
    if not _TELEMETRY_RE.match(v):
        raise ValueError(f"telemetry tag must look like 'sysmon:13' or 'entra_signin', got {value!r}")
    return v


def unique_sorted(values: list[str]) -> list[str]:
    """Deterministic ordering keeps content hashes stable across re-compilations."""
    return sorted(set(values))
