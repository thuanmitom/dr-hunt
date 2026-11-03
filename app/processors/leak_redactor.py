"""Turns leak / stealer-log text into *pseudonymous* account exposures. Passwords are never
returned, stored or logged — they are dropped at parse time.

An account is represented by ``ref = HMAC-SHA256(account_key, lower(account))`` where
``account_key = HMAC-SHA256(tenant_hmac_secret, "account-ref/v1")``. Only the tenant SOAR, which
holds the same secret and its own directory, can turn a ref back into a user. HuntCompiler keeps
the ref plus a masked display form (``n***n@tencongty.vn``) and never the identity itself.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

ACCOUNT_REF_CONTEXT = b"account-ref/v1"
_BLOCK_URL = re.compile(r"^\s*(?:url|host|link|site)\s*[:=]\s*(\S+)", re.I)
_BLOCK_USER = re.compile(r"^\s*(?:user(?:name)?|login|email|account)\s*[:=]\s*(\S+)", re.I)
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
_SEPARATORS = re.compile(r"[:|;\t ]")
STEALER_FAMILIES = re.compile(r"\b(lumma|redline|stealc|vidar|raccoon|risepro|meta ?stealer|rhadamanthys|acr)\b", re.I)


@dataclass(frozen=True, slots=True)
class AccountExposure:
    ref: str
    masked: str
    host: str | None


def account_key(tenant_secret: str) -> bytes:
    return hmac.new(tenant_secret.encode(), ACCOUNT_REF_CONTEXT, hashlib.sha256).digest()


def account_ref(key: bytes, account: str) -> str:
    return hmac.new(key, account.strip().lower().encode(), hashlib.sha256).hexdigest()


def mask_account(account: str) -> str:
    local, _, domain = account.strip().lower().partition("@")
    shown = f"{local[0]}***{local[-1]}" if len(local) > 2 else f"{local[:1]}***"
    return f"{shown}@{domain}" if domain else shown


def _host_of(raw: str) -> str:
    raw = raw.strip()
    if "://" not in raw:
        raw = "http://" + raw
    return (urlsplit(raw).hostname or "").lower()


def _relevant_host(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def find_exposures(
    text: str, *, domains: list[str], portal_hosts: list[str], key: bytes
) -> tuple[list[AccountExposure], int]:
    """Returns (unique exposures, number of matching lines). Handles three common shapes:
    ``URL:/Username:/Password:`` blocks, ``url:login:pass`` (ULP) lines and ``email:pass`` lines."""
    doms = tuple(d.lower() for d in domains)
    portals = tuple(h.lower() for h in portal_hosts)
    found: dict[str, AccountExposure] = {}
    matched_lines = 0
    block_host: str | None = None

    def add(account: str, host: str | None) -> None:
        account = account.strip().strip("'\"")
        if not account or len(account) > 256:
            return
        ref = account_ref(key, account)
        found.setdefault(ref, AccountExposure(ref, mask_account(account), host))

    for line in text.splitlines():
        if m := _BLOCK_URL.match(line):
            block_host = _host_of(m.group(1))
            continue
        if m := _BLOCK_USER.match(line):
            user = m.group(1)
            email_domain = user.lower().partition("@")[2]
            if (block_host and (block_host in portals or _relevant_host(block_host, doms))) or (
                email_domain and _relevant_host(email_domain, doms)
            ):
                add(user, block_host)
                matched_lines += 1
            continue
        stripped = line.strip()
        if not stripped:
            block_host = None
            continue
        body = re.sub(r"^[a-z][a-z0-9+.-]*://", "", stripped, flags=re.I)
        parts = _SEPARATORS.split(body)
        if len(parts) >= 3:  # ULP: host[/path]:login:password
            host = _host_of(parts[0].split("/")[0])
            if host in portals or _relevant_host(host, doms):
                add(parts[1], host)
                matched_lines += 1
                continue
        for email in _EMAIL.findall(stripped):  # email:password
            if _relevant_host(email.lower().partition("@")[2], doms):
                add(email, None)
                matched_lines += 1
    return list(found.values()), matched_lines


def stealer_family_hints(text: str) -> list[str]:
    return sorted({m.lower().replace(" ", "") for m in STEALER_FAMILIES.findall(text)})
