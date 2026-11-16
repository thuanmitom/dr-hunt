"""Resolve ``affected_accounts[].ref`` against your own directory (DECISIONS.md D-09).

HuntCompiler never holds identities: an exposed account travels as
``ref = HMAC_SHA256(HMAC_SHA256(tenant_secret, "account-ref/v1"), lower(account))``. Only you hold both the secret
and the directory, so only you can turn refs back into users. The directory is a CSV export with a header row and
the columns ``upn``, ``sam`` and (optional) ``mail``. A leaked line may name the UPN, the e-mail address or just the
sAMAccountName, so all three are tried.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
from dataclasses import dataclass
from pathlib import Path

ACCOUNT_REF_CONTEXT = b"account-ref/v1"


def account_key(tenant_secret: str) -> bytes:
    return hmac.new(tenant_secret.encode(), ACCOUNT_REF_CONTEXT, hashlib.sha256).digest()


def account_ref(key: bytes, account: str) -> str:
    return hmac.new(key, account.strip().lower().encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class DirectoryUser:
    upn: str
    sam: str
    mail: str = ""


def load_directory(path: str | Path) -> list[DirectoryUser]:
    with Path(path).open(encoding="utf-8-sig", newline="") as fh:
        rows = csv.DictReader(fh)
        return [DirectoryUser((r.get("upn") or "").strip(), (r.get("sam") or "").strip(), (r.get("mail") or "").strip())
                for r in rows if (r.get("upn") or r.get("sam"))]  # fmt: skip


@dataclass(frozen=True, slots=True)
class Resolution:
    upns: list[str]
    sams: list[str]
    unresolved: int


def resolve(affected: list[dict], directory: list[DirectoryUser], tenant_secret: str) -> Resolution:
    key = account_key(tenant_secret)
    by_ref: dict[str, DirectoryUser] = {}
    for user in directory:
        for name in (user.upn, user.sam, user.mail):
            if name:
                by_ref.setdefault(account_ref(key, name), user)
    users = [by_ref[a["ref"]] for a in affected if a.get("ref") in by_ref]
    return Resolution(
        upns=sorted({u.upn for u in users if u.upn}),
        sams=sorted({u.sam for u in users if u.sam}),
        unresolved=sum(a.get("ref") not in by_ref for a in affected),
    )
