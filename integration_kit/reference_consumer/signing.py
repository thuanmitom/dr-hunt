"""HuntCompiler wire signature (DECISIONS.md D-02), re-implemented so the kit does not depend on HuntCompiler code.

    X-HuntCompiler-Timestamp: <unix seconds>
    X-HuntCompiler-Signature: sha256=<hex(HMAC_SHA256(secret, f"{timestamp}." + raw_body))>

Push: verify the raw request body exactly as received. Pull: each item is signed over the canonical JSON of its
``pack`` (keys sorted, no whitespace, UTF-8, non-ASCII kept), which ``canonical_json`` reproduces.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

TOLERANCE_SECONDS = 300
SIGNATURE_HEADER = "X-HuntCompiler-Signature"
TIMESTAMP_HEADER = "X-HuntCompiler-Timestamp"
TENANT_HEADER = "X-HuntCompiler-Tenant"
PACK_ID_HEADER = "X-HuntCompiler-Pack-Id"


class SignatureError(ValueError):
    """Missing, malformed, stale or wrong signature."""


def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sign(secret: str, timestamp: int, body: bytes) -> str:
    mac = hmac.new(secret.encode("utf-8"), f"{timestamp}.".encode("ascii") + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def verify(secret: str, body: bytes, signature: str | None, timestamp: str | int | None, *,
           tolerance: int = TOLERANCE_SECONDS, now: int | None = None) -> int:  # fmt: skip
    """Returns the verified timestamp or raises ``SignatureError``."""
    if not signature or timestamp is None or timestamp == "":
        raise SignatureError("missing signature or timestamp")
    if not str(signature).startswith("sha256="):
        raise SignatureError("unsupported signature scheme")
    try:
        ts = int(timestamp)
    except (TypeError, ValueError) as exc:
        raise SignatureError("malformed timestamp") from exc
    if abs((int(time.time()) if now is None else now) - ts) > tolerance:
        raise SignatureError("timestamp outside the tolerance window (replayed or clock skew)")
    if not hmac.compare_digest(sign(secret, ts, body), str(signature).strip()):
        raise SignatureError("signature mismatch")
    return ts


def signed_headers(secret: str, body: bytes, *, tenant: str, now: int | None = None) -> dict[str, str]:
    ts = int(time.time()) if now is None else now
    return {
        "Content-Type": "application/json; charset=utf-8",
        TIMESTAMP_HEADER: str(ts),
        SIGNATURE_HEADER: sign(secret, ts, body),
        TENANT_HEADER: tenant,
    }
