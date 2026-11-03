"""Wire-level signing contract shared by the dispatcher, the feedback API and the SOAR side.

Signature scheme (Stripe-style, replay-resistant):

    X-HuntCompiler-Timestamp: <unix seconds>
    X-HuntCompiler-Signature: sha256=<hex(HMAC_SHA256(secret, f"{timestamp}." + raw_body))>

The MAC covers the *exact raw bytes* sent on the wire. Receivers must verify against the
raw request body (in n8n: enable "Raw Body" on the Webhook node), never against a
re-serialised JSON object, and must reject timestamps outside the tolerance window.
Receivers should additionally de-duplicate on ``X-HuntCompiler-Pack-Id``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import time
from typing import Any

SIGNATURE_HEADER = "X-HuntCompiler-Signature"
TIMESTAMP_HEADER = "X-HuntCompiler-Timestamp"
PACK_ID_HEADER = "X-HuntCompiler-Pack-Id"
TENANT_HEADER = "X-HuntCompiler-Tenant"
SIGNATURE_PREFIX = "sha256="


class SignatureError(ValueError):
    """Signature missing, malformed, stale or not matching."""


def canonical_json(obj: Any) -> bytes:
    """Deterministic JSON encoding used for request bodies and content hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def compute_signature(secret: str | bytes, timestamp: int, body: bytes) -> str:
    key = secret.encode("utf-8") if isinstance(secret, str) else secret
    mac = hmac.new(key, f"{timestamp}.".encode("ascii") + body, hashlib.sha256)
    return SIGNATURE_PREFIX + mac.hexdigest()


def build_signed_headers(
    secret: str | bytes,
    body: bytes,
    *,
    pack_id: str | None = None,
    tenant_slug: str | None = None,
    now: int | None = None,
) -> dict[str, str]:
    ts = int(time.time()) if now is None else now
    headers = {
        "Content-Type": "application/json; charset=utf-8",
        TIMESTAMP_HEADER: str(ts),
        SIGNATURE_HEADER: compute_signature(secret, ts, body),
    }
    if pack_id:
        headers[PACK_ID_HEADER] = pack_id
    if tenant_slug:
        headers[TENANT_HEADER] = tenant_slug
    return headers


def verify_signature(
    secret: str | bytes,
    body: bytes,
    signature_header: str | None,
    timestamp_header: str | None,
    *,
    tolerance_seconds: int = 300,
    now: int | None = None,
) -> int:
    """Validate a signed request. Returns the verified timestamp or raises SignatureError."""
    if not signature_header or not timestamp_header:
        raise SignatureError("missing signature or timestamp header")
    if not signature_header.startswith(SIGNATURE_PREFIX):
        raise SignatureError("unsupported signature scheme")
    try:
        ts = int(timestamp_header)
    except ValueError as exc:
        raise SignatureError("malformed timestamp") from exc
    current = int(time.time()) if now is None else now
    if abs(current - ts) > tolerance_seconds:
        raise SignatureError("timestamp outside tolerance window")
    expected = compute_signature(secret, ts, body)
    if not hmac.compare_digest(expected, signature_header.strip()):
        raise SignatureError("signature mismatch")
    return ts
