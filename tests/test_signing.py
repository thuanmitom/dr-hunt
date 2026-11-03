from __future__ import annotations

import pytest

from app.core.signing import (
    SIGNATURE_HEADER,
    TIMESTAMP_HEADER,
    SignatureError,
    build_signed_headers,
    canonical_json,
    compute_signature,
    verify_signature,
)

SECRET = "k" * 48
BODY = canonical_json({"b": 1, "a": "Tên Công Ty"})
NOW = 1_793_000_000


def test_round_trip():
    h = build_signed_headers(SECRET, BODY, pack_id="p1", tenant_slug="t1", now=NOW)
    assert h[SIGNATURE_HEADER].startswith("sha256=")
    assert verify_signature(SECRET, BODY, h[SIGNATURE_HEADER], h[TIMESTAMP_HEADER], now=NOW + 10) == NOW


def test_canonical_json_is_stable():
    assert canonical_json({"b": 1, "a": 2}) == b'{"a":2,"b":1}'


@pytest.mark.parametrize(
    "body,secret,now,msg",
    [
        (BODY + b" ", SECRET, NOW, "mismatch"),
        (BODY, "x" * 48, NOW, "mismatch"),
        (BODY, SECRET, NOW + 301, "tolerance"),
        (BODY, SECRET, NOW - 301, "tolerance"),
    ],
)
def test_rejections(body, secret, now, msg):
    sig = compute_signature(SECRET, NOW, BODY)
    with pytest.raises(SignatureError, match=msg):
        verify_signature(secret, body, sig, str(NOW), now=now)


def test_missing_or_malformed_headers():
    with pytest.raises(SignatureError):
        verify_signature(SECRET, BODY, None, str(NOW), now=NOW)
    with pytest.raises(SignatureError, match="scheme"):
        verify_signature(SECRET, BODY, "md5=abc", str(NOW), now=NOW)
    with pytest.raises(SignatureError, match="malformed"):
        verify_signature(SECRET, BODY, compute_signature(SECRET, NOW, BODY), "yesterday", now=NOW)
