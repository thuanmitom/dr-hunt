"""Symmetric encryption for secrets stored in PostgreSQL, plus API-token helpers.

Tenant HMAC secrets must be recoverable (HMAC is symmetric), so they are encrypted with
Fernet (AES-128-CBC + HMAC-SHA256) rather than hashed. ``MultiFernet`` enables key
rotation: prepend a new key to ``HC_MASTER_ENCRYPTION_KEYS`` and re-save rows.
API tokens, in contrast, only need to be compared, so only their SHA-256 is stored.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from functools import lru_cache

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

from app.core.config import get_settings


class SecretDecryptionError(RuntimeError):
    """Raised when a stored secret cannot be decrypted with any configured key."""


@lru_cache(maxsize=1)
def _cipher() -> MultiFernet:
    raw = get_settings().master_encryption_keys.get_secret_value()
    keys = [k.strip() for k in raw.split(",") if k.strip()]
    if not keys:
        raise RuntimeError("HC_MASTER_ENCRYPTION_KEYS is empty")
    return MultiFernet([Fernet(k.encode("ascii")) for k in keys])


def encrypt_str(plaintext: str) -> str:
    return _cipher().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_str(token: str) -> str:
    try:
        return _cipher().decrypt(token.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:  # wrong/rotated-out key or tampered ciphertext
        raise SecretDecryptionError("unable to decrypt stored secret") from exc


def generate_secret(nbytes: int = 32) -> str:
    """URL-safe random secret, suitable for HMAC keys and API tokens."""
    return secrets.token_urlsafe(nbytes)


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def token_matches(presented: str, stored_sha256: str) -> bool:
    return hmac.compare_digest(sha256_hex(presented), stored_sha256)
