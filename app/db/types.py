from __future__ import annotations

from typing import Any

from sqlalchemy import Dialect, Text
from sqlalchemy.types import TypeDecorator

from app.core.crypto import decrypt_str, encrypt_str


class EncryptedString(TypeDecorator[str]):
    """Transparently Fernet-encrypts a string column at rest."""

    impl = Text
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        return None if value is None else encrypt_str(value)

    def process_result_value(self, value: Any, dialect: Dialect) -> str | None:
        return None if value is None else decrypt_str(value)
