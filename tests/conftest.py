from __future__ import annotations

import os

from cryptography.fernet import Fernet

# Settings are read at import time by some modules: configure before anything imports app.*
os.environ.setdefault("HC_ENVIRONMENT", "dev")
os.environ.setdefault(
    "HC_DATABASE_URL",
    os.environ.get("HC_TEST_DATABASE_URL", "postgresql+asyncpg://test:test@127.0.0.1:5432/test"),
)
os.environ.setdefault("HC_MASTER_ENCRYPTION_KEYS", Fernet.generate_key().decode())
