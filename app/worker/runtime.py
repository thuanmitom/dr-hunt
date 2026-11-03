"""Bridges sync Celery tasks to the async code base."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager
from typing import Any

import redis

from app.core.config import get_settings
from app.db.session import build_engine


def run_with_engine[T](fn: Callable[..., Awaitable[T]], *args: Any) -> T:
    """Run ``fn(engine, *args)`` in a fresh event loop with a NullPool engine (loop-safe)."""

    async def _main() -> T:
        engine = build_engine(pooled=False)
        try:
            return await fn(engine, *args)
        finally:
            await engine.dispose()

    return asyncio.run(_main())


@contextmanager
def single_flight(name: str, ttl_seconds: int) -> Iterator[bool]:
    """Redis lock so a slow sweep never overlaps the next scheduled run."""
    client = redis.Redis.from_url(get_settings().redis_url)
    key = f"hc:lock:{name}"
    acquired = bool(client.set(key, "1", nx=True, ex=ttl_seconds))
    try:
        yield acquired
    finally:
        if acquired:
            client.delete(key)
        client.close()
