"""Fixed-window rate limits for the tenant API, kept in the Redis the stack already runs (D-56).

* Per tenant: ``api_rate_limit_per_minute`` authenticated calls (pull + feedback together).
* Per client IP: after ``api_auth_failures_per_ip`` failed authentications within ``api_auth_failure_window_seconds``,
  every call from that IP gets 429 until the window ends, including calls with a valid credential, so a token or an
  HMAC secret cannot be brute-forced and tenant slugs cannot be probed.

If Redis is unreachable the API stays available (fail open) and the outage is logged; ``/readyz`` already reports it.
After an error Redis is not retried for ``COOLDOWN_SECONDS``, so one outage does not slow every request.
"""

from __future__ import annotations

import logging
import time
from collections.abc import Callable
from typing import Any

from fastapi import HTTPException, Request, status

log = logging.getLogger(__name__)
COOLDOWN_SECONDS = 30.0


class RateLimiter:
    def __init__(self, redis: Any, *, per_minute: int, auth_failures: int, auth_window: int,
                 clock: Callable[[], float] = time.time) -> None:  # fmt: skip
        self._redis, self._clock = redis, clock
        self.per_minute, self.auth_failures, self.auth_window = per_minute, auth_failures, auth_window
        self._down_until = 0.0

    def _window(self, scope: str, ident: str, seconds: int) -> tuple[str, int]:
        now = self._clock()
        return f"hc:rl:{scope}:{ident}:{int(now // seconds)}", max(1, int(seconds - now % seconds))

    async def _call(self, fn: Callable[[], Any]) -> Any:
        if self._clock() < self._down_until:
            return None
        try:
            return await fn()
        except Exception as exc:  # noqa: BLE001 — any Redis/connection error: fail open, never fail the request
            self._down_until = self._clock() + COOLDOWN_SECONDS
            log.warning("rate limiter disabled for %.0fs: Redis error %s", COOLDOWN_SECONDS, type(exc).__name__)
            return None

    async def _incr(self, key: str, ttl: int) -> int | None:
        async def go() -> int:
            n = int(await self._redis.incr(key))
            if n == 1:
                await self._redis.expire(key, ttl)
            return n

        return await self._call(go)

    async def ip_blocked(self, ip: str) -> int | None:
        """Seconds to wait if this IP has used up its failed authentications, else None."""
        key, retry = self._window("authfail", ip, self.auth_window)
        count = await self._call(lambda: self._redis.get(key))
        return retry if count is not None and int(count) >= self.auth_failures else None

    async def auth_failed(self, ip: str) -> None:
        key, _ = self._window("authfail", ip, self.auth_window)
        await self._incr(key, self.auth_window)

    async def tenant_over_limit(self, tenant_slug: str) -> int | None:
        """Counts one call; seconds to wait if the tenant is over its per-minute budget, else None."""
        key, retry = self._window("tenant", tenant_slug, 60)
        n = await self._incr(key, 60)
        return retry if n is not None and n > self.per_minute else None


class DisabledLimiter(RateLimiter):
    """Used only when the app runs without its lifespan (embedded in tests)."""

    def __init__(self) -> None:
        super().__init__(None, per_minute=1, auth_failures=1, auth_window=1)

    async def _call(self, fn: Callable[[], Any]) -> Any:
        return None


def get_limiter(request: Request) -> RateLimiter:
    return getattr(request.app.state, "limiter", None) or DisabledLimiter()


def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def too_many(retry_after: int, detail: str = "rate limit exceeded") -> HTTPException:
    return HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, detail, headers={"Retry-After": str(retry_after)})
