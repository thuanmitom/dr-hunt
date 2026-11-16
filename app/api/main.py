"""FastAPI application. Phase 1 exposes health probes only; pack pull and feedback
endpoints are added in Phase 3 on top of the same contracts."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, Response, status
from sqlalchemy import text

from app import __version__
from app.api.ratelimit import RateLimiter
from app.api.routes import router
from app.core.config import get_settings
from app.core.logging import configure_logging, quiet_noisy_loggers
from app.db.session import dispose_engine, get_engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    if settings.log_format == "json":  # again, in case the app was imported before uvicorn set up its handlers
        configure_logging(settings.log_level, settings.log_format)
    app.state.redis = aioredis.from_url(settings.redis_url, socket_timeout=3)
    app.state.limiter = RateLimiter(app.state.redis, per_minute=settings.api_rate_limit_per_minute,
                                    auth_failures=settings.api_auth_failures_per_ip,
                                    auth_window=settings.api_auth_failure_window_seconds)  # fmt: skip
    try:
        yield
    finally:
        await app.state.redis.aclose()
        await dispose_engine()


def create_app() -> FastAPI:
    settings = get_settings()
    # uvicorn installs its handlers before it imports this module, so its own startup lines are JSON too
    if settings.log_format == "json":
        configure_logging(settings.log_level, settings.log_format)
    quiet_noisy_loggers(settings.log_level)
    app = FastAPI(
        title="OutSight HuntCompiler",
        version=__version__,
        lifespan=lifespan,
        docs_url=None if settings.is_prod else "/docs",
        redoc_url=None,
        openapi_url=None if settings.is_prod else "/openapi.json",
    )

    app.include_router(router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    @app.get("/readyz", include_in_schema=False)
    async def readyz(response: Response) -> dict[str, str]:
        checks: dict[str, str] = {}
        try:
            async with get_engine().connect() as conn:
                await conn.execute(text("SELECT 1"))
            checks["postgres"] = "ok"
        except Exception as exc:  # noqa: BLE001 — report, never raise from a probe
            checks["postgres"] = f"error: {type(exc).__name__}"
        try:
            await app.state.redis.ping()
            checks["redis"] = "ok"
        except Exception as exc:  # noqa: BLE001
            checks["redis"] = f"error: {type(exc).__name__}"
        if any(v != "ok" for v in checks.values()):
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return checks

    return app


app = create_app()
