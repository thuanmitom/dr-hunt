from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from functools import lru_cache

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

from app.core.config import get_settings


def build_engine(*, pooled: bool = True) -> AsyncEngine:
    """``pooled=False`` (NullPool) is required for Celery workers, which run each task in a
    fresh event loop via ``asyncio.run`` — pooled asyncpg connections are loop-bound."""
    settings = get_settings()
    url = settings.database_url.get_secret_value()
    if pooled:
        return create_async_engine(
            url,
            pool_pre_ping=True,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
        )
    return create_async_engine(url, poolclass=NullPool)


@lru_cache(maxsize=1)
def get_engine() -> AsyncEngine:
    return build_engine(pooled=True)


@lru_cache(maxsize=1)
def get_sessionmaker() -> async_sessionmaker[AsyncSession]:
    return async_sessionmaker(get_engine(), expire_on_commit=False)


async def get_session() -> AsyncIterator[AsyncSession]:
    """FastAPI dependency."""
    async with get_sessionmaker()() as session:
        yield session


@asynccontextmanager
async def session_scope(engine: AsyncEngine | None = None) -> AsyncIterator[AsyncSession]:
    """Unit of work: commit on success, rollback on error."""
    maker = async_sessionmaker(engine, expire_on_commit=False) if engine else get_sessionmaker()
    async with maker() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def dispose_engine() -> None:
    if get_engine.cache_info().currsize:
        await get_engine().dispose()
