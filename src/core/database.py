"""Database connection and session management."""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from core.config import get_settings
from tenant_guc import register_tenant_guc

logger = logging.getLogger(__name__)

settings = get_settings()

# Create async engine (SSL is configured in database_url query string)
engine = create_async_engine(
    settings.database_url,
    echo=settings.environment == "development",
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# art#49: bind ``app.current_tenant`` transaction-locally on EVERY transaction of
# this engine (inert unless TENANT_RLS_MODE=enforce). See tenant_guc.py. Without
# it, once the RLS policies exist and the mode is enforce, every request reads 0
# rows — silently.
register_tenant_guc(engine)

# Create session factory
async_session_maker = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


# Base class for models
class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncGenerator[AsyncSession]:
    """Dependency for getting async database sessions."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            # rollback-before-reraise must catch all (incl. CancelledError)
            logger.error("Database session error, rolling back", exc_info=True)
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_context() -> AsyncGenerator[AsyncSession]:
    """Context manager for database sessions."""
    async with async_session_maker() as session:
        try:
            yield session
            await session.commit()
        except BaseException:
            # rollback-before-reraise must catch all (incl. CancelledError)
            logger.error("Database session error, rolling back", exc_info=True)
            await session.rollback()
            raise
        finally:
            await session.close()
