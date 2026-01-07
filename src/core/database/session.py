"""
Database session management and connection pooling.
"""

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool, QueuePool

from .models import Base

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and sessions."""

    def __init__(self, database_url: str, echo: bool = False):
        """
        Initialize database manager.

        Args:
            database_url: SQLAlchemy database URL (async format)
            echo: Whether to log SQL statements
        """
        # Choose appropriate pool based on database type
        if "sqlite" in database_url:
            # SQLite doesn't support connection pooling well
            poolclass = NullPool
        else:
            # PostgreSQL, MySQL, etc.
            poolclass = QueuePool

        self.engine = create_async_engine(
            database_url,
            echo=echo,
            poolclass=poolclass,
            pool_size=20,
            max_overflow=10,
            pool_pre_ping=True,  # Verify connections before checkout
        )

        self.session_factory = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

    async def create_tables(self) -> None:
        """Create all tables in the database."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info("Database tables created successfully")

    async def drop_tables(self) -> None:
        """Drop all tables (use with caution!)."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        logger.warning("All database tables dropped")

    @asynccontextmanager
    async def session(self) -> AsyncGenerator[AsyncSession, None]:
        """
        Context manager for database sessions.

        Usage:
            async with db_manager.session() as session:
                result = await session.execute(query)
        """
        async with self.session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()

    async def get_session(self) -> AsyncSession:
        """Get a new database session (for dependency injection)."""
        return self.session_factory()

    async def close(self) -> None:
        """Close all database connections."""
        await self.engine.dispose()
        logger.info("Database connections closed")


# Singleton instance
_db_manager: DatabaseManager | None = None


async def init_database(database_url: str, echo: bool = False) -> DatabaseManager:
    """Initialize the global database manager."""
    global _db_manager
    _db_manager = DatabaseManager(database_url, echo=echo)
    await _db_manager.create_tables()
    return _db_manager


def get_db_manager() -> DatabaseManager:
    """Get the global database manager instance."""
    if _db_manager is None:
        raise RuntimeError("Database not initialized. Call init_database() first.")
    return _db_manager


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI route handlers.

    Usage:
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            ...
    """
    db_manager = get_db_manager()
    async with db_manager.session() as session:
        yield session
