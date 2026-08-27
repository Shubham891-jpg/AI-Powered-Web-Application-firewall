"""
Database connection, session management, and health verification.
Uses SQLAlchemy 2.0 async engine.
"""

import time
from typing import AsyncGenerator
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base

from app.config import settings

Base = declarative_base()

# Async database engine
try:
    engine = create_async_engine(
        settings.DATABASE_URL,
        echo=settings.DEBUG,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20,
    )
    async_session_factory = async_sessionmaker(
        bind=engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
except Exception:
    engine = None
    async_session_factory = None


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for obtaining an async database session."""
    if async_session_factory is None:
        raise RuntimeError("Database engine is not initialized.")
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def check_database_health() -> tuple[bool, float, str]:
    """
    Pings the PostgreSQL database and returns (is_healthy, latency_ms, detail).
    Non-blocking and safe if database is down or unreachable.
    """
    if engine is None:
        return False, 0.0, "Database engine not initialized"
    start_time = time.perf_counter()
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        latency = (time.perf_counter() - start_time) * 1000.0
        return True, round(latency, 2), "Connected to PostgreSQL"
    except Exception as e:
        latency = (time.perf_counter() - start_time) * 1000.0
        return False, round(latency, 2), str(e)
