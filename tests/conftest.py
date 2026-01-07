"""
Test configuration and fixtures.
"""

import asyncio
from typing import AsyncGenerator

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from src.api.app import app
from src.core.database import Base

# Test database URL (SQLite in memory)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="function")
async def db_engine():
    """Create a test database engine."""
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture(scope="function")
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    session_factory = async_sessionmaker(
        db_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with session_factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
async def client():
    """Create a test HTTP client."""
    async with AsyncClient(app=app, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def sample_user_data():
    """Sample user data for testing."""
    return {
        "username": "testuser",
        "email": "test@example.com",
        "password": "testpassword123",
        "role": "analyst",
    }


@pytest.fixture
def sample_scan_data():
    """Sample scan data for testing."""
    return {
        "target_url": "https://example.com",
        "modules": ["xss", "sqli", "directory"],
    }


@pytest.fixture
def sample_vulnerability_data():
    """Sample vulnerability data for testing."""
    return {
        "title": "SQL Injection",
        "description": "SQL injection vulnerability found",
        "type": "sqli",
        "severity": "high",
        "cvss_score": 8.5,
        "cwe_id": "CWE-89",
        "evidence": {
            "url": "https://example.com/api/users?id=1",
            "payload": "' OR '1'='1",
            "response": "Database error...",
        },
        "remediation": "Use prepared statements",
        "module_name": "SQLIScanner",
    }
