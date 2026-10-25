"""Pytest fixtures and configuration."""

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from waliya.db.session import async_session_factory, engine
from waliya.main import create_app


@pytest_asyncio.fixture(scope="session", autouse=True)
async def dispose_engine_on_teardown():
    """Ensure all pooled DB connections are gracefully closed at session end."""
    yield
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session():
    """Yield an asynchronous SQLAlchemy database session."""
    async with async_session_factory() as session:
        yield session


@pytest_asyncio.fixture
async def async_client():
    """Yield an asynchronous HTTP test client bound to the FastAPI application."""
    app = create_app()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client
