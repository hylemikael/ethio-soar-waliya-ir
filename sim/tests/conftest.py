"""Pytest fixtures for Waliya-Sim testing."""

import pytest
import pytest_asyncio
from uuid import uuid4

from waliya.contracts import EventTypeEnum, SeverityEnum
from waliya.core.crypto import hash_agent_token
from waliya.config import settings
from waliya.db.session import engine


@pytest_asyncio.fixture(scope="session", autouse=True)
async def dispose_engine_on_teardown():
    """Ensure all pooled DB connections are gracefully closed at session end."""
    yield
    await engine.dispose()


@pytest.fixture
def sample_run_ids():
    return {
        "run_id": f"sim-{uuid4().hex[:12]}",
        "trace_id": f"trace-{uuid4().hex[:12]}",
        "agent_id": uuid4(),
    }


@pytest.fixture
def sim_test_agent():
    """Create agent credentials for testing."""
    agent_id = uuid4()
    token = f"sim-test-agent-token-{uuid4().hex}"
    return {
        "id": agent_id,
        "token": token,
        "admin_key": settings.ADMIN_API_KEY,
    }
