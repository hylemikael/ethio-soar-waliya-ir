"""Pytest fixtures for Waliya-IR Agent test suite."""

import os
import tempfile
from pathlib import Path
from typing import Generator
from uuid import UUID, uuid4

import pytest

from waliya_agent.config import (
    AgentConfig,
    AgentIdentityConfig,
    C2Config,
    LoggingConfig,
    ServerConfig,
    TelemetryConfig,
)


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Provide isolated temporary directory for test artifacts."""
    with tempfile.TemporaryDirectory() as td:
        yield Path(td)


@pytest.fixture
def mock_agent_id() -> UUID:
    """Stable mock agent UUID."""
    return UUID("3c1bdddb-c4b6-4eea-98d2-e24a56f3b8f7")


@pytest.fixture
def mock_signing_secret() -> str:
    """Sample agent signing secret."""
    return "test-agent-hmac-secret-abcdef123456"


@pytest.fixture
def sample_config(temp_dir: Path, mock_agent_id: UUID, mock_signing_secret: str) -> AgentConfig:
    """Valid AgentConfig instance for testing."""
    return AgentConfig(
        server=ServerConfig(
            url="http://127.0.0.1:8000",
            tls_verify=True,
            request_timeout_seconds=5.0,
            max_retries=2,
            retry_backoff_factor=1.2,
        ),
        agent=AgentIdentityConfig(
            id=mock_agent_id,
            api_token="test-agent-token-12345678",
            signing_secret=mock_signing_secret,
            state_dir=temp_dir / "state",
        ),
        telemetry=TelemetryConfig(
            upload_interval_seconds=1.0,
            upload_batch_size=50,
            buffer_capacity=1000,
            fim_enabled=True,
            fim_paths=[str(temp_dir / "monitored")],
            fim_poll_interval_seconds=1.0,
            fim_debounce_seconds=0.2,
            process_enabled=True,
            process_poll_interval_seconds=1.0,
            auth_enabled=True,
            auth_log_path=str(temp_dir / "auth.log"),
            network_enabled=True,
        ),
        c2=C2Config(
            heartbeat_interval_seconds=2.0,
            task_poll_interval_seconds=1.0,
        ),
        logging=LoggingConfig(level="DEBUG", format="json"),
    )
