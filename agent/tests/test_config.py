"""Tests for agent configuration parsing and validation."""

import os
from pathlib import Path
from uuid import UUID

import pytest
import yaml
from pydantic import ValidationError

from waliya_agent.config import (
    AgentConfig,
    AgentIdentityConfig,
    ServerConfig,
    load_config_from_file_or_env,
)


def test_valid_config_instantiation(sample_config: AgentConfig):
    """Verify that a valid configuration model loads successfully."""
    assert sample_config.server.url == "http://127.0.0.1:8000"
    assert sample_config.server.tls_verify is True
    assert sample_config.agent.id == UUID("3c1bdddb-c4b6-4eea-98d2-e24a56f3b8f7")
    assert sample_config.telemetry.buffer_capacity == 1000


def test_invalid_server_url_rejected():
    """Verify that malformed or non-http URLs are rejected."""
    with pytest.raises(ValidationError) as exc:
        ServerConfig(url="ftp://malicious.com")
    assert "Server URL must begin with" in str(exc.value)


def test_short_api_token_or_secret_rejected(temp_dir: Path):
    """Verify that weak or short credentials fail validation."""
    with pytest.raises(ValidationError):
        AgentIdentityConfig(
            id=UUID("3c1bdddb-c4b6-4eea-98d2-e24a56f3b8f7"),
            api_token="short",  # < 8 chars
            signing_secret="secret1234567890",
            state_dir=temp_dir,
        )

    with pytest.raises(ValidationError):
        AgentIdentityConfig(
            id=UUID("3c1bdddb-c4b6-4eea-98d2-e24a56f3b8f7"),
            api_token="valid_token_123",
            signing_secret="short",  # < 16 chars
            state_dir=temp_dir,
        )


def test_sanitized_dict_masks_secrets(sample_config: AgentConfig):
    """Verify that sensitive tokens are never outputted in sanitized configuration dicts."""
    sanitized = sample_config.sanitized_dict()
    assert sanitized["agent"]["api_token"] == "***MASKED***"
    assert sanitized["agent"]["signing_secret"] == "***MASKED***"


def test_load_from_yaml_file(temp_dir: Path):
    """Test loading configuration from a YAML file."""
    yaml_file = temp_dir / "agent.yaml"
    data = {
        "server": {"url": "https://secops.waliya.org:8443", "tls_verify": False},
        "agent": {
            "id": "11111111-2222-3333-4444-555555555555",
            "api_token": "token-from-file-123456",
            "signing_secret": "signing-secret-file-123456789",
            "state_dir": str(temp_dir / "custom_state"),
        },
        "telemetry": {"buffer_capacity": 2500},
    }
    with open(yaml_file, "w", encoding="utf-8") as f:
        yaml.dump(data, f)

    loaded = load_config_from_file_or_env(yaml_file)
    assert loaded.server.url == "https://secops.waliya.org:8443"
    assert loaded.server.tls_verify is False
    assert loaded.agent.id == UUID("11111111-2222-3333-4444-555555555555")
    assert loaded.telemetry.buffer_capacity == 2500


def test_env_var_overrides(temp_dir: Path, monkeypatch: pytest.MonkeyPatch):
    """Test that environment variables cleanly override defaults or file values."""
    monkeypatch.setenv("WALIYA_AGENT_SERVER_URL", "https://env.waliya.internal")
    monkeypatch.setenv("WALIYA_AGENT_ID", "22222222-3333-4444-5555-666666666666")
    monkeypatch.setenv("WALIYA_AGENT_API_TOKEN", "token-from-env-override")
    monkeypatch.setenv("WALIYA_AGENT_SIGNING_SECRET", "secret-from-env-override-123456")
    monkeypatch.setenv("WALIYA_AGENT_STATE_DIR", str(temp_dir / "env_state"))

    loaded = load_config_from_file_or_env(None)
    assert loaded.server.url == "https://env.waliya.internal"
    assert loaded.agent.id == UUID("22222222-3333-4444-5555-666666666666")
    assert loaded.agent.api_token == "token-from-env-override"
    assert loaded.agent.signing_secret == "secret-from-env-override-123456"
