"""Unit tests for response action registry and dispatch gating."""

from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from waliya_agent.config import ResponseConfig
from waliya_agent.response.handlers.base import ExecutionResult
from waliya_agent.response.registry import ResponseActionRegistry


@pytest.mark.asyncio
async def test_registry_dry_run_default_enforcement(tmp_path: Path):
    """Verify that when enable_response_actions is False (default), execution is forced to dry_run=True."""
    config = ResponseConfig(
        enable_response_actions=False,
        allowed_actions=["BLOCK_IP"],
        forensic_artifact_dir=tmp_path,
    )
    registry = ResponseActionRegistry(config=config, server_url="http://192.168.1.100:8000")

    result = await registry.dispatch("BLOCK_IP", {"ip_address": "198.51.100.42"})
    assert result.status == "EXECUTED"
    assert result.dry_run is True
    assert "[DRY-RUN]" in result.output


@pytest.mark.asyncio
async def test_registry_unallowed_action_rejected():
    """Verify that actions not in the allowed_actions list are rejected."""
    config = ResponseConfig(
        enable_response_actions=False,
        allowed_actions=["TERMINATE_PROCESS"],  # BLOCK_IP not allowed
    )
    registry = ResponseActionRegistry(config=config)

    result = await registry.dispatch("BLOCK_IP", {"ip_address": "198.51.100.42"})
    assert result.status == "FAILED"
    assert result.exit_code == 1
    assert "not in allowed_actions" in result.output


@pytest.mark.asyncio
async def test_registry_parameter_validation_failure():
    """Verify that invalid parameters return FAILED status cleanly."""
    config = ResponseConfig(
        enable_response_actions=False,
        allowed_actions=["TERMINATE_PROCESS"],
    )
    registry = ResponseActionRegistry(config=config)

    # Missing process_name
    result = await registry.dispatch("TERMINATE_PROCESS", {"pid": 555})
    assert result.status == "FAILED"
    assert result.exit_code == 1
    assert "Parameter validation failed" in result.output


@pytest.mark.asyncio
async def test_registry_dispatch_with_actions_enabled(tmp_path: Path):
    """Verify that when enable_response_actions=True, handler is called with dry_run=False."""
    config = ResponseConfig(
        enable_response_actions=True,
        allowed_actions=["COLLECT_FORENSIC_ARTIFACT"],
        forensic_artifact_dir=tmp_path,
    )
    registry = ResponseActionRegistry(config=config)

    result = await registry.dispatch("COLLECT_FORENSIC_ARTIFACT", {"artifact_type": "PROC_MAP"})
    assert result.status == "EXECUTED"
    assert result.dry_run is False
    assert result.observed_state["artifact_size_bytes"] > 0
