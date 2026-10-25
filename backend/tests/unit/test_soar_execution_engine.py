"""Unit tests for ResponseExecutionEngine: adapter resolution, timeouts, safe retries, and modes."""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest

from waliya.contracts import (
    ActionRiskClassificationEnum,
    ExecutionModeEnum,
    ResponseActionEnum,
    ResponseStateEnum,
)
from waliya.soar.action_registry import ACTION_REGISTRY, ActionMetadata
from waliya.soar.adapters import DryRunResponseAdapter, LinuxHostResponseAdapter
from waliya.soar.execution_engine import AdapterExecutionOutcome, ResponseExecutionEngine


class TestAdapterResolution:
    """Verifies authoritative adapter resolution and strict rejection of unauthorized actions."""

    def test_all_allowlisted_actions_resolve_in_dry_run_mode(self):
        for action_type in ResponseActionEnum:
            adapter = ResponseExecutionEngine.resolve_adapter(action_type, ExecutionModeEnum.DRY_RUN)
            assert isinstance(adapter, DryRunResponseAdapter)

    def test_all_allowlisted_actions_resolve_in_simulation_mode(self):
        for action_type in ResponseActionEnum:
            adapter = ResponseExecutionEngine.resolve_adapter(action_type, ExecutionModeEnum.SIMULATION)
            assert isinstance(adapter, DryRunResponseAdapter)

    def test_all_allowlisted_actions_resolve_in_production_mode(self):
        for action_type in ResponseActionEnum:
            adapter = ResponseExecutionEngine.resolve_adapter(action_type, ExecutionModeEnum.PRODUCTION)
            assert isinstance(adapter, LinuxHostResponseAdapter)

    def test_unregistered_action_rejected(self):
        with pytest.raises(ValueError, match="not registered in allowlisted ACTION_REGISTRY"):
            ResponseExecutionEngine.resolve_adapter("DROP_DATABASE", ExecutionModeEnum.PRODUCTION)


class TestStepExecutionAndSafetyInvariants:
    """Verifies pre-execution validation, timeout handling, and destructive action retry invariants."""

    @pytest.mark.asyncio
    async def test_parameter_validation_failure_before_adapter_invocation(self):
        """Invalid action parameters fail immediately without invoking adapters."""
        # Attempting to block protected loopback IP (127.0.0.1) violates policy
        outcome = await ResponseExecutionEngine.execute_action_step(
            action_type=ResponseActionEnum.BLOCK_IP,
            parameters={"ip_address": "127.0.0.1", "direction": "IN"},
            execution_mode=ExecutionModeEnum.DRY_RUN,
        )
        assert outcome.status == ResponseStateEnum.FAILED
        assert outcome.exit_code == 1
        assert "protected management/infrastructure address" in (outcome.error_message or "")
        assert outcome.is_uncertain is False

    @pytest.mark.asyncio
    async def test_timeout_classified_as_timed_out_and_uncertain(self):
        """Action execution timeout produces TIMED_OUT status and flags is_uncertain=True."""
        # Mock slow adapter exceeding bounded timeout
        with patch.object(DryRunResponseAdapter, "execute", new_callable=AsyncMock) as mock_exec:
            async def slow_execution(*args, **kwargs):
                await asyncio.sleep(0.5)
                return {"status": "EXECUTED", "exit_code": 0}

            mock_exec.side_effect = slow_execution

            outcome = await ResponseExecutionEngine.execute_action_step(
                action_type=ResponseActionEnum.BLOCK_IP,
                parameters={"ip_address": "203.0.113.10", "direction": "IN"},
                execution_mode=ExecutionModeEnum.DRY_RUN,
                timeout_seconds=0.05,  # Very short timeout
            )

            assert outcome.status == ResponseStateEnum.TIMED_OUT
            assert outcome.is_uncertain is True
            assert "timed out after" in (outcome.error_message or "")

    @pytest.mark.asyncio
    async def test_destructive_action_never_retried_on_timeout(self):
        """Destructive action (e.g. TERMINATE_PROCESS) must never be retried upon timeout."""
        call_count = 0

        with patch.object(LinuxHostResponseAdapter, "execute", new_callable=AsyncMock) as mock_exec:
            async def slow_exec(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                await asyncio.sleep(0.5)
                return {"status": "EXECUTED", "exit_code": 0}

            mock_exec.side_effect = slow_exec

            outcome = await ResponseExecutionEngine.execute_action_step(
                action_type=ResponseActionEnum.TERMINATE_PROCESS,
                parameters={"pid": 1234, "process_name": "malware.elf"},
                execution_mode=ExecutionModeEnum.PRODUCTION,
                timeout_seconds=0.05,
            )

            assert outcome.status == ResponseStateEnum.TIMED_OUT
            assert outcome.is_uncertain is True
            assert outcome.attempt_count == 1
            assert call_count == 1  # Strictly 1 attempt, zero retries

    @pytest.mark.asyncio
    async def test_destructive_action_never_retried_on_failure(self):
        """Destructive actions must never be retried on failure to avoid compounding damage."""
        call_count = 0

        with patch.object(LinuxHostResponseAdapter, "execute", new_callable=AsyncMock) as mock_exec:
            async def failing_exec(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                raise RuntimeError("OS kernel error killing PID")

            mock_exec.side_effect = failing_exec

            outcome = await ResponseExecutionEngine.execute_action_step(
                action_type=ResponseActionEnum.TERMINATE_PROCESS,
                parameters={"pid": 5678, "process_name": "beacon.bin"},
                execution_mode=ExecutionModeEnum.PRODUCTION,
            )

            assert outcome.status == ResponseStateEnum.FAILED
            assert outcome.is_uncertain is False
            assert outcome.attempt_count == 1
            assert call_count == 1

    @pytest.mark.asyncio
    async def test_non_destructive_action_retries_up_to_max(self):
        """Non-destructive action (COLLECT_FORENSIC_ARTIFACT) retries up to max_retries on transient failure."""
        call_count = 0

        with patch.object(LinuxHostResponseAdapter, "execute", new_callable=AsyncMock) as mock_exec:
            async def flaking_exec(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count < 3:
                    raise IOError("Disk temporarily busy")
                return {"status": "EXECUTED", "exit_code": 0, "output": "Artifacts collected"}

            mock_exec.side_effect = flaking_exec

            outcome = await ResponseExecutionEngine.execute_action_step(
                action_type=ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT,
                parameters={"artifact_type": "LOGS"},
                execution_mode=ExecutionModeEnum.PRODUCTION,
            )

            assert outcome.status == ResponseStateEnum.EXECUTED
            assert outcome.exit_code == 0
            assert outcome.attempt_count == 3
            assert call_count == 3
