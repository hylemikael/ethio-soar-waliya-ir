"""Unit tests for the SOAR closed-loop verification engine and state machine."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4
import pytest

from waliya.audit.ledger_service import AuditLedgerService
from waliya.contracts import IncidentStatusEnum, ResponseActionEnum, ResponseStateEnum
from waliya.db.models import IncidentModel, ResponseActionModel
from waliya.soar.adapters import LinuxHostResponseAdapter
from waliya.soar.verification import ClosedLoopVerificationEngine


def create_mock_action(status: ResponseStateEnum = ResponseStateEnum.REQUESTED):
    return ResponseActionModel(
        id=uuid4(),
        command_id=uuid4(),
        incident_id=uuid4(),
        agent_id=uuid4(),
        action=ResponseActionEnum.BLOCK_IP.value,
        parameters={"ip_address": "198.51.100.77"},
        status=status.value,
        sequence=1,
        nonce=uuid4(),
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc),
        signature="a" * 64,
    )


def test_state_machine_transition_invariants():
    """Verify strictly allowed and forbidden response state transitions."""
    engine = ClosedLoopVerificationEngine()

    # Valid progression
    assert engine.validate_transition(ResponseStateEnum.REQUESTED.value, ResponseStateEnum.PENDING_APPROVAL)
    assert engine.validate_transition(ResponseStateEnum.PENDING_APPROVAL.value, ResponseStateEnum.QUEUED)
    assert engine.validate_transition(ResponseStateEnum.QUEUED.value, ResponseStateEnum.RECEIVED)
    assert engine.validate_transition(ResponseStateEnum.RECEIVED.value, ResponseStateEnum.VERIFYING)
    assert engine.validate_transition(ResponseStateEnum.VERIFYING.value, ResponseStateEnum.VERIFIED_CONTAINED)
    assert engine.validate_transition(ResponseStateEnum.VERIFYING.value, ResponseStateEnum.VERIFICATION_INCONCLUSIVE)

    # Idempotent re-transitions
    assert engine.validate_transition(ResponseStateEnum.QUEUED.value, ResponseStateEnum.QUEUED)
    assert engine.validate_transition(ResponseStateEnum.VERIFYING.value, ResponseStateEnum.VERIFYING)

    # Strictly forbidden transitions
    assert not engine.validate_transition(ResponseStateEnum.REQUESTED.value, ResponseStateEnum.VERIFIED_CONTAINED)
    assert not engine.validate_transition(ResponseStateEnum.PENDING_APPROVAL.value, ResponseStateEnum.VERIFIED_CONTAINED)
    assert not engine.validate_transition(ResponseStateEnum.VERIFIED_CONTAINED.value, ResponseStateEnum.QUEUED)
    assert not engine.validate_transition(ResponseStateEnum.FAILED.value, ResponseStateEnum.QUEUED)


@pytest.mark.asyncio
@patch.object(AuditLedgerService, "record_action", new_callable=AsyncMock)
async def test_execution_receipt_transitions_to_verifying(mock_audit):
    """Verify execution receipt transitions to VERIFYING (receipt != containment)."""
    engine = ClosedLoopVerificationEngine()
    action = create_mock_action(ResponseStateEnum.RECEIVED)
    session = AsyncMock()

    receipt = {
        "command_id": str(action.command_id),
        "status": "EXECUTED",
        "exit_code": 0,
        "output": "Rule installed successfully",
        "executed_at": datetime.now(timezone.utc).isoformat(),
    }

    new_state = await engine.record_execution_receipt(session, action, receipt)
    assert new_state == ResponseStateEnum.VERIFYING
    assert action.status == ResponseStateEnum.VERIFYING.value
    assert action.execution_receipt == receipt
    assert mock_audit.called


@pytest.mark.asyncio
@patch.object(AuditLedgerService, "record_action", new_callable=AsyncMock)
async def test_execution_receipt_failure(mock_audit):
    """Verify execution receipt with non-zero exit code transitions to FAILED."""
    engine = ClosedLoopVerificationEngine()
    action = create_mock_action(ResponseStateEnum.RECEIVED)
    session = AsyncMock()

    receipt = {
        "command_id": str(action.command_id),
        "status": "FAILED",
        "exit_code": 1,
        "output": "iptables: Permission denied",
    }

    new_state = await engine.record_execution_receipt(session, action, receipt)
    assert new_state == ResponseStateEnum.FAILED
    assert action.status == ResponseStateEnum.FAILED.value
    assert mock_audit.called


@pytest.mark.asyncio
@patch.object(AuditLedgerService, "record_action", new_callable=AsyncMock)
async def test_containment_verification_updates_incident(mock_audit):
    """Verify positive containment evidence transitions incident to CONTAINED."""
    engine = ClosedLoopVerificationEngine()
    action = create_mock_action(ResponseStateEnum.VERIFYING)

    # Mock incident
    incident = IncidentModel(
        id=action.incident_id,
        title="Active Incident",
        description="Testing containment",
        severity="HIGH",
        status="OPEN",
        composite_risk_score=80.0,
        update_history=[],
    )

    session = AsyncMock()
    mock_res = MagicMock()
    mock_res.scalars.return_value.first.return_value = incident
    session.execute.return_value = mock_res

    # Positive telemetry containing active firewall rule
    observed_state = {
        "firewall_rules": [
            "-A WALIYA_BLOCK -s 198.51.100.77/32 -j DROP",
        ]
    }

    state, explanation = await engine.verify_containment(session, action, observed_state)
    assert state == ResponseStateEnum.VERIFIED_CONTAINED
    assert action.status == ResponseStateEnum.VERIFIED_CONTAINED.value

    # Incident status transitioned to CONTAINED
    assert incident.status == IncidentStatusEnum.CONTAINED.value
    assert len(incident.update_history) >= 1
    assert incident.update_history[-1]["action"] == "INCIDENT_CONTAINED"
    assert mock_audit.called
