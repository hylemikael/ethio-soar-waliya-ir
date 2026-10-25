"""Closed-loop containment verification engine and response state machine."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.contracts import IncidentStatusEnum, ResponseActionEnum, ResponseStateEnum
from waliya.db.models import IncidentModel, ResponseActionModel
from waliya.soar.adapters import BaseResponseAdapter, LinuxHostResponseAdapter

logger = logging.getLogger("waliya.soar.verification")

# Valid state machine transitions
VALID_TRANSITIONS: Dict[ResponseStateEnum, Set[ResponseStateEnum]] = {
    ResponseStateEnum.REQUESTED: {
        ResponseStateEnum.PENDING_APPROVAL,
        ResponseStateEnum.QUEUED,
        ResponseStateEnum.REJECTED,
        ResponseStateEnum.EXPIRED,
    },
    ResponseStateEnum.PENDING_APPROVAL: {
        ResponseStateEnum.QUEUED,
        ResponseStateEnum.REJECTED,
        ResponseStateEnum.EXPIRED,
    },
    ResponseStateEnum.QUEUED: {
        ResponseStateEnum.RECEIVED,
        ResponseStateEnum.EXECUTED,
        ResponseStateEnum.EXPIRED,
        ResponseStateEnum.FAILED,
        ResponseStateEnum.TIMED_OUT,
        ResponseStateEnum.OUTCOME_UNCERTAIN,
    },
    ResponseStateEnum.RECEIVED: {
        ResponseStateEnum.EXECUTED,
        ResponseStateEnum.VERIFYING,
        ResponseStateEnum.FAILED,
        ResponseStateEnum.EXPIRED,
        ResponseStateEnum.TIMED_OUT,
        ResponseStateEnum.OUTCOME_UNCERTAIN,
    },
    ResponseStateEnum.EXECUTED: {
        ResponseStateEnum.VERIFYING,
        ResponseStateEnum.FAILED,
        ResponseStateEnum.TIMED_OUT,
        ResponseStateEnum.OUTCOME_UNCERTAIN,
    },
    ResponseStateEnum.VERIFYING: {
        ResponseStateEnum.VERIFIED_CONTAINED,
        ResponseStateEnum.VERIFICATION_INCONCLUSIVE,
        ResponseStateEnum.FAILED,
        ResponseStateEnum.TIMED_OUT,
        ResponseStateEnum.OUTCOME_UNCERTAIN,
    },
    ResponseStateEnum.VERIFICATION_INCONCLUSIVE: {
        ResponseStateEnum.VERIFIED_CONTAINED,
        ResponseStateEnum.FAILED,
        ResponseStateEnum.EXPIRED,
        ResponseStateEnum.OUTCOME_UNCERTAIN,
    },
    # Terminal states
    ResponseStateEnum.VERIFIED_CONTAINED: set(),
    ResponseStateEnum.FAILED: set(),
    ResponseStateEnum.EXPIRED: set(),
    ResponseStateEnum.REJECTED: set(),
    ResponseStateEnum.TIMED_OUT: set(),
    ResponseStateEnum.OUTCOME_UNCERTAIN: set(),
}


class ClosedLoopVerificationEngine:
    """Enforces state machine invariants and evaluates post-action containment telemetry."""

    def __init__(self, adapter: Optional[BaseResponseAdapter] = None):
        self.adapter = adapter or LinuxHostResponseAdapter()

    @staticmethod
    def validate_transition(current_state: str, new_state: ResponseStateEnum) -> bool:
        """Verify whether a proposed state transition is valid under the state machine."""
        try:
            curr_enum = ResponseStateEnum(current_state)
        except ValueError:
            return False

        # Idempotent state transition (already in requested state)
        if curr_enum == new_state:
            return True

        allowed = VALID_TRANSITIONS.get(curr_enum, set())
        return new_state in allowed

    async def record_execution_receipt(
        self,
        session: AsyncSession,
        action_model: ResponseActionModel,
        receipt: Dict[str, Any],
    ) -> ResponseStateEnum:
        """Process an agent execution receipt.

        Receipt of execution transitions the state to VERIFYING (not directly to contained).
        """
        now_utc = datetime.now(timezone.utc)
        exec_status = receipt.get("status", "EXECUTED").upper()

        if exec_status == "FAILED" or receipt.get("exit_code", 0) != 0:
            target_state = ResponseStateEnum.FAILED
        else:
            # Execution receipt initiates the post-action observation/verifying window
            target_state = ResponseStateEnum.VERIFYING

        if not self.validate_transition(action_model.status, target_state):
            logger.warning(
                "Invalid transition for action %s: %s -> %s",
                action_model.command_id, action_model.status, target_state.value,
            )
            return ResponseStateEnum(action_model.status)

        old_status = action_model.status
        action_model.status = target_state.value
        action_model.execution_receipt = receipt

        # Audit ledger record
        await AuditLedgerService.record_action(
            session=session,
            actor_id=str(action_model.agent_id),
            actor_role="AGENT",
            action="EXECUTION_RECEIPT_PROCESSED",
            target_entity=f"command:{action_model.command_id}",
            payload={
                "command_id": str(action_model.command_id),
                "previous_status": old_status,
                "current_status": target_state.value,
                "exit_code": receipt.get("exit_code"),
                "status": receipt.get("status"),
            },
            timestamp=now_utc,
        )

        logger.info(
            "Action %s transition: %s -> %s (exit_code=%s)",
            action_model.command_id, old_status, target_state.value, receipt.get("exit_code"),
        )
        return target_state

    async def verify_containment(
        self,
        session: AsyncSession,
        action_model: ResponseActionModel,
        observed_state: Dict[str, Any],
        verified_at: Optional[datetime] = None,
    ) -> Tuple[ResponseStateEnum, str]:
        """Perform positive verification of containment against observed telemetry.

        Enforces that containment is NEVER inferred solely from an absence of events.
        """
        now_utc = verified_at or datetime.now(timezone.utc)
        action_enum = ResponseActionEnum(action_model.action)

        # Ensure action is in VERIFYING or VERIFICATION_INCONCLUSIVE state
        if action_model.status not in (ResponseStateEnum.VERIFYING.value, ResponseStateEnum.VERIFICATION_INCONCLUSIVE.value):
            msg = f"Cannot verify action {action_model.command_id} in status '{action_model.status}'. Must be in VERIFYING or VERIFICATION_INCONCLUSIVE."
            logger.warning(msg)
            return ResponseStateEnum(action_model.status), msg

        # Run verification adapter
        determined_state, explanation = await self.adapter.verify(
            action=action_enum,
            parameters=action_model.parameters,
            observed_state=observed_state,
        )

        # Invariant: An execution receipt from dry-run mode strictly prevents VERIFIED_CONTAINED
        receipt = action_model.execution_receipt or {}
        is_dry_run_exec = (
            receipt.get("dry_run") is True
            or "[DRY-RUN]" in str(receipt.get("output", ""))
        )
        if is_dry_run_exec and determined_state == ResponseStateEnum.VERIFIED_CONTAINED:
            determined_state = ResponseStateEnum.VERIFICATION_INCONCLUSIVE
            explanation = f"[DRY-RUN] Execution was simulated; real containment cannot be established for {action_model.action}."

        old_status = action_model.status
        action_model.status = determined_state.value
        action_model.verification_result = {
            "status": determined_state.value,
            "explanation": explanation,
            "observed_state": observed_state,
            "verified_at": now_utc.isoformat(),
        }

        # If verified contained, check and update associated incident
        if determined_state == ResponseStateEnum.VERIFIED_CONTAINED:
            inc_query = select(IncidentModel).where(IncidentModel.id == action_model.incident_id)
            res = await session.execute(inc_query)
            incident = res.scalars().first()

            if incident and incident.status in ("OPEN", "INVESTIGATING"):
                incident.status = IncidentStatusEnum.CONTAINED.value
                history = list(incident.update_history or [])
                history.append({
                    "timestamp": now_utc.isoformat(),
                    "action": "INCIDENT_CONTAINED",
                    "command_id": str(action_model.command_id),
                    "response_action": action_model.action,
                    "explanation": explanation,
                })
                incident.update_history = history
                logger.info("Incident %s transitioned to CONTAINED by verified action %s", incident.id, action_model.command_id)

        # Audit ledger record
        await AuditLedgerService.record_action(
            session=session,
            actor_id="system:verification",
            actor_role="SYSTEM",
            action="CONTAINMENT_VERIFICATION_EVALUATED",
            target_entity=f"command:{action_model.command_id}",
            payload={
                "command_id": str(action_model.command_id),
                "previous_status": old_status,
                "determined_status": determined_state.value,
                "is_dry_run": is_dry_run_exec,
                "explanation": explanation,
                "incident_id": str(action_model.incident_id),
            },
            timestamp=now_utc,
        )

        logger.info(
            "Action %s verification complete: %s -> %s: %s",
            action_model.command_id, old_status, determined_state.value, explanation,
        )
        return determined_state, explanation
