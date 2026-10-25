"""Governed incident response plan service.

Implements approval gates, state transition rules, cryptographic approval hashes,
separation-of-duties tracking, idempotency enforcement, and simulation isolation.
"""

from datetime import datetime, timedelta, timezone
import hashlib
import json
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.audit.ledger_service import AuditLedgerService
from waliya.config import settings
from waliya.contracts import (
    ActionRiskClassificationEnum,
    ResponseActionEnum,
    ResponsePlanCreateRequest,
    ResponsePlanStatusEnum,
    ResponseStateEnum,
)
from waliya.core.crypto import (
    compute_command_signature,
    decrypt_agent_secret,
)
from waliya.db.models import (
    AgentModel,
    IncidentModel,
    ResponseActionModel,
    ResponsePlanModel,
)
from waliya.soar.action_registry import ResponseActionRegistry
from waliya.soar.adapters import ActionParametersValidator
from waliya.soar.playbook_engine import PlaybookEngine

logger = logging.getLogger("waliya.soar.plan_service")


class InvalidLifecycleTransitionError(ValueError):
    """Raised when an illegal response plan lifecycle transition is requested."""
    pass


def compute_actions_approval_hash(actions: List[Dict[str, Any]]) -> str:
    """Compute deterministic SHA-256 hash of response plan action definitions.

    Used to guarantee action specifications are not modified between approval and execution.
    """
    canonical_json = json.dumps(actions, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical_json.encode("utf-8")).hexdigest()


class ResponsePlanService:
    """Enterprise governance service for approval-gated incident response plans."""

    # Explicit finite state machine for plan lifecycle
    ALLOWED_TRANSITIONS = {
        ResponsePlanStatusEnum.DRAFT: {
            ResponsePlanStatusEnum.PENDING_APPROVAL,
            ResponsePlanStatusEnum.CANCELLED,
        },
        ResponsePlanStatusEnum.PENDING_APPROVAL: {
            ResponsePlanStatusEnum.APPROVED,
            ResponsePlanStatusEnum.REJECTED,
            ResponsePlanStatusEnum.CANCELLED,
        },
        ResponsePlanStatusEnum.APPROVED: {
            ResponsePlanStatusEnum.EXECUTING,
            ResponsePlanStatusEnum.CANCELLED,
        },
        ResponsePlanStatusEnum.EXECUTING: {
            ResponsePlanStatusEnum.SUCCEEDED,
            ResponsePlanStatusEnum.FAILED,
        },
        ResponsePlanStatusEnum.SUCCEEDED: set(),
        ResponsePlanStatusEnum.FAILED: set(),
        ResponsePlanStatusEnum.REJECTED: set(),
        ResponsePlanStatusEnum.CANCELLED: set(),
    }

    @classmethod
    def _validate_transition(
        cls,
        current_status: ResponsePlanStatusEnum,
        target_status: ResponsePlanStatusEnum,
    ) -> None:
        """Validate state transition against the formal lifecycle state machine."""
        allowed = cls.ALLOWED_TRANSITIONS.get(current_status, set())
        if target_status not in allowed:
            raise InvalidLifecycleTransitionError(
                f"Cannot transition response plan from {current_status.value} to {target_status.value}. "
                f"Allowed transitions: {[s.value for s in allowed] or 'None (terminal state)'}"
            )

    @classmethod
    async def _queue_status_notification(
        cls,
        session: AsyncSession,
        plan: ResponsePlanModel,
    ) -> None:
        """Queue outbound notification for response plan lifecycle events."""
        if getattr(plan, "is_simulation", False):
            return
        try:
            from waliya.integrations.delivery_service import NotificationDeliveryService
            from waliya.integrations.payloads import (
                NotificationEventType,
                build_response_plan_state_changed_payload,
            )
            notif = build_response_plan_state_changed_payload(
                plan_id=plan.id,
                plan_number=plan.plan_number or 0,
                title=plan.title,
                status=plan.status,
                risk_level=plan.risk_level,
                dry_run=plan.dry_run,
                actions_count=len(plan.actions or []),
                incident_id=plan.incident_id,
            )
            await NotificationDeliveryService.queue_notification(
                session=session,
                event_type=NotificationEventType.RESPONSE_PLAN_STATE_CHANGED.value,
                event_id=str(plan.id),
                payload=notif,
            )
        except Exception as err:
            logger.warning("Failed queuing response plan notification for plan %s: %s", plan.id, err)

    @classmethod
    async def create_plan(
        cls,
        session: AsyncSession,
        payload: ResponsePlanCreateRequest,
        created_by: str,
    ) -> ResponsePlanModel:
        """Create a new governed response plan with strict action parameter validation."""
        # Verify parent incident exists
        incident_res = await session.execute(
            select(IncidentModel).where(IncidentModel.id == payload.incident_id)
        )
        incident = incident_res.scalars().first()
        if not incident:
            raise ValueError(f"Target incident {payload.incident_id} does not exist.")

        # Determine simulation boundary
        is_simulation = bool(
            incident.is_simulation
            or (incident.title and incident.title.startswith("[SIMULATION]"))
        )
        effective_dry_run = True if is_simulation else payload.dry_run

        # Validate action items
        if not payload.actions:
            raise ValueError("Response plan must contain at least one response action.")

        validated_actions: List[Dict[str, Any]] = []
        for idx, item in enumerate(payload.actions):
            if not ResponseActionRegistry.is_supported(item.action.value):
                raise ValueError(f"Action '{item.action}' in step {idx+1} is not supported.")

            # Validate target agent exists
            ag_res = await session.execute(
                select(AgentModel).where(AgentModel.id == item.agent_id)
            )
            agent = ag_res.scalars().first()
            if not agent:
                raise ValueError(f"Target agent {item.agent_id} in step {idx+1} does not exist.")

            # Validate action parameters against strict allowlist schema
            validated_params = ActionParametersValidator.validate(item.action, item.parameters)
            action_meta = ResponseActionRegistry.get_metadata(item.action)

            validated_actions.append({
                "action": item.action.value,
                "parameters": validated_params,
                "agent_id": str(item.agent_id),
                "requires_approval": item.requires_approval,
                "risk_level": (
                    item.risk_level.value
                    if item.risk_level
                    else action_meta.risk_classification.value
                ),
                "description": item.description or action_meta.description,
            })

        # Calculate plan-level aggregate risk and approval mandate
        plan_risk = ResponseActionRegistry.compute_plan_risk(validated_actions)
        requires_approval = ResponseActionRegistry.plan_requires_approval(validated_actions)

        # Initial status and approval hash
        if payload.submit_for_approval:
            initial_status = ResponsePlanStatusEnum.PENDING_APPROVAL.value
            approval_hash = compute_actions_approval_hash(validated_actions)
        else:
            initial_status = ResponsePlanStatusEnum.DRAFT.value
            approval_hash = None

        plan = ResponsePlanModel(
            id=uuid4(),
            title=payload.title,
            description=payload.description,
            incident_id=incident.id,
            status=initial_status,
            risk_level=plan_risk.value,
            requires_approval=requires_approval,
            actions=validated_actions,
            approval_hash=approval_hash,
            dry_run=effective_dry_run,
            is_simulation=is_simulation,
            simulation_run_id=incident.simulation_run_id,
            created_by=created_by,
        )
        session.add(plan)
        await session.flush()

        # Audit ledger record for creation
        await AuditLedgerService.record_action(
            session=session,
            actor_id=created_by,
            actor_role="ANALYST",
            action="RESPONSE_PLAN_CREATED",
            target_entity=f"response_plan:{plan.id}",
            payload={
                "plan_id": str(plan.id),
                "plan_number": plan.plan_number,
                "incident_id": str(plan.incident_id),
                "title": plan.title,
                "status": plan.status,
                "risk_level": plan.risk_level,
                "actions_count": len(validated_actions),
                "requires_approval": plan.requires_approval,
                "dry_run": plan.dry_run,
                "is_simulation": plan.is_simulation,
            },
        )

        if payload.submit_for_approval:
            await AuditLedgerService.record_action(
                session=session,
                actor_id=created_by,
                actor_role="ANALYST",
                action="RESPONSE_PLAN_SUBMITTED",
                target_entity=f"response_plan:{plan.id}",
                payload={
                    "plan_id": str(plan.id),
                    "approval_hash": approval_hash,
                },
            )

        await session.commit()
        return plan

    @classmethod
    async def get_plan(
        cls,
        session: AsyncSession,
        plan_id: UUID,
    ) -> Optional[ResponsePlanModel]:
        """Retrieve response plan with linked actions."""
        stmt = (
            select(ResponsePlanModel)
            .where(ResponsePlanModel.id == plan_id)
            .options(selectinload(ResponsePlanModel.actions_rel))
        )
        res = await session.execute(stmt)
        return res.scalars().first()

    @classmethod
    async def list_plans(
        cls,
        session: AsyncSession,
        incident_id: Optional[UUID] = None,
        status_filter: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ResponsePlanModel]:
        """List response plans with optional incident or status filtering."""
        query = select(ResponsePlanModel).order_by(desc(ResponsePlanModel.created_at))
        if incident_id:
            query = query.where(ResponsePlanModel.incident_id == incident_id)
        if status_filter:
            query = query.where(ResponsePlanModel.status == status_filter)
        query = query.offset(offset).limit(limit)

        res = await session.execute(query)
        return list(res.scalars().all())

    @classmethod
    async def submit_plan(
        cls,
        session: AsyncSession,
        plan_id: UUID,
        actor_id: str,
    ) -> ResponsePlanModel:
        """Submit a draft plan for security approval and compute its cryptographic approval hash."""
        plan = await cls.get_plan(session, plan_id)
        if not plan:
            raise ValueError(f"Response plan {plan_id} not found.")

        current_enum = ResponsePlanStatusEnum(plan.status)
        cls._validate_transition(current_enum, ResponsePlanStatusEnum.PENDING_APPROVAL)

        # Compute tamper-evident approval hash over actions
        plan.approval_hash = compute_actions_approval_hash(plan.actions)
        plan.status = ResponsePlanStatusEnum.PENDING_APPROVAL.value

        await AuditLedgerService.record_action(
            session=session,
            actor_id=actor_id,
            actor_role="ANALYST",
            action="RESPONSE_PLAN_SUBMITTED",
            target_entity=f"response_plan:{plan.id}",
            payload={
                "plan_id": str(plan.id),
                "approval_hash": plan.approval_hash,
            },
        )
        await session.commit()
        return plan

    @classmethod
    async def approve_plan(
        cls,
        session: AsyncSession,
        plan_id: UUID,
        actor_id: str,
        reason: str,
    ) -> ResponsePlanModel:
        """Approve a pending response plan with separation-of-duties tracking."""
        plan = await cls.get_plan(session, plan_id)
        if not plan:
            raise ValueError(f"Response plan {plan_id} not found.")

        current_enum = ResponsePlanStatusEnum(plan.status)
        cls._validate_transition(current_enum, ResponsePlanStatusEnum.APPROVED)

        # Verify action integrity against submission hash
        current_hash = compute_actions_approval_hash(plan.actions)
        if plan.approval_hash and current_hash != plan.approval_hash:
            raise ValueError(
                f"Action payload mismatch detected. Submission hash {plan.approval_hash} "
                f"does not match current hash {current_hash}."
            )
        plan.approval_hash = current_hash

        # Separation of duties tracking
        separation_of_duties_honored = bool(plan.created_by != actor_id)

        now_utc = datetime.now(timezone.utc)
        plan.status = ResponsePlanStatusEnum.APPROVED.value
        plan.approved_by = actor_id
        plan.approved_at = now_utc
        plan.approval_reason = reason

        await AuditLedgerService.record_action(
            session=session,
            actor_id=actor_id,
            actor_role="ADMIN",
            action="RESPONSE_PLAN_APPROVED",
            target_entity=f"response_plan:{plan.id}",
            payload={
                "plan_id": str(plan.id),
                "approved_by": actor_id,
                "created_by": plan.created_by,
                "separation_of_duties_honored": separation_of_duties_honored,
                "approval_hash": plan.approval_hash,
                "reason": reason,
            },
        )
        await cls._queue_status_notification(session, plan)
        await session.commit()
        return plan

    @classmethod
    async def reject_plan(
        cls,
        session: AsyncSession,
        plan_id: UUID,
        actor_id: str,
        reason: str,
    ) -> ResponsePlanModel:
        """Reject a pending response plan with justification."""
        plan = await cls.get_plan(session, plan_id)
        if not plan:
            raise ValueError(f"Response plan {plan_id} not found.")

        current_enum = ResponsePlanStatusEnum(plan.status)
        cls._validate_transition(current_enum, ResponsePlanStatusEnum.REJECTED)

        plan.status = ResponsePlanStatusEnum.REJECTED.value
        plan.rejected_by = actor_id
        plan.rejection_reason = reason

        await AuditLedgerService.record_action(
            session=session,
            actor_id=actor_id,
            actor_role="ADMIN",
            action="RESPONSE_PLAN_REJECTED",
            target_entity=f"response_plan:{plan.id}",
            payload={
                "plan_id": str(plan.id),
                "rejected_by": actor_id,
                "reason": reason,
            },
        )
        await cls._queue_status_notification(session, plan)
        await session.commit()
        return plan

    @classmethod
    async def cancel_plan(
        cls,
        session: AsyncSession,
        plan_id: UUID,
        actor_id: str,
        reason: str,
    ) -> ResponsePlanModel:
        """Cancel an unexecuted response plan."""
        plan = await cls.get_plan(session, plan_id)
        if not plan:
            raise ValueError(f"Response plan {plan_id} not found.")

        current_enum = ResponsePlanStatusEnum(plan.status)
        cls._validate_transition(current_enum, ResponsePlanStatusEnum.CANCELLED)

        plan.status = ResponsePlanStatusEnum.CANCELLED.value
        plan.cancelled_by = actor_id
        plan.cancellation_reason = reason

        await AuditLedgerService.record_action(
            session=session,
            actor_id=actor_id,
            actor_role="ANALYST",
            action="RESPONSE_PLAN_CANCELLED",
            target_entity=f"response_plan:{plan.id}",
            payload={
                "plan_id": str(plan.id),
                "cancelled_by": actor_id,
                "reason": reason,
            },
        )
        await cls._queue_status_notification(session, plan)
        await session.commit()
        return plan

    @classmethod
    async def execute_plan(
        cls,
        session: AsyncSession,
        plan_id: UUID,
        actor_id: str,
        dry_run: Optional[bool] = None,
        idempotency_key: Optional[str] = None,
    ) -> ResponsePlanModel:
        """Execute an approved response plan with idempotency, integrity verification, and adapter coordination."""
        from waliya.soar.execution_engine import ResponseExecutionEngine

        return await ResponseExecutionEngine.execute_plan(
            session=session,
            plan_id=plan_id,
            actor_id=actor_id,
            dry_run=dry_run,
            idempotency_key=idempotency_key,
        )

    @classmethod
    async def reconcile_plan(
        cls,
        session: AsyncSession,
        plan_id: UUID,
        actor_id: str,
        reason: str,
    ) -> ResponsePlanModel:
        """Safely reconcile an interrupted or stalled response plan execution."""
        stmt = (
            select(ResponsePlanModel)
            .where(ResponsePlanModel.id == plan_id)
            .options(selectinload(ResponsePlanModel.actions_rel))
            .with_for_update()
        )
        res = await session.execute(stmt)
        plan = res.scalars().first()
        if not plan:
            raise ValueError(f"Response plan {plan_id} not found.")

        # Only plans currently EXECUTING can be reconciled
        if plan.status != ResponsePlanStatusEnum.EXECUTING.value:
            raise InvalidLifecycleTransitionError(
                f"Cannot reconcile response plan in status '{plan.status}'. Only EXECUTING plans can be reconciled."
            )

        now_utc = datetime.now(timezone.utc)
        actions_reconciled = 0
        all_actions_succeeded = True

        if plan.actions_rel:
            for act in plan.actions_rel:
                # If action was left in non-terminal / unconfirmed state (QUEUED, RECEIVED, REQUESTED)
                if act.status in (
                    ResponseStateEnum.QUEUED.value,
                    ResponseStateEnum.RECEIVED.value,
                    ResponseStateEnum.REQUESTED.value,
                ):
                    act.status = ResponseStateEnum.OUTCOME_UNCERTAIN.value
                    receipt = act.execution_receipt or {}
                    receipt["status"] = ResponseStateEnum.OUTCOME_UNCERTAIN.value
                    receipt["is_uncertain"] = True
                    receipt["error_message"] = f"Execution interrupted; reconciled as OUTCOME_UNCERTAIN: {reason}"
                    receipt["reconciled_by"] = actor_id
                    receipt["reconciled_at"] = now_utc.isoformat()
                    act.execution_receipt = receipt
                    actions_reconciled += 1
                    all_actions_succeeded = False
                elif act.status != ResponseStateEnum.EXECUTED.value:
                    all_actions_succeeded = False
        else:
            all_actions_succeeded = False

        plan.status = (
            ResponsePlanStatusEnum.SUCCEEDED.value
            if all_actions_succeeded and len(plan.actions_rel or []) == len(plan.actions)
            else ResponsePlanStatusEnum.FAILED.value
        )

        summary = plan.execution_summary or {}
        summary["reconciled"] = True
        summary["reconciled_by"] = actor_id
        summary["reconciled_at"] = now_utc.isoformat()
        summary["reconciliation_reason"] = reason
        summary["has_uncertain_outcomes"] = not all_actions_succeeded
        plan.execution_summary = summary

        await AuditLedgerService.record_action(
            session=session,
            actor_id=actor_id,
            actor_role="ADMIN",
            action="RESPONSE_PLAN_RECONCILED",
            target_entity=f"response_plan:{plan.id}",
            payload={
                "plan_id": str(plan.id),
                "reconciled_by": actor_id,
                "reason": reason,
                "previous_status": "EXECUTING",
                "final_status": plan.status,
                "actions_reconciled_count": actions_reconciled,
            },
        )

        await session.commit()
        return plan
