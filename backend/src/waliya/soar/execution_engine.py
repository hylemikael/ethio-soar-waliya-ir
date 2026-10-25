"""Reliable response execution engine and adapter coordinator.

Provides pre-execution validation, row-level locking for concurrency control,
adapter resolution, bounded timeouts, safe retry policies, durable execution receipts,
and tamper-evident audit logging.
"""

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.audit.ledger_service import AuditLedgerService
from waliya.config import settings
from waliya.contracts import (
    ActionRiskClassificationEnum,
    ExecutionModeEnum,
    ResponseActionEnum,
    ResponsePlanStatusEnum,
    ResponseStateEnum,
)
from waliya.core.crypto import compute_command_signature, decrypt_agent_secret
from waliya.db.models import AgentModel, IncidentModel, ResponseActionModel, ResponsePlanModel
from waliya.soar.action_registry import ACTION_REGISTRY, compute_actions_approval_hash
from waliya.soar.adapters import (
    ActionParametersValidator,
    BaseResponseAdapter,
    DryRunResponseAdapter,
    LinuxHostResponseAdapter,
)
from waliya.soar.playbook_engine import PlaybookEngine

logger = logging.getLogger("waliya.soar.execution_engine")


@dataclass
class AdapterExecutionOutcome:
    """Standardized result of a response adapter execution attempt."""
    status: ResponseStateEnum
    exit_code: Optional[int]
    output: str
    error_message: Optional[str]
    is_uncertain: bool
    attempt_count: int
    started_at: datetime
    completed_at: datetime

    @property
    def duration_ms(self) -> float:
        return round((self.completed_at - self.started_at).total_seconds() * 1000, 2)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "exit_code": self.exit_code,
            "output": self.output,
            "error_message": self.error_message,
            "is_uncertain": self.is_uncertain,
            "attempt_count": self.attempt_count,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat(),
            "duration_ms": self.duration_ms,
        }


class ResponseExecutionEngine:
    """Coordinator for governed response plan execution across allowlisted adapters."""

    @classmethod
    def resolve_adapter(
        cls,
        action: ResponseActionEnum,
        execution_mode: ExecutionModeEnum,
    ) -> BaseResponseAdapter:
        """Resolve authoritative adapter for the requested action and execution mode.

        Raises:
            ValueError: If the action is not declared in ACTION_REGISTRY.
        """
        if action not in ACTION_REGISTRY:
            raise ValueError(
                f"Action '{action.value if hasattr(action, 'value') else action}' is not registered "
                "in allowlisted ACTION_REGISTRY. Refusing to resolve adapter."
            )

        if execution_mode in (ExecutionModeEnum.DRY_RUN, ExecutionModeEnum.SIMULATION):
            return DryRunResponseAdapter()

        # Operational production execution
        return LinuxHostResponseAdapter()

    @classmethod
    async def execute_action_step(
        cls,
        action_type: ResponseActionEnum,
        parameters: Dict[str, Any],
        execution_mode: ExecutionModeEnum,
        timeout_seconds: Optional[int] = None,
    ) -> AdapterExecutionOutcome:
        """Execute a single allowlisted response action with bounded timeout and safe retry policy."""
        start_time = datetime.now(timezone.utc)

        # 1. Re-validate parameters to enforce safety invariants
        try:
            validated_params = ActionParametersValidator.validate(action_type, parameters)
        except ValueError as err:
            logger.error("Pre-execution parameter validation failed for %s: %s", action_type.value, err)
            return AdapterExecutionOutcome(
                status=ResponseStateEnum.FAILED,
                exit_code=1,
                output="",
                error_message=f"Parameter validation failed: {err}",
                is_uncertain=False,
                attempt_count=1,
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
            )

        # 2. Retrieve action metadata and safety policies
        action_meta = ACTION_REGISTRY.get(action_type)
        if not action_meta:
            return AdapterExecutionOutcome(
                status=ResponseStateEnum.FAILED,
                exit_code=1,
                output="",
                error_message=f"Action '{action_type.value}' not found in ACTION_REGISTRY",
                is_uncertain=False,
                attempt_count=1,
                started_at=start_time,
                completed_at=datetime.now(timezone.utc),
            )

        timeout = timeout_seconds or action_meta.default_timeout_seconds
        max_retries = action_meta.max_retries
        is_destructive = (action_meta.risk_classification == ActionRiskClassificationEnum.DESTRUCTIVE)
        is_dry_run = (execution_mode != ExecutionModeEnum.PRODUCTION)

        adapter = cls.resolve_adapter(action_type, execution_mode)

        attempt = 0
        outcome: Optional[AdapterExecutionOutcome] = None

        while attempt <= max_retries:
            attempt += 1
            step_start = datetime.now(timezone.utc)
            try:
                res = await asyncio.wait_for(
                    adapter.execute(action_type, validated_params, dry_run=is_dry_run),
                    timeout=float(timeout),
                )
                step_end = datetime.now(timezone.utc)
                outcome = AdapterExecutionOutcome(
                    status=ResponseStateEnum.EXECUTED,
                    exit_code=res.get("exit_code", 0),
                    output=res.get("output", ""),
                    error_message=None,
                    is_uncertain=False,
                    attempt_count=attempt,
                    started_at=step_start,
                    completed_at=step_end,
                )
                break

            except asyncio.TimeoutError:
                step_end = datetime.now(timezone.utc)
                err_msg = f"Execution timed out after {timeout} seconds"
                logger.warning(
                    "Action %s (attempt %d) timed out after %ds. Setting OUTCOME_UNCERTAIN; aborting retries.",
                    action_type.value, attempt, timeout,
                )
                # Timeout on endpoint or network means the command might or might not have run on host.
                # Never retry destructive actions on timeout.
                outcome = AdapterExecutionOutcome(
                    status=ResponseStateEnum.TIMED_OUT,
                    exit_code=None,
                    output="",
                    error_message=err_msg,
                    is_uncertain=True,
                    attempt_count=attempt,
                    started_at=step_start,
                    completed_at=step_end,
                )
                break

            except Exception as exc:
                step_end = datetime.now(timezone.utc)
                err_msg = str(exc)
                logger.warning(
                    "Action %s failed on attempt %d: %s",
                    action_type.value, attempt, err_msg,
                )
                # Destructive actions are never retried upon failure to prevent compounding harm
                if is_destructive or attempt > max_retries:
                    outcome = AdapterExecutionOutcome(
                        status=ResponseStateEnum.FAILED,
                        exit_code=1,
                        output="",
                        error_message=err_msg,
                        is_uncertain=False,
                        attempt_count=attempt,
                        started_at=step_start,
                        completed_at=step_end,
                    )
                    break

        return outcome or AdapterExecutionOutcome(
            status=ResponseStateEnum.FAILED,
            exit_code=1,
            output="",
            error_message="Unknown execution failure",
            is_uncertain=False,
            attempt_count=attempt,
            started_at=start_time,
            completed_at=datetime.now(timezone.utc),
        )

    @classmethod
    async def execute_plan(
        cls,
        session: AsyncSession,
        plan_id: UUID,
        actor_id: str,
        dry_run: Optional[bool] = None,
        idempotency_key: Optional[str] = None,
    ) -> ResponsePlanModel:
        """Execute an approved response plan with concurrency row-locking, idempotency, and adapter coordination."""
        # 1. Acquire row-level database lock using with_for_update() to prevent race conditions
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

        # 2. Idempotency & Replay Verification
        if idempotency_key and plan.idempotency_key == idempotency_key:
            if plan.status in (
                ResponsePlanStatusEnum.SUCCEEDED.value,
                ResponsePlanStatusEnum.FAILED.value,
            ):
                logger.info(
                    "Idempotent replay detected for completed plan %s with key %s. Returning cached result.",
                    plan_id, idempotency_key,
                )
                return plan
            if plan.status == ResponsePlanStatusEnum.EXECUTING.value:
                raise ValueError(
                    f"Response plan {plan_id} execution with idempotency key '{idempotency_key}' is already in progress."
                )

        # 3. State Invariant Verification: Plan must be APPROVED
        if plan.status != ResponsePlanStatusEnum.APPROVED.value:
            from waliya.soar.plan_service import InvalidLifecycleTransitionError

            raise InvalidLifecycleTransitionError(
                f"Cannot transition response plan from {plan.status} to EXECUTING."
            )

        # 4. Canonical Approval Hash Verification (Tamper Detection)
        current_hash = compute_actions_approval_hash(plan.actions)
        if plan.requires_approval and plan.approval_hash and current_hash != plan.approval_hash:
            raise ValueError(
                f"Action payload mismatch detected at execution time. Approved hash: {plan.approval_hash}, "
                f"Actual payload hash: {current_hash}. Plan execution aborted."
            )

        # 5. Resolve Execution Mode & Simulation Boundaries
        inc_res = await session.execute(
            select(IncidentModel).where(IncidentModel.id == plan.incident_id)
        )
        incident = inc_res.scalars().first()
        if not incident:
            raise ValueError(f"Linked incident {plan.incident_id} not found.")

        is_sim = bool(
            incident.is_simulation
            or plan.is_simulation
            or (incident.title and incident.title.startswith("[SIMULATION]"))
        )

        if is_sim:
            execution_mode = ExecutionModeEnum.SIMULATION
            effective_dry_run = True
            if dry_run is False:
                logger.warning(
                    "Plan %s belongs to simulation incident %s. Forcing dry_run=True.",
                    plan.id, incident.id,
                )
        elif dry_run is True or (dry_run is None and plan.dry_run is True):
            execution_mode = ExecutionModeEnum.DRY_RUN
            effective_dry_run = True
        else:
            execution_mode = ExecutionModeEnum.PRODUCTION
            effective_dry_run = False

        plan.dry_run = effective_dry_run
        if idempotency_key:
            plan.idempotency_key = idempotency_key

        plan.status = ResponsePlanStatusEnum.EXECUTING.value
        await session.flush()

        now_utc = datetime.now(timezone.utc)

        # 6. Audit: Execution Started
        await AuditLedgerService.record_action(
            session=session,
            actor_id=actor_id,
            actor_role="ADMIN",
            action="RESPONSE_PLAN_EXECUTING",
            target_entity=f"response_plan:{plan.id}",
            payload={
                "plan_id": str(plan.id),
                "incident_id": str(plan.incident_id),
                "execution_mode": execution_mode.value,
                "dry_run": effective_dry_run,
                "is_simulation": is_sim,
                "simulation_run_id": plan.simulation_run_id or incident.simulation_run_id,
                "idempotency_key": idempotency_key,
                "approval_hash": plan.approval_hash,
                "actions_count": len(plan.actions),
            },
        )

        step_results: List[Dict[str, Any]] = []
        count_succeeded = 0
        count_failed = 0
        count_uncertain = 0

        # 7. Coordinate Step Execution
        for idx, act in enumerate(plan.actions):
            act_type_str = act.get("action")
            agent_id_str = act.get("agent_id")
            raw_params = act.get("parameters", {})

            # Validate action enum and agent UUID
            try:
                action_enum = ResponseActionEnum(act_type_str)
                agent_uuid = UUID(agent_id_str)
            except Exception as exc:
                count_failed += 1
                failure_receipt = {
                    "step": idx + 1,
                    "action": act_type_str,
                    "status": ResponseStateEnum.FAILED.value,
                    "error_message": f"Invalid action or agent ID: {exc}",
                    "is_uncertain": False,
                    "execution_mode": execution_mode.value,
                }
                step_results.append(failure_receipt)
                continue

            # Look up target agent
            ag_res = await session.execute(select(AgentModel).where(AgentModel.id == agent_uuid))
            agent = ag_res.scalars().first()
            if not agent:
                count_failed += 1
                failure_receipt = {
                    "step": idx + 1,
                    "action": action_enum.value,
                    "agent_id": str(agent_uuid),
                    "status": ResponseStateEnum.FAILED.value,
                    "error_message": f"Target agent {agent_id_str} not found in database.",
                    "is_uncertain": False,
                    "execution_mode": execution_mode.value,
                }
                step_results.append(failure_receipt)
                continue

            # Production check: fail-closed if agent is revoked or offline
            if execution_mode == ExecutionModeEnum.PRODUCTION and agent.status in ("REVOKED", "OFFLINE"):
                count_failed += 1
                failure_receipt = {
                    "step": idx + 1,
                    "action": action_enum.value,
                    "agent_id": str(agent.id),
                    "status": ResponseStateEnum.FAILED.value,
                    "error_message": f"Target agent {agent.id} is {agent.status}. Refusing production execution.",
                    "is_uncertain": False,
                    "execution_mode": execution_mode.value,
                }
                step_results.append(failure_receipt)
                continue

            # Generate signed command envelope for agent replay protection & auditability
            agent_secret = decrypt_agent_secret(agent.secret_key_enc, settings.SECRET_KEY)
            seq = await PlaybookEngine.get_next_agent_sequence(session, agent.id)
            nonce = uuid4()
            command_id = uuid4()
            issued_at = datetime.now(timezone.utc)
            expires_at = issued_at + timedelta(seconds=settings.COMMAND_TTL_SECONDS)

            try:
                validated_params = ActionParametersValidator.validate(action_enum, raw_params)
            except ValueError as val_err:
                count_failed += 1
                failure_receipt = {
                    "step": idx + 1,
                    "action": action_enum.value,
                    "agent_id": str(agent.id),
                    "status": ResponseStateEnum.FAILED.value,
                    "error_message": f"Parameter validation failed: {val_err}",
                    "is_uncertain": False,
                    "execution_mode": execution_mode.value,
                }
                step_results.append(failure_receipt)
                continue

            signature = compute_command_signature(
                command_id=command_id,
                agent_id=agent.id,
                action=action_enum.value,
                parameters=validated_params,
                sequence=seq,
                nonce=nonce,
                issued_at=issued_at,
                expires_at=expires_at,
                secret_key=agent_secret,
            )

            # Execute via adapter with bounded timeout & safe retries
            outcome = await cls.execute_action_step(
                action_type=action_enum,
                parameters=validated_params,
                execution_mode=execution_mode,
            )

            receipt_dict = outcome.to_dict()
            receipt_dict["operation_id"] = str(uuid4())
            receipt_dict["command_id"] = str(command_id)
            receipt_dict["step"] = idx + 1
            receipt_dict["action"] = action_enum.value
            receipt_dict["agent_id"] = str(agent.id)
            receipt_dict["execution_mode"] = execution_mode.value
            receipt_dict["dry_run"] = effective_dry_run

            if outcome.status == ResponseStateEnum.EXECUTED:
                count_succeeded += 1
            elif outcome.status in (ResponseStateEnum.TIMED_OUT, ResponseStateEnum.OUTCOME_UNCERTAIN):
                count_uncertain += 1
            else:
                count_failed += 1

            # Persist durable action record linked to the response plan
            action_model = ResponseActionModel(
                id=uuid4(),
                command_id=command_id,
                response_plan_id=plan.id,
                incident_id=incident.id,
                agent_id=agent.id,
                action=action_enum.value,
                parameters=validated_params,
                status=outcome.status.value,
                nonce=nonce,
                sequence=seq,
                issued_at=issued_at,
                expires_at=expires_at,
                signature=signature,
                execution_receipt=receipt_dict,
                requested_by=plan.created_by,
                approved_by=plan.approved_by or actor_id,
                approved_at=plan.approved_at or now_utc,
                approval_reason=plan.approval_reason or "Approved governed response plan execution",
            )
            session.add(action_model)

            step_results.append(receipt_dict)

            # Audit ledger per step
            audit_action = (
                "RESPONSE_ACTION_EXECUTED"
                if outcome.status == ResponseStateEnum.EXECUTED
                else (
                    "RESPONSE_ACTION_TIMED_OUT"
                    if outcome.status == ResponseStateEnum.TIMED_OUT
                    else "RESPONSE_ACTION_FAILED"
                )
            )
            await AuditLedgerService.record_action(
                session=session,
                actor_id=actor_id,
                actor_role="ADMIN",
                action=audit_action,
                target_entity=f"response_action:{command_id}",
                payload={
                    "plan_id": str(plan.id),
                    "step": idx + 1,
                    "action": action_enum.value,
                    "agent_id": str(agent.id),
                    "status": outcome.status.value,
                    "is_uncertain": outcome.is_uncertain,
                    "execution_mode": execution_mode.value,
                    "duration_ms": outcome.duration_ms,
                    "error_message": outcome.error_message,
                },
            )

        # 8. Determine Final Plan Status and Compile Execution Summary
        has_uncertain = (count_uncertain > 0)
        has_failure = (count_failed > 0 or has_uncertain)

        plan.status = (
            ResponsePlanStatusEnum.FAILED.value
            if has_failure
            else ResponsePlanStatusEnum.SUCCEEDED.value
        )

        completed_at = datetime.now(timezone.utc)
        plan.execution_summary = {
            "executed_by": actor_id,
            "executed_at": now_utc.isoformat(),
            "completed_at": completed_at.isoformat(),
            "execution_mode": execution_mode.value,
            "dry_run": effective_dry_run,
            "is_simulation": is_sim,
            "simulation_run_id": plan.simulation_run_id or incident.simulation_run_id,
            "total_steps": len(plan.actions),
            "succeeded_steps": count_succeeded,
            "failed_steps": count_failed,
            "uncertain_steps": count_uncertain,
            "has_uncertain_outcomes": has_uncertain,
            "results": step_results,
        }

        # 9. Final Plan Execution Audit Record
        final_audit_action = (
            "RESPONSE_PLAN_FAILED" if has_failure else "RESPONSE_PLAN_EXECUTED"
        )
        await AuditLedgerService.record_action(
            session=session,
            actor_id=actor_id,
            actor_role="ADMIN",
            action=final_audit_action,
            target_entity=f"response_plan:{plan.id}",
            payload={
                "plan_id": str(plan.id),
                "status": plan.status,
                "execution_mode": execution_mode.value,
                "dry_run": effective_dry_run,
                "total_steps": len(plan.actions),
                "succeeded_steps": count_succeeded,
                "failed_steps": count_failed,
                "uncertain_steps": count_uncertain,
                "has_uncertain_outcomes": has_uncertain,
            },
        )

        await session.commit()
        return plan
