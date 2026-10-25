"""SOAR management endpoints for playbook execution, action approval, and audit verification."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.inspection import inspect

from waliya.audit.ledger_service import AuditLedgerService
from waliya.contracts import (
    ActionRegistryEntryResponse,
    ActionRiskClassificationEnum,
    AuditLedgerRecord,
    AuditVerificationResponse,
    PlaybookRunSummary,
    PlaybookSchema,
    ResponseActionEnum,
    ResponsePlanApprovalRequest,
    ResponsePlanCancelRequest,
    ResponsePlanCreateRequest,
    ResponsePlanExecuteRequest,
    ResponsePlanReconcileRequest,
    ResponsePlanResponse,
    ResponsePlanStatusEnum,
    ResponseStateEnum,
)
from waliya.core.auth import verify_admin_key, verify_operator_or_admin
from waliya.db.models import (
    AgentModel,
    AuditLedgerModel,
    IncidentModel,
    PlaybookModel,
    PlaybookRunModel,
    ResponseActionModel,
    ResponsePlanModel,
)
from waliya.db.session import get_db_session
from waliya.soar.action_registry import ResponseActionRegistry
from waliya.soar.adapters import ActionParametersValidator
from waliya.soar.plan_service import InvalidLifecycleTransitionError, ResponsePlanService
from waliya.soar.playbook_engine import PlaybookEngine, seed_builtin_playbooks

logger = logging.getLogger("waliya.api.routes.soar")

router = APIRouter(prefix="/soar", tags=["soar"])


class ActionApprovalRequest(BaseModel):
    """Payload for analyst or administrator approval."""
    reason: str = Field(..., min_length=3, max_length=1000, description="Authorization justification")


class PlaybookExecuteRequest(BaseModel):
    """Payload to trigger a playbook execution run."""
    playbook_id: UUID
    incident_id: UUID
    agent_id: UUID
    dry_run: bool = Field(default=True, description="Dry-run simulation mode")
    context_override: Optional[Dict[str, Any]] = Field(default=None, description="Optional manual parameter overrides")


@router.get(
    "/playbooks",
    response_model=List[PlaybookSchema],
    status_code=status.HTTP_200_OK,
    summary="List available response playbooks",
)
async def list_playbooks(
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> List[PlaybookSchema]:
    """Retrieve all configured SOAR playbooks."""
    await seed_builtin_playbooks(session)
    res = await session.execute(select(PlaybookModel).where(PlaybookModel.is_active == True))
    playbooks = res.scalars().all()

    return [
        PlaybookSchema(
            playbook_id=pb.id,
            name=pb.name,
            description=pb.description,
            trigger_conditions=pb.trigger_conditions or [],
            action_steps=pb.action_steps or [],
            requires_approval=pb.requires_approval,
            is_active=pb.is_active,
        )
        for pb in playbooks
    ]


@router.post(
    "/playbooks/execute",
    response_model=PlaybookRunSummary,
    status_code=status.HTTP_200_OK,
    summary="Trigger playbook execution against incident",
)
async def execute_playbook(
    payload: PlaybookExecuteRequest,
    admin_id: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> PlaybookRunSummary:
    """Execute response playbook with dry-run default and approval gates."""
    # Validate playbook exists
    pb_res = await session.execute(select(PlaybookModel).where(PlaybookModel.id == payload.playbook_id))
    playbook = pb_res.scalars().first()
    if not playbook:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook '{payload.playbook_id}' not found",
        )

    # Validate incident exists
    inc_res = await session.execute(select(IncidentModel).where(IncidentModel.id == payload.incident_id))
    incident = inc_res.scalars().first()
    if not incident:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident '{payload.incident_id}' not found",
        )

    # Validate target agent exists
    ag_res = await session.execute(select(AgentModel).where(AgentModel.id == payload.agent_id))
    agent = ag_res.scalars().first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Agent '{payload.agent_id}' not found",
        )

    run = await PlaybookEngine.execute_playbook(
        session=session,
        playbook=playbook,
        incident=incident,
        agent=agent,
        executed_by=admin_id,
        dry_run=payload.dry_run,
        context_override=payload.context_override,
    )

    return PlaybookRunSummary(
        run_id=run.id,
        playbook_id=run.playbook_id,
        incident_id=run.incident_id,
        status=run.status,
        dry_run=run.dry_run,
        executed_by=run.executed_by,
        start_time=run.start_time,
        end_time=run.end_time,
    )


@router.get(
    "/runs/{run_id}",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Get playbook run execution status and step results",
)
async def get_playbook_run(
    run_id: UUID,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Retrieve detailed execution status and step outputs for a playbook run."""
    run_res = await session.execute(select(PlaybookRunModel).where(PlaybookRunModel.id == run_id))
    run = run_res.scalars().first()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Playbook run '{run_id}' not found",
        )

    # Fetch associated actions
    act_res = await session.execute(select(ResponseActionModel).where(ResponseActionModel.playbook_run_id == run.id))
    actions = act_res.scalars().all()

    return {
        "run_id": str(run.id),
        "playbook_id": str(run.playbook_id),
        "incident_id": str(run.incident_id),
        "status": run.status,
        "dry_run": run.dry_run,
        "executed_by": run.executed_by,
        "start_time": run.start_time.isoformat() if run.start_time else None,
        "end_time": run.end_time.isoformat() if run.end_time else None,
        "output_summary": run.output_summary or {},
        "actions": [
            {
                "command_id": str(a.command_id),
                "action": a.action,
                "status": a.status,
                "parameters": a.parameters,
                "sequence": a.sequence,
                "approved_by": a.approved_by,
                "approved_at": a.approved_at.isoformat() if a.approved_at else None,
            }
            for a in actions
        ],
    }


@router.post(
    "/actions/{action_id}/approve",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Authorize and approve a pending response action",
)
async def approve_response_action(
    action_id: UUID,
    payload: ActionApprovalRequest,
    admin_id: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Approve a pending action and promote it to QUEUED state for agent execution.

    Enforces:
    - Verifies action is currently PENDING_APPROVAL.
    - Re-validates parameters against schemas to prevent payload tampering.
    - Records approver identity, timestamp, and justification.
    - Emits immutable cryptographic audit entry.
    """
    act_res = await session.execute(select(ResponseActionModel).where(ResponseActionModel.id == action_id))
    action = act_res.scalars().first()
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action '{action_id}' not found",
        )

    if action.status != ResponseStateEnum.PENDING_APPROVAL.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action '{action_id}' is in status '{action.status}', expected PENDING_APPROVAL",
        )

    # Re-validate parameters to prevent approval reuse with modified payloads
    action_enum = ResponseActionEnum(action.action)
    try:
        ActionParametersValidator.validate(action_enum, action.parameters)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Action parameters invalid: {val_err}",
        )

    now_utc = datetime.now(timezone.utc)
    action.status = ResponseStateEnum.QUEUED.value
    action.approved_by = admin_id
    action.approved_at = now_utc
    action.approval_reason = payload.reason

    # Audit record
    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_id,
        actor_role="ADMIN",
        action="RESPONSE_ACTION_APPROVED",
        target_entity=f"command:{action.command_id}",
        payload={
            "action_id": str(action.id),
            "command_id": str(action.command_id),
            "approved_by": admin_id,
            "reason": payload.reason,
            "action": action.action,
            "parameters": action.parameters,
        },
        timestamp=now_utc,
    )

    await session.commit()
    logger.info("Action %s approved by %s (reason: %s)", action_id, admin_id, payload.reason)

    return {
        "action_id": str(action.id),
        "command_id": str(action.command_id),
        "status": action.status,
        "approved_by": action.approved_by,
        "approved_at": action.approved_at.isoformat(),
        "message": f"Action approved successfully and promoted to {action.status}",
    }


@router.post(
    "/actions/{action_id}/reject",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Reject a pending response action",
)
async def reject_response_action(
    action_id: UUID,
    payload: ActionApprovalRequest,
    admin_id: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Reject an action and transition it to terminal REJECTED state."""
    act_res = await session.execute(select(ResponseActionModel).where(ResponseActionModel.id == action_id))
    action = act_res.scalars().first()
    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response action '{action_id}' not found",
        )

    if action.status not in (ResponseStateEnum.PENDING_APPROVAL.value, ResponseStateEnum.REQUESTED.value):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Action '{action_id}' cannot be rejected in current status '{action.status}'",
        )

    now_utc = datetime.now(timezone.utc)
    action.status = ResponseStateEnum.REJECTED.value

    # Audit record
    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_id,
        actor_role="ADMIN",
        action="RESPONSE_ACTION_REJECTED",
        target_entity=f"command:{action.command_id}",
        payload={
            "action_id": str(action.id),
            "command_id": str(action.command_id),
            "rejected_by": admin_id,
            "reason": payload.reason,
        },
        timestamp=now_utc,
    )

    await session.commit()
    return {
        "action_id": str(action.id),
        "command_id": str(action.command_id),
        "status": action.status,
        "message": "Action rejected and cancelled",
    }


@router.get(
    "/audit/verify",
    response_model=AuditVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Cryptographically verify audit ledger chain",
)
async def verify_audit_ledger(
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> AuditVerificationResponse:
    """Validate hash chain integrity from genesis record to latest committed head."""
    return await AuditLedgerService.verify_chain(session)


@router.get(
    "/audit/records",
    response_model=List[AuditLedgerRecord],
    status_code=status.HTTP_200_OK,
    summary="List paginated audit ledger records",
)
async def list_audit_records(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> List[AuditLedgerRecord]:
    """Retrieve chronologically ordered audit ledger records."""
    query = (
        select(AuditLedgerModel)
        .order_by(AuditLedgerModel.sequence_number.asc())
        .offset(offset)
        .limit(limit)
    )
    res = await session.execute(query)
    records = res.scalars().all()

    return [
        AuditLedgerRecord(
            sequence_number=r.sequence_number,
            record_id=r.id,
            timestamp=r.timestamp,
            actor_id=r.actor_id,
            actor_role=r.actor_role,
            action=r.action,
            target_entity=r.target_entity,
            canonical_payload=r.canonical_payload,
            previous_hash=r.previous_hash,
            current_hash=r.current_hash,
        )
        for r in records
    ]


@router.get(
    "/actions",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List response actions and approvals",
)
async def list_response_actions(
    status_filter: Optional[str] = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """Retrieve response actions with target agent, incident, and execution context."""
    query = (
        select(ResponseActionModel)
        .order_by(ResponseActionModel.issued_at.desc())
        .offset(offset)
        .limit(limit)
    )
    if status_filter:
        query = query.where(ResponseActionModel.status == status_filter)

    res = await session.execute(query)
    actions = res.scalars().all()

    # Pre-fetch agent hostnames and incident numbers for rich context
    agent_ids = {a.agent_id for a in actions if a.agent_id}
    inc_ids = {a.incident_id for a in actions if a.incident_id}

    agent_map: Dict[UUID, Dict[str, Any]] = {}
    if agent_ids:
        ag_res = await session.execute(select(AgentModel).where(AgentModel.id.in_(agent_ids)))
        for ag in ag_res.scalars().all():
            agent_map[ag.id] = {
                "hostname": ag.hostname,
                "primary_ip": ag.primary_ip,
                "status": ag.status,
            }

    inc_map: Dict[UUID, Dict[str, Any]] = {}
    if inc_ids:
        inc_res = await session.execute(select(IncidentModel).where(IncidentModel.id.in_(inc_ids)))
        for inc in inc_res.scalars().all():
            inc_map[inc.id] = {
                "incident_number": inc.incident_number,
                "title": inc.title,
                "severity": inc.severity,
            }

    return [
        {
            "id": str(a.id),
            "command_id": str(a.command_id),
            "action": a.action,
            "status": a.status,
            "parameters": a.parameters,
            "sequence": a.sequence,
            "agent_id": str(a.agent_id),
            "agent": agent_map.get(a.agent_id, {"hostname": "Unknown", "primary_ip": "N/A", "status": "UNKNOWN"}),
            "incident_id": str(a.incident_id),
            "incident": inc_map.get(a.incident_id, {"incident_number": 0, "title": "Linked Incident", "severity": "MEDIUM"}),
            "playbook_run_id": str(a.playbook_run_id) if a.playbook_run_id else None,
            "approved_by": a.approved_by,
            "approved_at": a.approved_at.isoformat() if a.approved_at else None,
            "approval_reason": a.approval_reason,
            "execution_receipt": a.execution_receipt,
            "verification_receipt": a.verification_result,
            "issued_at": a.issued_at.isoformat() if a.issued_at else None,
            "expires_at": a.expires_at.isoformat() if a.expires_at else None,
        }
        for a in actions
    ]


@router.get(
    "/runs",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List recent playbook execution runs",
)
async def list_playbook_runs(
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """List recent SOAR workflow execution history."""
    query = (
        select(PlaybookRunModel)
        .order_by(PlaybookRunModel.start_time.desc())
        .offset(offset)
        .limit(limit)
    )
    res = await session.execute(query)
    runs = res.scalars().all()

    pb_ids = {r.playbook_id for r in runs}
    pb_map: Dict[UUID, str] = {}
    if pb_ids:
        pb_res = await session.execute(select(PlaybookModel).where(PlaybookModel.id.in_(pb_ids)))
        for pb in pb_res.scalars().all():
            pb_map[pb.id] = pb.name

    return [
        {
            "run_id": str(r.id),
            "playbook_id": str(r.playbook_id),
            "playbook_name": pb_map.get(r.playbook_id, "Response Workflow"),
            "incident_id": str(r.incident_id),
            "status": r.status,
            "dry_run": r.dry_run,
            "executed_by": r.executed_by,
            "start_time": r.start_time.isoformat() if r.start_time else None,
            "end_time": r.end_time.isoformat() if r.end_time else None,
            "output_summary": r.output_summary or {},
        }
        for r in runs
    ]


def _format_plan_response(plan: ResponsePlanModel) -> ResponsePlanResponse:
    """Map ResponsePlanModel to validated ResponsePlanResponse contract."""
    action_commands = []
    state = inspect(plan)
    if "actions_rel" in state.dict and plan.actions_rel:
        for cmd in plan.actions_rel:
            action_commands.append({
                "id": str(cmd.id),
                "command_id": str(cmd.command_id),
                "action": cmd.action,
                "status": cmd.status,
                "agent_id": str(cmd.agent_id),
                "sequence": cmd.sequence,
                "issued_at": cmd.issued_at.isoformat() if cmd.issued_at else None,
                "execution_receipt": cmd.execution_receipt,
            })

    return ResponsePlanResponse(
        id=plan.id,
        plan_number=plan.plan_number,
        title=plan.title,
        description=plan.description,
        incident_id=plan.incident_id,
        status=ResponsePlanStatusEnum(plan.status),
        risk_level=ActionRiskClassificationEnum(plan.risk_level),
        requires_approval=plan.requires_approval,
        actions=plan.actions or [],
        approval_hash=plan.approval_hash,
        dry_run=plan.dry_run,
        is_simulation=plan.is_simulation,
        simulation_run_id=plan.simulation_run_id,
        created_by=plan.created_by,
        approved_by=plan.approved_by,
        approved_at=plan.approved_at,
        approval_reason=plan.approval_reason,
        rejected_by=plan.rejected_by,
        rejection_reason=plan.rejection_reason,
        cancelled_by=plan.cancelled_by,
        cancellation_reason=plan.cancellation_reason,
        idempotency_key=plan.idempotency_key,
        execution_summary=plan.execution_summary,
        action_commands=action_commands,
        created_at=plan.created_at,
        updated_at=plan.updated_at,
    )


@router.get(
    "/actions/registry",
    response_model=List[ActionRegistryEntryResponse],
    status_code=status.HTTP_200_OK,
    summary="List allowlisted response action registry definitions",
)
async def get_action_registry(
    _admin: str = Depends(verify_admin_key),
) -> List[ActionRegistryEntryResponse]:
    """Retrieve operational metadata and safety policies for allowlisted response actions."""
    return ResponseActionRegistry.list_entries()


@router.post(
    "/plans",
    response_model=ResponsePlanResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a governed incident response plan",
)
async def create_response_plan(
    payload: ResponsePlanCreateRequest,
    admin_id: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ResponsePlanResponse:
    """Create an approval-gated response plan with explicit risk classification."""
    try:
        plan = await ResponsePlanService.create_plan(
            session=session,
            payload=payload,
            created_by=admin_id,
        )
        return _format_plan_response(plan)
    except ValueError as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(val_err),
        )


@router.get(
    "/plans",
    response_model=List[ResponsePlanResponse],
    status_code=status.HTTP_200_OK,
    summary="List response plans with optional filtering",
)
async def list_response_plans(
    incident_id: Optional[UUID] = Query(default=None, description="Filter by incident ID"),
    status_filter: Optional[str] = Query(default=None, description="Filter by status enum"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> List[ResponsePlanResponse]:
    """Retrieve governed response plans ordered by creation time."""
    plans = await ResponsePlanService.list_plans(
        session=session,
        incident_id=incident_id,
        status_filter=status_filter,
        limit=limit,
        offset=offset,
    )
    return [_format_plan_response(p) for p in plans]


@router.get(
    "/plans/{plan_id}",
    response_model=ResponsePlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Retrieve response plan details",
)
async def get_response_plan(
    plan_id: UUID,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ResponsePlanResponse:
    """Retrieve full details of a specific response plan including linked commands."""
    plan = await ResponsePlanService.get_plan(session=session, plan_id=plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Response plan {plan_id} not found",
        )
    return _format_plan_response(plan)


@router.post(
    "/plans/{plan_id}/submit",
    response_model=ResponsePlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit draft response plan for approval",
)
async def submit_response_plan(
    plan_id: UUID,
    admin_id: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ResponsePlanResponse:
    """Transition a DRAFT response plan to PENDING_APPROVAL and record approval hash."""
    try:
        plan = await ResponsePlanService.submit_plan(
            session=session,
            plan_id=plan_id,
            actor_id=admin_id,
        )
        return _format_plan_response(plan)
    except (ValueError, InvalidLifecycleTransitionError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )


@router.post(
    "/plans/{plan_id}/approve",
    response_model=ResponsePlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Approve pending response plan",
)
async def approve_response_plan(
    plan_id: UUID,
    payload: ResponsePlanApprovalRequest,
    admin_id: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> ResponsePlanResponse:
    """Authorize a response plan with mandatory justification and integrity verification."""
    try:
        plan = await ResponsePlanService.approve_plan(
            session=session,
            plan_id=plan_id,
            actor_id=admin_id,
            reason=payload.reason,
        )
        return _format_plan_response(plan)
    except (ValueError, InvalidLifecycleTransitionError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )


@router.post(
    "/plans/{plan_id}/reject",
    response_model=ResponsePlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Reject pending response plan",
)
async def reject_response_plan(
    plan_id: UUID,
    payload: ResponsePlanApprovalRequest,
    admin_id: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> ResponsePlanResponse:
    """Reject a response plan with justification."""
    try:
        plan = await ResponsePlanService.reject_plan(
            session=session,
            plan_id=plan_id,
            actor_id=admin_id,
            reason=payload.reason,
        )
        return _format_plan_response(plan)
    except (ValueError, InvalidLifecycleTransitionError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )


@router.post(
    "/plans/{plan_id}/cancel",
    response_model=ResponsePlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Cancel response plan",
)
async def cancel_response_plan(
    plan_id: UUID,
    payload: ResponsePlanCancelRequest,
    admin_id: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> ResponsePlanResponse:
    """Cancel a draft or pending response plan."""
    try:
        plan = await ResponsePlanService.cancel_plan(
            session=session,
            plan_id=plan_id,
            actor_id=admin_id,
            reason=payload.reason,
        )
        return _format_plan_response(plan)
    except (ValueError, InvalidLifecycleTransitionError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )


@router.post(
    "/plans/{plan_id}/execute",
    response_model=ResponsePlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute approved response plan",
)
async def execute_response_plan(
    plan_id: UUID,
    payload: ResponsePlanExecuteRequest,
    admin_id: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> ResponsePlanResponse:
    """Trigger dispatch of signed response actions for an approved response plan."""
    try:
        plan = await ResponsePlanService.execute_plan(
            session=session,
            plan_id=plan_id,
            actor_id=admin_id,
            dry_run=payload.dry_run,
            idempotency_key=payload.idempotency_key,
        )
        return _format_plan_response(plan)
    except (ValueError, InvalidLifecycleTransitionError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )


@router.post(
    "/plans/{plan_id}/reconcile",
    response_model=ResponsePlanResponse,
    status_code=status.HTTP_200_OK,
    summary="Reconcile an interrupted or stalled response plan",
)
async def reconcile_response_plan(
    plan_id: UUID,
    payload: ResponsePlanReconcileRequest,
    admin_id: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> ResponsePlanResponse:
    """Safely reconcile a response plan stalled in EXECUTING state (e.g. after a crash or timeout)."""
    try:
        plan = await ResponsePlanService.reconcile_plan(
            session=session,
            plan_id=plan_id,
            actor_id=admin_id,
            reason=payload.reason,
        )
        return _format_plan_response(plan)
    except (ValueError, InvalidLifecycleTransitionError) as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(err),
        )
