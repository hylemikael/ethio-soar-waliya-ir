"""Outbound HTTPS agent task channel and command dispatch endpoints."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.config import settings
from waliya.contracts import (
    AgentHeartbeatResponse,
    CommandEnvelope,
    ExecutionReceiptRequest,
    ResponseActionEnum,
    ResponseStateEnum,
    TaskPollRequest,
    VerificationResultResponse,
    VerificationTelemetryRequest,
)
from waliya.core.auth import get_authenticated_agent, verify_admin_key
from waliya.core.crypto import compute_command_signature, decrypt_agent_secret
from waliya.db.models import AgentModel, ResponseActionModel
from waliya.db.session import get_db_session
from waliya.soar.verification import ClosedLoopVerificationEngine

logger = logging.getLogger("waliya.api.routes.agents")

router = APIRouter(prefix="/agents", tags=["agents"])
verification_engine = ClosedLoopVerificationEngine()


@router.get(
    "",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List registered endpoint agents",
)
async def list_agents(
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """List all registered Linux endpoint agents."""
    res = await session.execute(select(AgentModel).order_by(AgentModel.hostname.asc()))
    agents = res.scalars().all()
    return [
        {
            "id": str(a.id),
            "hostname": a.hostname,
            "primary_ip": a.primary_ip,
            "status": a.status,
            "os_family": a.os_family,
            "os_version": a.os_version,
            "agent_version": a.agent_version,
            "mac_address": a.mac_address,
            "last_heartbeat": a.last_heartbeat.isoformat() if a.last_heartbeat else None,
            "created_at": a.registered_at.isoformat() if a.registered_at else None,
        }
        for a in agents
    ]


@router.post(
    "/{agent_id}/heartbeat",
    response_model=AgentHeartbeatResponse,
    status_code=status.HTTP_200_OK,
    summary="Agent periodic health heartbeat",
)
async def agent_heartbeat(
    agent_id: UUID,
    agent: AgentModel = Depends(get_authenticated_agent),
    session: AsyncSession = Depends(get_db_session),
) -> AgentHeartbeatResponse:
    """Record agent heartbeat, update ONLINE status, and report pending command counts."""
    if agent.id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated agent token does not match agent ID in URL path",
        )

    now_utc = datetime.now(timezone.utc)
    agent.last_heartbeat = now_utc
    agent.status = "ONLINE"

    # Query pending queued tasks for this agent
    pending_query = select(func.count(ResponseActionModel.id)).where(
        ResponseActionModel.agent_id == agent.id,
        ResponseActionModel.status == ResponseStateEnum.QUEUED.value,
        ResponseActionModel.expires_at > now_utc,
    )
    res = await session.execute(pending_query)
    pending_count = res.scalar() or 0

    await session.commit()
    return AgentHeartbeatResponse(
        status="ACK",
        server_time=now_utc,
        pending_tasks=pending_count,
    )


@router.post(
    "/{agent_id}/tasks/poll",
    response_model=Optional[CommandEnvelope],
    status_code=status.HTTP_200_OK,
    summary="Poll for queued signed command envelopes",
)
async def poll_agent_tasks(
    agent_id: UUID,
    poll_req: TaskPollRequest,
    agent: AgentModel = Depends(get_authenticated_agent),
    session: AsyncSession = Depends(get_db_session),
) -> Optional[CommandEnvelope]:
    """Retrieve the next queued command envelope signed with agent HMAC secret.

    Guarantees:
    - Enforces monotonically increasing sequence order.
    - Rejects expired commands and transitions them to EXPIRED state.
    - Idempotently delivers commands.
    """
    if agent.id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated agent token does not match agent ID in URL path",
        )

    now_utc = datetime.now(timezone.utc)

    # Query next queued command in sequence order
    query = (
        select(ResponseActionModel)
        .where(
            ResponseActionModel.agent_id == agent.id,
            ResponseActionModel.status == ResponseStateEnum.QUEUED.value,
        )
        .order_by(ResponseActionModel.sequence.asc())
        .limit(1)
        .with_for_update()
    )
    res = await session.execute(query)
    action = res.scalars().first()

    if not action:
        return None

    # Check command expiry deadline
    if action.expires_at <= now_utc:
        logger.warning("Queued command %s expired before delivery deadline", action.command_id)
        action.status = ResponseStateEnum.EXPIRED.value
        await AuditLedgerService.record_action(
            session=session,
            actor_id="system:scheduler",
            actor_role="SYSTEM",
            action="COMMAND_EXPIRED",
            target_entity=f"command:{action.command_id}",
            payload={
                "command_id": str(action.command_id),
                "agent_id": str(agent.id),
                "expired_at": now_utc.isoformat(),
            },
            timestamp=now_utc,
        )
        await session.commit()
        return None

    # Filter by supported actions if specified by agent
    if poll_req.supported_actions and ResponseActionEnum(action.action) not in poll_req.supported_actions:
        logger.debug("Skipping command %s: action %s not in agent supported actions", action.command_id, action.action)
        return None

    # Mark status as RECEIVED upon poll delivery
    action.status = ResponseStateEnum.RECEIVED.value

    # Decrypt agent HMAC signing secret
    agent_secret = decrypt_agent_secret(agent.secret_key_enc, settings.SECRET_KEY)

    # Re-compute / ensure signature validity
    signature = compute_command_signature(
        command_id=action.command_id,
        agent_id=action.agent_id,
        action=action.action,
        parameters=action.parameters,
        sequence=action.sequence,
        nonce=action.nonce,
        issued_at=action.issued_at,
        expires_at=action.expires_at,
        secret_key=agent_secret,
    )
    action.signature = signature

    await session.commit()

    return CommandEnvelope(
        command_id=action.command_id,
        agent_id=action.agent_id,
        action=ResponseActionEnum(action.action),
        parameters=action.parameters,
        sequence=action.sequence,
        nonce=action.nonce,
        issued_at=action.issued_at,
        expires_at=action.expires_at,
        signature_version=1,
        signature=signature,
    )


@router.post(
    "/{agent_id}/receipts",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Submit execution receipt for dispatched command",
)
async def submit_execution_receipt(
    agent_id: UUID,
    receipt_req: ExecutionReceiptRequest,
    agent: AgentModel = Depends(get_authenticated_agent),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Record execution receipt and transition action into VERIFYING observation state."""
    if agent.id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated agent token does not match agent ID in URL path",
        )

    # Query action
    query = select(ResponseActionModel).where(
        ResponseActionModel.command_id == receipt_req.command_id,
        ResponseActionModel.agent_id == agent.id,
    )
    res = await session.execute(query)
    action = res.scalars().first()

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Command '{receipt_req.command_id}' not found for agent '{agent_id}'",
        )

    new_state = await verification_engine.record_execution_receipt(
        session=session,
        action_model=action,
        receipt=receipt_req.model_dump(mode="json"),
    )

    await session.commit()
    return {
        "command_id": str(action.command_id),
        "status": new_state.value,
        "message": f"Execution receipt recorded. Action status is now {new_state.value}.",
    }


@router.post(
    "/{agent_id}/verification",
    response_model=VerificationResultResponse,
    status_code=status.HTTP_200_OK,
    summary="Submit post-action verification telemetry",
)
async def submit_verification_telemetry(
    agent_id: UUID,
    telemetry_req: VerificationTelemetryRequest,
    agent: AgentModel = Depends(get_authenticated_agent),
    session: AsyncSession = Depends(get_db_session),
) -> VerificationResultResponse:
    """Evaluate observed OS telemetry and determine containment verification outcome."""
    if agent.id != agent_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated agent token does not match agent ID in URL path",
        )

    # Query action
    query = select(ResponseActionModel).where(
        ResponseActionModel.command_id == telemetry_req.command_id,
        ResponseActionModel.agent_id == agent.id,
    )
    res = await session.execute(query)
    action = res.scalars().first()

    if not action:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Command '{telemetry_req.command_id}' not found for agent '{agent_id}'",
        )

    determined_state, explanation = await verification_engine.verify_containment(
        session=session,
        action_model=action,
        observed_state=telemetry_req.observed_state,
        verified_at=telemetry_req.verified_at,
    )

    await session.commit()
    return VerificationResultResponse(
        command_id=action.command_id,
        status=determined_state,
        explanation=explanation,
    )
