"""Asset inventory and administrative context management API endpoints."""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.audit.ledger_service import AuditLedgerService
from waliya.contracts import (
    AssetContextCreateOrUpdate,
    AssetContextResponse,
    AssetCriticalityEnum,
    AssetDetailResponse,
    AssetEnvironmentEnum,
    AssetListResponse,
)
from waliya.core.auth import verify_operator_or_admin, verify_viewer_or_above
from waliya.db.models import AgentModel, AssetContextModel
from waliya.db.session import get_db_session

logger = logging.getLogger("waliya.api.routes.assets")

router = APIRouter(prefix="/assets", tags=["assets"])


def _context_model_to_response(model: AssetContextModel) -> AssetContextResponse:
    return AssetContextResponse(
        id=model.id,
        agent_id=model.agent_id,
        criticality=AssetCriticalityEnum(model.criticality),
        environment=AssetEnvironmentEnum(model.environment) if model.environment else None,
        asset_group=model.asset_group,
        description=model.description,
        owner=model.owner,
        business_unit=model.business_unit,
        network_zone=model.network_zone,
        tags=model.tags or [],
        created_at=model.created_at,
        updated_at=model.updated_at,
        updated_by=model.updated_by,
    )


def _agent_and_context_to_response(agent: AgentModel) -> AssetDetailResponse:
    ctx_resp: Optional[AssetContextResponse] = None
    is_crit = False

    if agent.asset_context is not None:
        ctx_resp = _context_model_to_response(agent.asset_context)
        is_crit = (agent.asset_context.criticality == AssetCriticalityEnum.CRITICAL.value)

    return AssetDetailResponse(
        agent_id=agent.id,
        hostname=agent.hostname,
        primary_ip=agent.primary_ip,
        mac_address=agent.mac_address,
        os_family=agent.os_family,
        os_version=agent.os_version,
        agent_version=agent.agent_version,
        status=agent.status,
        last_heartbeat=agent.last_heartbeat,
        registered_at=agent.registered_at,
        context=ctx_resp,
        is_critical=is_crit,
    )


@router.get(
    "",
    response_model=AssetListResponse,
    status_code=status.HTTP_200_OK,
    summary="List asset inventory with operational telemetry and administrative context",
)
async def list_assets(
    criticality: Optional[str] = Query(None, description="Filter by criticality (LOW, MEDIUM, HIGH, CRITICAL, or UNASSIGNED)"),
    environment: Optional[str] = Query(None, description="Filter by environment (e.g. PRODUCTION, STAGING, DMZ)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by agent operational status (e.g. ONLINE, OFFLINE)"),
    search: Optional[str] = Query(None, description="Search term matching hostname or primary IP"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> AssetListResponse:
    """Retrieve paginated assets with operational state and business criticality context."""
    query = (
        select(AgentModel)
        .outerjoin(AssetContextModel, AgentModel.id == AssetContextModel.agent_id)
        .options(selectinload(AgentModel.asset_context))
    )

    if criticality:
        crit_upper = criticality.strip().upper()
        if crit_upper == "UNASSIGNED":
            query = query.where(AssetContextModel.id.is_(None))
        else:
            query = query.where(AssetContextModel.criticality == crit_upper)

    if environment:
        env_upper = environment.strip().upper()
        query = query.where(AssetContextModel.environment == env_upper)

    if status_filter:
        query = query.where(AgentModel.status == status_filter.strip().upper())

    if search:
        s_term = f"%{search.strip()}%"
        query = query.where(
            or_(
                AgentModel.hostname.ilike(s_term),
                AgentModel.primary_ip.ilike(s_term),
                AssetContextModel.owner.ilike(s_term),
                AssetContextModel.asset_group.ilike(s_term),
            )
        )

    # Count total
    count_query = select(func.count()).select_from(query.subquery())
    total_res = await session.execute(count_query)
    total = total_res.scalar() or 0

    query = query.order_by(AgentModel.hostname.asc()).limit(limit).offset(offset)
    res = await session.execute(query)
    agents = res.scalars().all()

    return AssetListResponse(
        items=[_agent_and_context_to_response(a) for a in agents],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{agent_id}",
    response_model=AssetDetailResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect individual asset and its administrative context",
)
async def get_asset(
    agent_id: UUID,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> AssetDetailResponse:
    """Retrieve asset operational details and associated administrative context."""
    query = (
        select(AgentModel)
        .where(AgentModel.id == agent_id)
        .options(selectinload(AgentModel.asset_context))
    )
    res = await session.execute(query)
    agent = res.scalars().first()

    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset with agent ID '{agent_id}' not found",
        )

    return _agent_and_context_to_response(agent)


@router.put(
    "/{agent_id}/context",
    response_model=AssetContextResponse,
    status_code=status.HTTP_200_OK,
    summary="Create or update asset criticality and administrative metadata",
)
async def update_asset_context(
    agent_id: UUID,
    payload: AssetContextCreateOrUpdate,
    _admin: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> AssetContextResponse:
    """Set business criticality and administrative metadata for an asset.

    Guarantees:
    - Rejects unauthorized or agent-originated requests.
    - Preserves audit trail in tamper-evident ledger.
    """
    # Verify agent exists
    agent_res = await session.execute(select(AgentModel).where(AgentModel.id == agent_id))
    agent = agent_res.scalars().first()
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Cannot assign context: Agent '{agent_id}' does not exist",
        )

    # Check if context already exists
    ctx_res = await session.execute(
        select(AssetContextModel).where(AssetContextModel.agent_id == agent_id)
    )
    ctx = ctx_res.scalars().first()

    now_utc = datetime.now(timezone.utc)
    is_new = False

    if ctx is None:
        is_new = True
        ctx = AssetContextModel(
            id=uuid4(),
            agent_id=agent_id,
            criticality=payload.criticality.value,
            environment=payload.environment.value if payload.environment else None,
            asset_group=payload.asset_group.strip() if payload.asset_group else None,
            description=payload.description.strip() if payload.description else None,
            owner=payload.owner.strip() if payload.owner else None,
            business_unit=payload.business_unit.strip() if payload.business_unit else None,
            network_zone=payload.network_zone.strip() if payload.network_zone else None,
            tags=payload.tags or [],
            created_at=now_utc,
            updated_at=now_utc,
            updated_by=_admin,
        )
        session.add(ctx)
    else:
        ctx.criticality = payload.criticality.value
        ctx.environment = payload.environment.value if payload.environment else None
        ctx.asset_group = payload.asset_group.strip() if payload.asset_group else None
        ctx.description = payload.description.strip() if payload.description else None
        ctx.owner = payload.owner.strip() if payload.owner else None
        ctx.business_unit = payload.business_unit.strip() if payload.business_unit else None
        ctx.network_zone = payload.network_zone.strip() if payload.network_zone else None
        ctx.tags = payload.tags or []
        ctx.updated_at = now_utc
        ctx.updated_by = _admin

    await session.commit()
    await session.refresh(ctx)

    # Record action in audit ledger
    await AuditLedgerService.record_action(
        session=session,
        actor_id=_admin,
        action="ASSET_CONTEXT_CREATED" if is_new else "ASSET_CONTEXT_UPDATED",
        target_entity=f"asset:{agent_id}",
        payload={
            "agent_id": str(agent_id),
            "hostname": agent.hostname,
            "criticality": ctx.criticality,
            "environment": ctx.environment,
            "owner": ctx.owner,
        },
    )
    await session.commit()

    return _context_model_to_response(ctx)
