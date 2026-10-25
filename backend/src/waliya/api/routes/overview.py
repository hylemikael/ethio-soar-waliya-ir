"""System overview and operational dashboard telemetry aggregations."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, status
from redis.asyncio import Redis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.config import settings
from waliya.contracts import (
    AgentHealthSummary,
    EventDistributionSummary,
    FindingsSeveritySummary,
    IncidentActivityItem,
    IncidentsOverviewSummary,
    IncidentStatusEnum,
    PipelineHealthSummary,
    RecentActionItem,
    ResponseActionEnum,
    ResponseOutcomesSummary,
    ResponseStateEnum,
    RulesOverviewSummary,
    SeverityEnum,
    SystemOverviewResponse,
)
from waliya.core.auth import verify_admin_key
from waliya.db.models import (
    AgentModel,
    EventModel,
    EventOutboxModel,
    FindingModel,
    IncidentModel,
    ResponseActionModel,
    RuleModel,
)
from waliya.db.session import get_db_session

logger = logging.getLogger("waliya.api.routes.overview")

router = APIRouter(prefix="/overview", tags=["overview"])


@router.get(
    "",
    response_model=SystemOverviewResponse,
    status_code=status.HTTP_200_OK,
    summary="Get comprehensive platform security and operational overview",
)
async def get_system_overview(
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> SystemOverviewResponse:
    """Retrieve actual database-derived counts, incident posture, and ingestion health."""
    now_utc = datetime.now(timezone.utc)

    # 1. Agents Summary
    total_agents = (await session.execute(select(func.count(AgentModel.id)))).scalar() or 0
    online_agents = (await session.execute(select(func.count(AgentModel.id)).where(AgentModel.status == "ONLINE"))).scalar() or 0
    degraded_agents = (await session.execute(select(func.count(AgentModel.id)).where(AgentModel.status == "DEGRADED"))).scalar() or 0
    offline_agents = (await session.execute(select(func.count(AgentModel.id)).where(AgentModel.status == "OFFLINE"))).scalar() or 0
    revoked_agents = (await session.execute(select(func.count(AgentModel.id)).where(AgentModel.status == "REVOKED"))).scalar() or 0
    latest_hb = (await session.execute(select(func.max(AgentModel.last_heartbeat)))).scalar()

    agents_summary = AgentHealthSummary(
        total=total_agents,
        online=online_agents,
        degraded=degraded_agents,
        offline=offline_agents,
        revoked=revoked_agents,
        last_heartbeat=latest_hb,
    )

    # 2. Telemetry Events (Last 24 Hours)
    cutoff_24h = now_utc - timedelta(hours=24)
    events_query = (
        select(EventModel.event_type, func.count(EventModel.id))
        .where(EventModel.timestamp >= cutoff_24h)
        .group_by(EventModel.event_type)
    )
    ev_res = await session.execute(events_query)
    by_type = {str(row[0]): int(row[1]) for row in ev_res.all()}
    events_summary = EventDistributionSummary(
        total_last_24h=sum(by_type.values()),
        by_type=by_type,
    )

    # 3. Findings Severity Distribution
    findings_query = (
        select(FindingModel.severity, func.count(FindingModel.id))
        .group_by(FindingModel.severity)
    )
    f_res = await session.execute(findings_query)
    by_sev = {str(row[0]): int(row[1]) for row in f_res.all()}
    findings_summary = FindingsSeveritySummary(
        total=sum(by_sev.values()),
        by_severity=by_sev,
    )

    # 4. Incidents Summary
    inc_status_query = select(IncidentModel.status, func.count(IncidentModel.id)).group_by(IncidentModel.status)
    inc_res = await session.execute(inc_status_query)
    status_map = {str(row[0]): int(row[1]) for row in inc_res.all()}

    inc_sev_query = (
        select(IncidentModel.severity, func.count(IncidentModel.id))
        .where(IncidentModel.status.in_(["OPEN", "INVESTIGATING"]))
        .group_by(IncidentModel.severity)
    )
    inc_sev_res = await session.execute(inc_sev_query)
    inc_by_sev = {str(row[0]): int(row[1]) for row in inc_sev_res.all()}

    open_count = status_map.get("OPEN", 0)
    investigating_count = status_map.get("INVESTIGATING", 0)
    contained_count = status_map.get("CONTAINED", 0)
    resolved_count = status_map.get("RESOLVED", 0)
    closed_count = status_map.get("CLOSED", 0)
    total_incidents = sum(status_map.values())

    # Recent 5 Incidents Activity
    recent_inc_query = (
        select(
            IncidentModel,
            func.count(FindingModel.id).label("findings_count"),
        )
        .outerjoin(FindingModel, FindingModel.incident_id == IncidentModel.id)
        .group_by(IncidentModel.id)
        .order_by(IncidentModel.last_seen.desc().nullslast(), IncidentModel.created_at.desc())
        .limit(5)
    )
    recent_res = await session.execute(recent_inc_query)
    recent_activity = [
        IncidentActivityItem(
            incident_id=inc.id,
            incident_number=inc.incident_number,
            title=inc.title,
            severity=SeverityEnum(inc.severity),
            status=IncidentStatusEnum(inc.status),
            composite_risk_score=inc.composite_risk_score,
            findings_count=f_cnt,
            last_seen=inc.last_seen,
            is_simulation=getattr(inc, "is_simulation", False) or inc.title.startswith("[SIMULATION]"),
        )
        for inc, f_cnt in recent_res.all()
    ]

    incidents_summary = IncidentsOverviewSummary(
        total=total_incidents,
        open_count=open_count,
        investigating_count=investigating_count,
        contained_count=contained_count,
        resolved_count=resolved_count,
        closed_count=closed_count,
        by_severity=inc_by_sev,
        recent_activity=recent_activity,
    )

    # 5. Pipeline & Stream Health
    outbox_query = select(EventOutboxModel.status, func.count(EventOutboxModel.id)).group_by(EventOutboxModel.status)
    out_res = await session.execute(outbox_query)
    outbox_map = {str(row[0]): int(row[1]) for row in out_res.all()}

    stream_len: Optional[int] = None
    stream_status = "HEALTHY"
    try:
        redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
        stream_len = await redis.xlen("stream:telemetry:raw")
        await redis.aclose()
    except Exception as redis_err:
        logger.warning("Redis stream stats unavailable: %s", redis_err)
        stream_status = "UNAVAILABLE"

    pipeline_summary = PipelineHealthSummary(
        stream_name="stream:telemetry:raw",
        stream_length=stream_len,
        stream_status=stream_status,
        outbox_pending=outbox_map.get("PENDING", 0),
        outbox_failed=outbox_map.get("FAILED", 0),
        outbox_published=outbox_map.get("PUBLISHED", 0),
    )

    # 6. Detection Rules
    total_rules = (await session.execute(select(func.count(RuleModel.id)))).scalar() or 0
    active_rules = (await session.execute(select(func.count(RuleModel.id)).where(RuleModel.is_active == True))).scalar() or 0
    rules_summary = RulesOverviewSummary(
        total_rules=total_rules,
        active_rules=active_rules,
    )

    # 7. SOAR Response Outcomes
    resp_query = select(ResponseActionModel.status, func.count(ResponseActionModel.id)).group_by(ResponseActionModel.status)
    resp_res = await session.execute(resp_query)
    resp_map = {str(row[0]): int(row[1]) for row in resp_res.all()}

    recent_actions_query = (
        select(ResponseActionModel)
        .order_by(ResponseActionModel.issued_at.desc())
        .limit(5)
    )
    recent_act_res = await session.execute(recent_actions_query)
    recent_actions = [
        RecentActionItem(
            command_id=act.command_id,
            action=ResponseActionEnum(act.action),
            status=ResponseStateEnum(act.status),
            issued_at=act.issued_at,
            agent_id=act.agent_id,
        )
        for act in recent_act_res.scalars().all()
    ]

    responses_summary = ResponseOutcomesSummary(
        total_actions=sum(resp_map.values()),
        by_status=resp_map,
        recent_actions=recent_actions,
    )

    # 8. Security Posture Level
    active_crit = inc_by_sev.get("CRITICAL", 0)
    active_high = inc_by_sev.get("HIGH", 0)

    if active_crit > 0:
        posture = "CRITICAL"
        reason = f"{active_crit} active CRITICAL incident(s) require immediate containment"
    elif active_high > 0:
        posture = "ELEVATED"
        reason = f"{active_high} active HIGH severity incident(s) currently under investigation"
    elif open_count + investigating_count > 0:
        posture = "NORMAL"
        reason = f"{open_count + investigating_count} low/medium incident(s) being tracked"
    else:
        posture = "NORMAL"
        reason = "All systems operational; no active security threats"

    return SystemOverviewResponse(
        generated_at=now_utc,
        security_posture=posture,
        posture_reason=reason,
        agents=agents_summary,
        events_24h=events_summary,
        findings=findings_summary,
        incidents=incidents_summary,
        pipeline=pipeline_summary,
        rules=rules_summary,
        responses=responses_summary,
    )
