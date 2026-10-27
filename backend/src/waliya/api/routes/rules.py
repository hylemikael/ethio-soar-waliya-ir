"""Detection rule management and dry-run evaluation API endpoints."""

from datetime import datetime, timezone
import logging
import math
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.config import settings

from waliya.contracts import DetectionRuleSchema, RuleCondition, RuleEvaluationResult, SecurityEventEnvelope
from waliya.core.auth import verify_admin_key, verify_viewer_or_above
from waliya.db.models import FindingModel, RuleModel
from waliya.db.session import get_db_session
from waliya.detection.rule_engine import ALLOWED_OPERATORS, RuleEngine

logger = logging.getLogger("waliya.api.routes.rules")

router = APIRouter(prefix="/rules", tags=["detection-rules"])


class RuleTestRequest(BaseModel):
    """Payload for dry-run testing a detection rule against a sample event."""
    rule: DetectionRuleSchema
    event: SecurityEventEnvelope


@router.get(
    "",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List all detection rules",
)
async def list_rules(
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """List all registered security detection rules with their versions and activation status."""
    query = select(RuleModel).order_by(RuleModel.created_at.desc())
    res = await session.execute(query)
    rules = res.scalars().all()

    return [
        {
            "id": str(r.id),
            "rule_id": r.rule_id,
            "version": r.version,
            "name": r.name,
            "description": r.description,
            "severity": r.severity,
            "event_type": r.event_type,
            "conditions": r.conditions,
            "mitre_attack_ids": r.mitre_attack_ids,
            "dedup_window_seconds": r.dedup_window_seconds,
            "is_active": r.is_active,
            "created_at": r.created_at.isoformat() if r.created_at else None,
            "updated_at": r.updated_at.isoformat() if r.updated_at else None,
        }
        for r in rules
    ]


@router.post(
    "",
    response_model=Dict[str, Any],
    status_code=status.HTTP_201_CREATED,
    summary="Create or update a detection rule",
)
async def create_or_update_rule(
    schema: DetectionRuleSchema,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Register or update a versioned detection rule after validating condition operators."""
    # Validate that all condition operators are within the restricted allowlist
    for cond in schema.conditions:
        if cond.operator not in ALLOWED_OPERATORS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Disallowed rule operator '{cond.operator}'. Allowed operators: {sorted(list(ALLOWED_OPERATORS))}",
            )

    query = select(RuleModel).where(RuleModel.rule_id == schema.rule_id)
    res = await session.execute(query)
    existing_rule = res.scalars().first()

    conditions_dict = [c.model_dump() for c in schema.conditions]

    if existing_rule:
        existing_rule.version = schema.version
        existing_rule.name = schema.name
        existing_rule.description = schema.description
        existing_rule.severity = schema.severity.value
        existing_rule.event_type = schema.event_type.value
        existing_rule.conditions = conditions_dict
        existing_rule.mitre_attack_ids = schema.mitre_attack_ids
        existing_rule.dedup_window_seconds = schema.dedup_window_seconds
        existing_rule.is_active = schema.is_active
        rule_id = existing_rule.id
    else:
        new_rule = RuleModel(
            id=uuid4(),
            rule_id=schema.rule_id,
            version=schema.version,
            name=schema.name,
            description=schema.description,
            severity=schema.severity.value,
            event_type=schema.event_type.value,
            conditions=conditions_dict,
            mitre_attack_ids=schema.mitre_attack_ids,
            dedup_window_seconds=schema.dedup_window_seconds,
            is_active=schema.is_active,
        )
        session.add(new_rule)
        rule_id = new_rule.id

    await session.commit()
    logger.info("Rule '%s' (v%d) persisted successfully", schema.rule_id, schema.version)

    return {
        "id": str(rule_id),
        "rule_id": schema.rule_id,
        "version": schema.version,
        "status": "SAVED",
    }


@router.post(
    "/test",
    response_model=RuleEvaluationResult,
    status_code=status.HTTP_200_OK,
    summary="Dry-run evaluate a detection rule against a sample event",
)
async def test_rule(
    payload: RuleTestRequest,
    _admin: str = Depends(verify_admin_key),
) -> RuleEvaluationResult:
    """Test a detection rule against a sample event without persisting findings or updating state."""
    # Validate condition operators
    for cond in payload.rule.conditions:
        if cond.operator not in ALLOWED_OPERATORS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Disallowed rule operator '{cond.operator}'",
            )

    event_dict = {
        "event_id": str(payload.event.event_id),
        "event_type": payload.event.event_type.value,
        "severity": payload.event.severity.value,
        "timestamp": payload.event.timestamp.isoformat(),
        "source": payload.event.source,
        "agent_id": str(payload.event.agent_id) if payload.event.agent_id else None,
        "attributes": payload.event.payload,
        "payload": payload.event.payload,
    }

    result = await RuleEngine.evaluate_rule(payload.rule, event_dict)
    return result


@router.get(
    "/findings",
    response_model=List[Dict[str, Any]],
    status_code=status.HTTP_200_OK,
    summary="List generated security findings",
)
async def list_findings(
    limit: int = 50,
    rule_id: Optional[str] = None,
    event_id: Optional[UUID] = None,
    trace_id: Optional[str] = None,
    simulation_run_id: Optional[str] = None,
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> List[Dict[str, Any]]:
    """Query recent security findings generated by rules and behavioral analytics."""
    query = select(FindingModel)

    if event_id:
        query = query.where(FindingModel.event_id == event_id)
    if rule_id:
        try:
            r_uuid = UUID(rule_id)
            query = query.where(FindingModel.rule_id == r_uuid)
        except ValueError:
            query = query.join(RuleModel, FindingModel.rule_id == RuleModel.id).where(RuleModel.rule_id == rule_id)
    if simulation_run_id:
        query = query.where(
            (FindingModel.simulation_run_id == simulation_run_id)
            | (FindingModel.explanation["simulation_run_id"].as_string() == simulation_run_id)
        )
    if trace_id:
        query = query.where(FindingModel.explanation["trace_id"].as_string() == trace_id)

    query = query.order_by(FindingModel.timestamp.desc()).limit(min(limit, 200))

    res = await session.execute(query)
    findings = res.scalars().all()

    return [
        {
            "id": str(f.id),
            "rule_id": str(f.rule_id) if f.rule_id else None,
            "event_id": str(f.event_id),
            "agent_id": str(f.agent_id) if f.agent_id else None,
            "severity": f.severity,
            "confidence": f.confidence,
            "explanation": f.explanation,
            "dedup_key": f.dedup_key,
            "timestamp": f.timestamp.isoformat() if f.timestamp else None,
        }
        for f in findings
    ]


class RuleStatusUpdateRequest(BaseModel):
    """Payload to toggle activation of a detection rule."""
    is_active: bool


@router.patch(
    "/{rule_id}/status",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Enable or disable a detection rule",
)
async def update_rule_status(
    rule_id: str,
    payload: RuleStatusUpdateRequest,
    admin_id: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Toggle a detection rule's active state with cryptographic audit logging."""
    query = select(RuleModel).where(RuleModel.rule_id == rule_id)
    res = await session.execute(query)
    rule = res.scalars().first()

    if not rule:
        # Fallback check by UUID string
        try:
            uuid_obj = UUID(rule_id)
            query_uuid = select(RuleModel).where(RuleModel.id == uuid_obj)
            res_uuid = await session.execute(query_uuid)
            rule = res_uuid.scalars().first()
        except ValueError:
            pass

    if not rule:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Detection rule '{rule_id}' not found",
        )

    previous_state = rule.is_active
    rule.is_active = payload.is_active

    # Audit ledger entry
    action_type = "RULE_ACTIVATED" if payload.is_active else "RULE_DEACTIVATED"
    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_id,
        actor_role="ADMIN",
        action=action_type,
        target_entity=f"rule:{rule.rule_id}",
        payload={
            "rule_id": rule.rule_id,
            "version": rule.version,
            "previous_state": previous_state,
            "new_state": rule.is_active,
        },
    )

    await session.commit()
    logger.info("Rule %s active status changed: %s -> %s", rule.rule_id, previous_state, rule.is_active)

    return {
        "rule_id": rule.rule_id,
        "is_active": rule.is_active,
        "previous_state": previous_state,
        "status": "UPDATED",
    }


@router.get(
    "/analytics/baselines",
    response_model=Dict[str, Any],
    status_code=status.HTTP_200_OK,
    summary="Retrieve real streaming EWMA behavioral baselines and anomaly metrics",
)
async def get_behavioral_baselines(
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Inspect streaming EWMA statistical baselines from Redis and recent behavioral anomalies."""
    baselines: List[Dict[str, Any]] = []

    try:
        redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
        # Scan for EWMA keys: waliya:ewma:{metric_name}:{entity_id}
        keys = await redis_client.keys("waliya:ewma:*")
        for key in keys:
            parts = key.split(":", 3)
            if len(parts) >= 4:
                metric_name = parts[2]
                entity_id = parts[3]
            else:
                metric_name = "general"
                entity_id = key

            data = await redis_client.hgetall(key)
            if data:
                mean_val = float(data.get("mean", 0.0))
                var_val = float(data.get("variance", 0.25))
                std_dev = round(math.sqrt(max(0.0, var_val)), 2)
                sample_count = int(data.get("sample_count", 0))
                last_updated = data.get("last_updated")

                baselines.append({
                    "key": key,
                    "metric_name": metric_name,
                    "entity_id": entity_id,
                    "mean": round(mean_val, 2),
                    "variance": round(var_val, 4),
                    "std_dev": std_dev,
                    "sample_count": sample_count,
                    "last_updated": datetime.fromtimestamp(float(last_updated), timezone.utc).isoformat() if last_updated else None,
                })
        await redis_client.aclose()
    except Exception as exc:
        logger.warning("Could not read EWMA keys from Redis: %s", exc)

    # Fetch recent behavioral findings (with Z-scores)
    f_query = (
        select(FindingModel)
        .order_by(FindingModel.timestamp.desc())
        .limit(100)
    )
    f_res = await session.execute(f_query)
    all_findings = f_res.scalars().all()

    anomalies: List[Dict[str, Any]] = []
    for f in all_findings:
        expl = f.explanation or {}
        if isinstance(expl, dict) and "z_score" in expl:
            anomalies.append({
                "finding_id": str(f.id),
                "timestamp": f.timestamp.isoformat() if f.timestamp else None,
                "severity": f.severity,
                "confidence": f.confidence,
                "metric_name": expl.get("metric_name", "behavioral_rate"),
                "observed_value": expl.get("observed_value"),
                "baseline_mean": expl.get("baseline_mean"),
                "baseline_std_dev": expl.get("baseline_std_dev"),
                "z_score": expl.get("z_score"),
                "observed_entity": expl.get("observed_entity"),
                "decision_reason": expl.get("decision_reason"),
            })

    return {
        "total_active_baselines": len(baselines),
        "baselines": baselines,
        "recent_anomalies_count": len(anomalies),
        "anomalies": anomalies,
        "ewma_configuration": {
            "decay_factor_alpha": 0.1,
            "z_threshold": 3.0,
            "cold_start_minimum_samples": 5,
            "variance_floor": 0.25,
            "state_ttl_seconds": 86400,
        },
    }
