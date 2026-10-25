"""Threat intelligence management and observable matching API endpoints."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.contracts import (
    FeedConfigurationResponse,
    FeedConfigurationUpdate,
    FeedSyncRequest,
    FeedSyncRunListResponse,
    FeedSyncRunResponse,
    IndicatorMatchItem,
    IndicatorMatchRequest,
    IndicatorMatchResponse,
    ThreatIndicatorBatchImportRequest,
    ThreatIndicatorBatchImportResponse,
    ThreatIndicatorCreate,
    ThreatIndicatorDecayRequest,
    ThreatIndicatorDecayResponse,
    ThreatIndicatorExtendExpiryRequest,
    ThreatIndicatorListResponse,
    ThreatIndicatorResponse,
    ThreatIndicatorUpdate,
)
from waliya.core.auth import verify_admin_key
from waliya.db.models import FeedConfigurationModel, FeedSyncRunModel, ThreatIndicatorModel
from waliya.db.session import get_db_session
from waliya.threat_intel.decay_service import ThreatIntelDecayService
from waliya.threat_intel.matcher import ThreatIntelMatcher
from waliya.threat_intel.normalizer import (
    IndicatorValidationError,
    detect_indicator_type,
    normalize_indicator,
)
from waliya.threat_intel.sync_service import ThreatIntelSyncService

logger = logging.getLogger("waliya.api.routes.threat_intel")

router = APIRouter(prefix="/threat-intel", tags=["threat-intel"])


def _model_to_response(model: ThreatIndicatorModel) -> ThreatIndicatorResponse:
    return ThreatIndicatorResponse(
        id=model.id,
        indicator_type=model.indicator_type,
        value=model.value,
        source=model.source,
        source_id=model.source_id,
        confidence=model.confidence,
        severity=model.severity,
        threat_category=model.threat_category,
        threat_actor=model.threat_actor,
        tags=model.tags or [],
        description=model.description,
        first_seen=model.first_seen,
        last_seen=model.last_seen,
        expires_at=model.expires_at,
        last_decayed_at=model.last_decayed_at,
        is_active=model.is_active,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


@router.get(
    "/indicators",
    response_model=ThreatIndicatorListResponse,
    status_code=status.HTTP_200_OK,
    summary="List and search threat intelligence indicators",
)
async def list_indicators(
    type: Optional[str] = Query(None, description="Filter by indicator type (e.g. IPV4, DOMAIN, SHA256)"),
    source: Optional[str] = Query(None, description="Filter by threat intelligence source/provider"),
    category: Optional[str] = Query(None, description="Filter by threat category (e.g. C2, BOTNET, RANSOMWARE)"),
    is_active: Optional[bool] = Query(None, description="Filter by active status"),
    search: Optional[str] = Query(None, description="Search term matching value, source, or description"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorListResponse:
    """Retrieve paginated threat intelligence indicators with optional filtering."""
    query = select(ThreatIndicatorModel)

    if type:
        clean_type = type.strip().upper()
        if clean_type == "IP":
            query = query.where(ThreatIndicatorModel.indicator_type.in_(["IPV4", "IPV6"]))
        else:
            query = query.where(ThreatIndicatorModel.indicator_type == clean_type)

    if source:
        query = query.where(ThreatIndicatorModel.source.ilike(f"%{source.strip()}%"))

    if category:
        query = query.where(ThreatIndicatorModel.threat_category.ilike(f"%{category.strip()}%"))

    if is_active is not None:
        query = query.where(ThreatIndicatorModel.is_active == is_active)

    if search:
        s_term = f"%{search.strip()}%"
        query = query.where(
            or_(
                ThreatIndicatorModel.value.ilike(s_term),
                ThreatIndicatorModel.source.ilike(s_term),
                ThreatIndicatorModel.description.ilike(s_term),
                ThreatIndicatorModel.threat_actor.ilike(s_term),
            )
        )

    # Count total matching
    count_query = select(func.count()).select_from(query.subquery())
    total_res = await session.execute(count_query)
    total = total_res.scalar() or 0

    # Paginated results ordered by creation time descending
    query = query.order_by(desc(ThreatIndicatorModel.created_at)).limit(limit).offset(offset)
    res = await session.execute(query)
    models = res.scalars().all()

    return ThreatIndicatorListResponse(
        items=[_model_to_response(m) for m in models],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.post(
    "/indicators",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new validated threat indicator",
)
async def create_indicator(
    payload: ThreatIndicatorCreate,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorResponse:
    """Normalize and store a new threat indicator record.

    Rejects malformed values and prevents duplicate indicators from the same provider.
    """
    try:
        norm_type, norm_val = normalize_indicator(payload.indicator_type.value, payload.value)
    except (IndicatorValidationError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
            detail=f"Indicator validation failed: {exc}",
        )

    # Check for existing indicator from the same provider
    existing_query = select(ThreatIndicatorModel).where(
        ThreatIndicatorModel.indicator_type == norm_type,
        ThreatIndicatorModel.value == norm_val,
        ThreatIndicatorModel.source == payload.source.strip(),
    )
    existing_res = await session.execute(existing_query)
    existing = existing_res.scalars().first()

    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Indicator '{norm_val}' ({norm_type}) from source '{payload.source}' already exists "
                f"with ID {existing.id}. Use PATCH to update."
            ),
        )

    now_utc = datetime.now(timezone.utc)
    new_model = ThreatIndicatorModel(
        id=uuid4(),
        indicator_type=norm_type,
        value=norm_val,
        source=payload.source.strip(),
        source_id=payload.source_id.strip() if payload.source_id else None,
        confidence=payload.confidence,
        severity=payload.severity.value,
        threat_category=payload.threat_category.strip().upper() if payload.threat_category else None,
        threat_actor=payload.threat_actor.strip() if payload.threat_actor else None,
        tags=payload.tags,
        description=payload.description.strip() if payload.description else None,
        first_seen=payload.first_seen,
        last_seen=payload.last_seen or now_utc,
        expires_at=payload.expires_at,
        is_active=payload.is_active,
        created_at=now_utc,
        updated_at=now_utc,
    )
    session.add(new_model)
    await session.commit()
    await session.refresh(new_model)
    ThreatIntelMatcher.clear_cache()

    # Record action in audit ledger
    await AuditLedgerService.record_action(
        session=session,
        actor_id=_admin,
        action="THREAT_INDICATOR_CREATED",
        target_entity=f"indicator:{new_model.id}",
        payload={
            "indicator_id": str(new_model.id),
            "indicator_type": norm_type,
            "value": norm_val,
            "source": new_model.source,
            "confidence": new_model.confidence,
        },
    )
    await session.commit()

    return _model_to_response(new_model)


@router.post(
    "/indicators/import",
    response_model=ThreatIndicatorBatchImportResponse,
    status_code=status.HTTP_200_OK,
    summary="Batch import validated threat indicators",
)
async def batch_import_indicators(
    payload: ThreatIndicatorBatchImportRequest,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorBatchImportResponse:
    """Import a bounded batch of threat intelligence indicators.

    Validates, normalizes, inserts new records, and updates existing records from the same provider.
    """
    total = len(payload.indicators)
    imported = 0
    updated = 0
    rejected = 0
    errors: List[Dict[str, Any]] = []

    now_utc = datetime.now(timezone.utc)

    for idx, item in enumerate(payload.indicators):
        try:
            norm_type, norm_val = normalize_indicator(item.indicator_type.value, item.value)
        except Exception as exc:
            rejected += 1
            errors.append({"index": idx, "value": item.value, "error": str(exc)})
            continue

        source_clean = item.source.strip()
        # Check existing
        existing_res = await session.execute(
            select(ThreatIndicatorModel).where(
                ThreatIndicatorModel.indicator_type == norm_type,
                ThreatIndicatorModel.value == norm_val,
                ThreatIndicatorModel.source == source_clean,
            )
        )
        existing = existing_res.scalars().first()

        if existing:
            # Update existing indicator attributes
            existing.confidence = item.confidence
            existing.severity = item.severity.value
            if item.threat_category:
                existing.threat_category = item.threat_category.strip().upper()
            if item.threat_actor:
                existing.threat_actor = item.threat_actor.strip()
            if item.tags:
                existing.tags = list(set((existing.tags or []) + item.tags))
            if item.description:
                existing.description = item.description.strip()
            if item.last_seen:
                existing.last_seen = item.last_seen
            if item.expires_at:
                existing.expires_at = item.expires_at
            existing.is_active = item.is_active
            existing.updated_at = now_utc
            updated += 1
        else:
            # Create new record
            new_ind = ThreatIndicatorModel(
                id=uuid4(),
                indicator_type=norm_type,
                value=norm_val,
                source=source_clean,
                source_id=item.source_id.strip() if item.source_id else None,
                confidence=item.confidence,
                severity=item.severity.value,
                threat_category=item.threat_category.strip().upper() if item.threat_category else None,
                threat_actor=item.threat_actor.strip() if item.threat_actor else None,
                tags=item.tags,
                description=item.description.strip() if item.description else None,
                first_seen=item.first_seen or now_utc,
                last_seen=item.last_seen or now_utc,
                expires_at=item.expires_at,
                is_active=item.is_active,
                created_at=now_utc,
                updated_at=now_utc,
            )
            session.add(new_ind)
            imported += 1

    await session.commit()

    # Record batch import action in audit ledger
    await AuditLedgerService.record_action(
        session=session,
        actor_id=_admin,
        action="THREAT_INDICATOR_BATCH_IMPORTED",
        target_entity="threat_indicators:batch",
        payload={
            "total_received": total,
            "imported_count": imported,
            "updated_count": updated,
            "rejected_count": rejected,
        },
    )
    await session.commit()

    return ThreatIndicatorBatchImportResponse(
        total_received=total,
        imported_count=imported,
        updated_count=updated,
        rejected_count=rejected,
        errors=errors,
    )


@router.get(
    "/indicators/{indicator_id}",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect a threat indicator by ID",
)
async def get_indicator(
    indicator_id: UUID,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorResponse:
    """Retrieve full details of an individual threat indicator record."""
    res = await session.execute(
        select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == indicator_id)
    )
    indicator = res.scalars().first()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator with ID '{indicator_id}' not found",
        )
    return _model_to_response(indicator)


@router.patch(
    "/indicators/{indicator_id}",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_200_OK,
    summary="Update threat indicator fields",
)
async def update_indicator(
    indicator_id: UUID,
    payload: ThreatIndicatorUpdate,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorResponse:
    """Update confidence, tags, category, or expiration of an existing indicator."""
    res = await session.execute(
        select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == indicator_id)
    )
    indicator = res.scalars().first()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator with ID '{indicator_id}' not found",
        )

    if payload.confidence is not None:
        indicator.confidence = payload.confidence
    if payload.severity is not None:
        indicator.severity = payload.severity.value
    if payload.threat_category is not None:
        indicator.threat_category = payload.threat_category.strip().upper()
    if payload.threat_actor is not None:
        indicator.threat_actor = payload.threat_actor.strip()
    if payload.tags is not None:
        indicator.tags = payload.tags
    if payload.description is not None:
        indicator.description = payload.description.strip()
    if payload.last_seen is not None:
        indicator.last_seen = payload.last_seen
    if payload.expires_at is not None:
        indicator.expires_at = payload.expires_at
    if payload.is_active is not None:
        indicator.is_active = payload.is_active

    indicator.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(indicator)
    ThreatIntelMatcher.clear_cache()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=_admin,
        action="THREAT_INDICATOR_UPDATED",
        target_entity=f"indicator:{indicator.id}",
        payload={
            "indicator_id": str(indicator.id),
            "confidence": indicator.confidence,
            "severity": indicator.severity,
            "is_active": indicator.is_active,
        },
    )
    await session.commit()

    return _model_to_response(indicator)


@router.post(
    "/indicators/{indicator_id}/deactivate",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_200_OK,
    summary="Deactivate a threat indicator without deleting history",
)
async def deactivate_indicator(
    indicator_id: UUID,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorResponse:
    """Deactivate an indicator, removing it from active matching while preserving historical audit context."""
    res = await session.execute(
        select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == indicator_id)
    )
    indicator = res.scalars().first()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator with ID '{indicator_id}' not found",
        )

    indicator.is_active = False
    indicator.updated_at = datetime.now(timezone.utc)
    await session.commit()
    await session.refresh(indicator)
    ThreatIntelMatcher.clear_cache()
    ThreatIntelMatcher.clear_cache()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=_admin,
        action="THREAT_INDICATOR_DEACTIVATED",
        target_entity=f"indicator:{indicator.id}",
        payload={"indicator_id": str(indicator.id), "value": indicator.value},
    )
    await session.commit()

    return _model_to_response(indicator)


@router.post(
    "/indicators/{indicator_id}/activate",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_200_OK,
    summary="Activate a threat indicator",
)
async def activate_indicator(
    indicator_id: UUID,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorResponse:
    """Explicitly activate a threat indicator. Rejects silent reactivation if the indicator is expired."""
    res = await session.execute(
        select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == indicator_id)
    )
    indicator = res.scalars().first()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator with ID '{indicator_id}' not found",
        )

    now_utc = datetime.now(timezone.utc)
    if indicator.expires_at and indicator.expires_at <= now_utc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot silently reactivate an expired indicator. Extend the indicator's expiration date first via /extend-expiry.",
        )

    indicator.is_active = True
    indicator.updated_at = now_utc
    await session.commit()
    await session.refresh(indicator)
    ThreatIntelMatcher.clear_cache()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=_admin,
        action="THREAT_INDICATOR_ACTIVATED",
        target_entity=f"indicator:{indicator.id}",
        payload={"indicator_id": str(indicator.id), "value": indicator.value},
        actor_role="ADMIN",
    )
    await session.commit()

    return _model_to_response(indicator)


@router.post(
    "/indicators/{indicator_id}/expire",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_200_OK,
    summary="Explicitly expire a threat indicator immediately",
)
async def expire_indicator(
    indicator_id: UUID,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorResponse:
    """Mark an indicator as immediately expired, preventing it from matching live telemetry."""
    res = await session.execute(
        select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == indicator_id)
    )
    indicator = res.scalars().first()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator with ID '{indicator_id}' not found",
        )

    now_utc = datetime.now(timezone.utc)
    indicator.expires_at = now_utc
    indicator.updated_at = now_utc
    await session.commit()
    await session.refresh(indicator)
    ThreatIntelMatcher.clear_cache()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=_admin,
        action="THREAT_INDICATOR_EXPIRED",
        target_entity=f"indicator:{indicator.id}",
        payload={"indicator_id": str(indicator.id), "value": indicator.value, "expired_at": now_utc.isoformat()},
        actor_role="ADMIN",
    )
    await session.commit()

    return _model_to_response(indicator)


@router.post(
    "/indicators/{indicator_id}/extend-expiry",
    response_model=ThreatIndicatorResponse,
    status_code=status.HTTP_200_OK,
    summary="Extend expiration deadline for a threat indicator",
)
async def extend_indicator_expiry(
    indicator_id: UUID,
    payload: ThreatIndicatorExtendExpiryRequest,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorResponse:
    """Safely extend an indicator's expiration deadline with explicit validation."""
    res = await session.execute(
        select(ThreatIndicatorModel).where(ThreatIndicatorModel.id == indicator_id)
    )
    indicator = res.scalars().first()
    if not indicator:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat indicator with ID '{indicator_id}' not found",
        )

    now_utc = datetime.now(timezone.utc)
    if payload.extension_days is not None:
        base_time = max(now_utc, indicator.expires_at or now_utc)
        new_expiry = base_time + timedelta(days=payload.extension_days)
    elif payload.new_expires_at is not None:
        if payload.new_expires_at <= now_utc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="New expiration timestamp must be strictly in the future.",
            )
        new_expiry = payload.new_expires_at
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide either extension_days or new_expires_at.",
        )

    indicator.expires_at = new_expiry
    indicator.updated_at = now_utc
    await session.commit()
    await session.refresh(indicator)
    ThreatIntelMatcher.clear_cache()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=_admin,
        action="THREAT_INDICATOR_EXPIRY_EXTENDED",
        target_entity=f"indicator:{indicator.id}",
        payload={
            "indicator_id": str(indicator.id),
            "new_expires_at": new_expiry.isoformat(),
            "extension_days": payload.extension_days,
        },
        actor_role="ADMIN",
    )
    await session.commit()

    return _model_to_response(indicator)


@router.post(
    "/indicators/decay",
    response_model=ThreatIndicatorDecayResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute deterministic confidence decay on stale indicators",
)
async def decay_indicators(
    payload: ThreatIndicatorDecayRequest,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> ThreatIndicatorDecayResponse:
    """Execute deterministic, idempotent confidence decay for stale threat intelligence indicators."""
    decay_result = await ThreatIntelDecayService.run_decay(
        session=session,
        actor_id=_admin,
        stale_days=payload.stale_days,
        decay_points=payload.decay_points,
        decay_interval_days=payload.decay_interval_days,
        min_confidence=payload.min_confidence,
        dry_run=payload.dry_run,
        indicator_type=payload.indicator_type.value if payload.indicator_type else None,
        source=payload.source,
    )
    return ThreatIndicatorDecayResponse(**decay_result)


@router.post(
    "/match",
    response_model=IndicatorMatchResponse,
    status_code=status.HTTP_200_OK,
    summary="Inspect indicator matches for a supplied observable",
)
async def match_observable(
    payload: IndicatorMatchRequest,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> IndicatorMatchResponse:
    """Safely match a given observable string against active, non-expired threat intelligence indicators.

    Performs zero network lookups.
    """
    clean_obs = payload.observable.strip()
    target_type = payload.indicator_type.value if payload.indicator_type else None

    matched_models = await ThreatIntelMatcher.match_observable(
        session=session,
        observable=clean_obs,
        indicator_type=target_type,
    )

    now_utc = datetime.now(timezone.utc)
    items: List[IndicatorMatchItem] = []
    for m in matched_models:
        items.append(
            IndicatorMatchItem(
                observable=clean_obs,
                indicator_id=m.id,
                indicator_type=m.indicator_type,
                value=m.value,
                source=m.source,
                source_id=m.source_id,
                confidence=m.confidence,
                severity=m.severity,
                threat_category=m.threat_category,
                threat_actor=m.threat_actor,
                tags=m.tags or [],
                description=m.description,
                first_seen=m.first_seen,
                last_seen=m.last_seen,
                matched_at=now_utc,
                investigative_note=(
                    f"Observable '{clean_obs}' matched known threat indicator ({m.indicator_type}) "
                    f"from {m.source} with confidence {m.confidence}%."
                ),
            )
        )

    return IndicatorMatchResponse(
        observable=clean_obs,
        matched=len(items) > 0,
        matches_count=len(items),
        matches=items,
    )


# ==============================================================================
# FEED MANAGEMENT & SYNCHRONIZATION ENDPOINTS
# ==============================================================================

def _feed_model_to_response(model: FeedConfigurationModel, indicator_count: int = 0) -> FeedConfigurationResponse:
    return FeedConfigurationResponse(
        id=model.id,
        feed_id=model.feed_id,
        provider=model.provider,
        name=model.name,
        description=model.description,
        is_enabled=model.is_enabled,
        refresh_interval_minutes=model.refresh_interval_minutes,
        last_sync_at=model.last_sync_at,
        last_successful_sync_at=model.last_successful_sync_at,
        last_status=model.last_status,
        last_error_summary=model.last_error_summary,
        config_options=model.config_options or {},
        indicators_count=indicator_count,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _run_model_to_response(model: FeedSyncRunModel) -> FeedSyncRunResponse:
    return FeedSyncRunResponse(
        id=model.id,
        feed_id=model.feed_id,
        started_at=model.started_at,
        finished_at=model.finished_at,
        status=model.status,
        is_dry_run=model.is_dry_run,
        fetched_count=model.fetched_count,
        normalized_count=model.normalized_count,
        inserted_count=model.inserted_count,
        updated_count=model.updated_count,
        skipped_count=model.skipped_count,
        rejected_count=model.rejected_count,
        deactivated_count=model.deactivated_count,
        error_summary=model.error_summary,
        diagnostics=model.diagnostics or {},
        triggered_by=model.triggered_by,
    )


@router.get(
    "/feeds",
    response_model=List[FeedConfigurationResponse],
    status_code=status.HTTP_200_OK,
    summary="List all configured threat intelligence feeds",
)
async def list_feeds(
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> List[FeedConfigurationResponse]:
    """Retrieve all external threat intelligence feed configurations with active indicator counts."""
    feed_pairs = await ThreatIntelSyncService.list_feeds(session)
    return [_feed_model_to_response(f, count) for f, count in feed_pairs]


@router.get(
    "/feeds/{feed_id}",
    response_model=FeedConfigurationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get configuration details for a specific threat feed",
)
async def get_feed(
    feed_id: str,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> FeedConfigurationResponse:
    """Retrieve details for a specific external threat feed."""
    clean_id = feed_id.strip().lower()
    feed = await ThreatIntelSyncService.get_or_create_feed_config(session, clean_id)
    if not feed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat intelligence feed '{clean_id}' not found",
        )

    count_q = (
        select(func.count(ThreatIndicatorModel.id))
        .where(
            ThreatIndicatorModel.source == feed.provider,
            ThreatIndicatorModel.is_active == True,
        )
    )
    count_res = await session.execute(count_q)
    ind_count = count_res.scalar() or 0

    return _feed_model_to_response(feed, ind_count)


@router.patch(
    "/feeds/{feed_id}",
    response_model=FeedConfigurationResponse,
    status_code=status.HTTP_200_OK,
    summary="Update threat intelligence feed configuration",
)
async def update_feed(
    feed_id: str,
    payload: FeedConfigurationUpdate,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> FeedConfigurationResponse:
    """Administratively update feed enable/disable toggle, refresh interval, or non-secret options."""
    clean_id = feed_id.strip().lower()
    feed = await ThreatIntelSyncService.get_or_create_feed_config(session, clean_id)
    if not feed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Threat intelligence feed '{clean_id}' not found",
        )

    changes: Dict[str, Any] = {}
    if payload.is_enabled is not None:
        feed.is_enabled = payload.is_enabled
        changes["is_enabled"] = payload.is_enabled

    if payload.refresh_interval_minutes is not None:
        feed.refresh_interval_minutes = payload.refresh_interval_minutes
        changes["refresh_interval_minutes"] = payload.refresh_interval_minutes

    if payload.config_options is not None:
        current_opts = dict(feed.config_options or {})
        current_opts.update(payload.config_options)
        feed.config_options = current_opts
        changes["config_options"] = current_opts

    if payload.description is not None:
        feed.description = payload.description.strip()
        changes["description"] = feed.description

    feed.updated_at = datetime.now(timezone.utc)
    await session.commit()

    # Record audit ledger entry
    try:
        await AuditLedgerService.record_action(
            session=session,
            actor_id="admin:api",
            action="UPDATE_FEED_CONFIG",
            target_entity=f"Feed:{feed.feed_id}",
            payload={"feed_id": feed.feed_id, "changes": changes},
            actor_role="ADMIN",
        )
        await session.commit()
    except Exception as exc:
        logger.error("Failed recording audit log for feed update: %s", exc)

    return _feed_model_to_response(feed)


@router.post(
    "/feeds/{feed_id}/sync",
    response_model=FeedSyncRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Trigger on-demand synchronization for a threat feed",
)
async def sync_feed_endpoint(
    feed_id: str,
    payload: FeedSyncRequest = FeedSyncRequest(),
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> FeedSyncRunResponse:
    """Execute on-demand threat intelligence synchronization with optional dry-run preview."""
    clean_id = feed_id.strip().lower()
    try:
        run = await ThreatIntelSyncService.sync_feed(
            session=session,
            feed_id=clean_id,
            is_dry_run=payload.dry_run,
            force=payload.force,
            triggered_by="admin:api",
        )
        return _run_model_to_response(run)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc))
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))


@router.get(
    "/feeds-runs",
    response_model=FeedSyncRunListResponse,
    status_code=status.HTTP_200_OK,
    summary="List historical feed synchronization runs",
)
async def list_sync_runs(
    feed_id: Optional[str] = Query(None, description="Filter by feed ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by run status"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> FeedSyncRunListResponse:
    """List historical synchronization executions with performance and count metrics."""
    query = select(FeedSyncRunModel)
    if feed_id:
        query = query.where(FeedSyncRunModel.feed_id == feed_id.strip().lower())
    if status_filter:
        query = query.where(FeedSyncRunModel.status == status_filter.strip().upper())

    count_q = select(func.count(FeedSyncRunModel.id))
    if feed_id:
        count_q = count_q.where(FeedSyncRunModel.feed_id == feed_id.strip().lower())
    if status_filter:
        count_q = count_q.where(FeedSyncRunModel.status == status_filter.strip().upper())

    total_res = await session.execute(count_q)
    total = total_res.scalar() or 0

    query = query.order_by(desc(FeedSyncRunModel.started_at)).limit(limit).offset(offset)
    res = await session.execute(query)
    runs = list(res.scalars().all())

    return FeedSyncRunListResponse(
        items=[_run_model_to_response(r) for r in runs],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/feeds-runs/{run_id}",
    response_model=FeedSyncRunResponse,
    status_code=status.HTTP_200_OK,
    summary="Get details of a specific feed synchronization run",
)
async def get_sync_run(
    run_id: UUID,
    _admin: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> FeedSyncRunResponse:
    """Retrieve diagnostics and metrics for a specific synchronization run."""
    query = select(FeedSyncRunModel).where(FeedSyncRunModel.id == run_id)
    res = await session.execute(query)
    run = res.scalar_one_or_none()
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Synchronization run '{run_id}' not found",
        )
    return _run_model_to_response(run)
