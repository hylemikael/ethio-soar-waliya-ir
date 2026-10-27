"""Administrative API endpoints for outbound integration destinations and delivery telemetry."""

import logging
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from sqlalchemy import desc, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.audit.ledger_service import AuditLedgerService
from waliya.config import settings
from waliya.contracts import (
    InboundEventIngestResponse,
    InboundSourceCreate,
    InboundSourceResponse,
    InboundSourceUpdate,
    NotificationDeliveryListResponse,
    NotificationDeliveryResponse,
    NotificationDestinationCreate,
    NotificationDestinationResponse,
    NotificationDestinationUpdate,
)
from waliya.core.auth import (
    verify_admin_key,
    verify_operator_or_admin,
    verify_viewer_or_above,
)
from waliya.db.models import (
    InboundEventDedupModel,
    InboundSourceModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
    utc_now,
)
from waliya.db.session import get_db_session
from waliya.integrations.delivery_service import NotificationDeliveryService
from waliya.integrations.inbound_service import InboundIngestionService
from waliya.integrations.network_security import (
    SSRFValidationError,
    validate_destination_url,
)
from waliya.integrations.payloads import NotificationEventType
from waliya.integrations.signing import encrypt_destination_secret

logger = logging.getLogger("waliya.api.integrations")

router = APIRouter(prefix="/integrations", tags=["Integrations"])
inbound_ingestion_service = InboundIngestionService()


def _to_source_response(model: InboundSourceModel) -> InboundSourceResponse:
    """Format inbound source model into response contract with secret presence boolean."""
    return InboundSourceResponse(
        id=model.id,
        source_id=model.source_id,
        name=model.name,
        provider_type=model.provider_type,
        is_enabled=model.is_enabled,
        auth_type=model.auth_type,
        has_shared_secret=bool(model.shared_secret_enc),
        permitted_event_types=model.permitted_event_types or [],
        total_events_received=model.total_events_received,
        total_events_accepted=model.total_events_accepted,
        total_events_rejected=model.total_events_rejected,
        total_events_deduplicated=model.total_events_deduplicated,
        last_received_at=model.last_received_at,
        last_error_message=model.last_error_message,
        created_by=model.created_by,
        created_at=model.created_at,
        updated_at=model.updated_at,
    )


def _to_destination_response(model: NotificationDestinationModel) -> NotificationDestinationResponse:
    """Format model into safe response contract with secret presence boolean."""
    return NotificationDestinationResponse(
        id=model.id,
        name=model.name,
        destination_url=model.destination_url,
        is_enabled=model.is_enabled,
        subscribed_events=model.subscribed_events or [],
        has_signing_secret=bool(model.signing_secret_enc),
        created_by=model.created_by,
        created_at=model.created_at,
        updated_at=model.updated_at,
        last_delivery_at=model.last_delivery_at,
        last_delivery_status=model.last_delivery_status,
        last_delivery_error=model.last_delivery_error,
    )


def _to_delivery_response(
    model: NotificationDeliveryModel,
    destination_name: Optional[str] = None,
) -> NotificationDeliveryResponse:
    """Format delivery model into response contract."""
    dest_name = destination_name or (model.destination.name if model.destination else None)
    return NotificationDeliveryResponse(
        id=model.id,
        destination_id=model.destination_id,
        destination_name=dest_name,
        delivery_id=model.delivery_id,
        event_type=model.event_type,
        event_id=model.event_id,
        status=model.status,
        attempt_count=model.attempt_count,
        max_attempts=model.max_attempts,
        next_attempt_at=model.next_attempt_at,
        payload=model.payload,
        response_status_code=model.response_status_code,
        response_time_ms=model.response_time_ms,
        error_message=model.error_message,
        created_at=model.created_at,
        updated_at=model.updated_at,
        delivered_at=model.delivered_at,
    )


# ---------------------------------------------------------------------------
# Destination Management Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/destinations",
    response_model=List[NotificationDestinationResponse],
    status_code=status.HTTP_200_OK,
    summary="List all configured outbound notification destinations",
)
async def list_destinations(
    admin_actor: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> List[NotificationDestinationResponse]:
    """Retrieve all configured webhook destinations with secrets securely redacted."""
    query = select(NotificationDestinationModel).order_by(NotificationDestinationModel.created_at.asc())
    result = await session.execute(query)
    destinations = result.scalars().all()
    return [_to_destination_response(d) for d in destinations]


@router.post(
    "/destinations",
    response_model=NotificationDestinationResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an authorized outbound notification destination",
)
async def create_destination(
    payload: NotificationDestinationCreate,
    admin_actor: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> NotificationDestinationResponse:
    """Register and validate a new outbound notification destination.

    Enforces strict pre-configuration SSRF and network security validation.
    """
    allow_local = settings.ENV in ("test", "testing")
    try:
        validate_destination_url(payload.destination_url, allow_local_for_testing=allow_local)
    except (SSRFValidationError, ValueError) as val_err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid destination URL: {val_err}",
        )

    # Validate subscribed event types
    valid_event_types = {e.value for e in NotificationEventType}
    valid_event_types.add("*")
    for event_name in payload.subscribed_events:
        if event_name not in valid_event_types:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported event type '{event_name}'. Valid types: {sorted(list(valid_event_types))}",
            )

    # Encrypt signing secret if provided
    signing_secret_enc = None
    if payload.signing_secret:
        signing_secret_enc = encrypt_destination_secret(payload.signing_secret)

    destination = NotificationDestinationModel(
        id=uuid4(),
        name=payload.name.strip(),
        destination_url=payload.destination_url.strip(),
        is_enabled=payload.is_enabled,
        subscribed_events=payload.subscribed_events,
        signing_secret_enc=signing_secret_enc,
        created_by=admin_actor,
    )
    session.add(destination)

    # Record tamper-evident audit ledger record
    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_actor,
        actor_role="ADMIN",
        action="NOTIFICATION_DESTINATION_CREATED",
        target_entity=str(destination.id),
        payload={
            "destination_id": str(destination.id),
            "name": destination.name,
            "destination_url": destination.destination_url,
            "is_enabled": destination.is_enabled,
            "subscribed_events": destination.subscribed_events,
            "has_signing_secret": bool(signing_secret_enc),
        },
    )

    await session.commit()
    logger.info("Admin '%s' created notification destination '%s' (%s)", admin_actor, destination.name, destination.id)
    return _to_destination_response(destination)


@router.get(
    "/destinations/{destination_id}",
    response_model=NotificationDestinationResponse,
    status_code=status.HTTP_200_OK,
    summary="Get destination details by ID",
)
async def get_destination(
    destination_id: UUID,
    admin_actor: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> NotificationDestinationResponse:
    """Retrieve details of a single notification destination."""
    res = await session.execute(
        select(NotificationDestinationModel).where(NotificationDestinationModel.id == destination_id)
    )
    destination = res.scalars().first()
    if not destination:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Destination '{destination_id}' not found",
        )
    return _to_destination_response(destination)


@router.patch(
    "/destinations/{destination_id}",
    response_model=NotificationDestinationResponse,
    status_code=status.HTTP_200_OK,
    summary="Update an existing outbound notification destination",
)
async def update_destination(
    destination_id: UUID,
    payload: NotificationDestinationUpdate,
    admin_actor: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> NotificationDestinationResponse:
    """Update settings for an existing notification destination."""
    res = await session.execute(
        select(NotificationDestinationModel).where(NotificationDestinationModel.id == destination_id)
    )
    destination = res.scalars().first()
    if not destination:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Destination '{destination_id}' not found",
        )

    allow_local = settings.ENV in ("test", "testing")
    if payload.destination_url is not None:
        try:
            validate_destination_url(payload.destination_url, allow_local_for_testing=allow_local)
        except (SSRFValidationError, ValueError) as val_err:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid destination URL: {val_err}",
            )
        destination.destination_url = payload.destination_url.strip()

    if payload.name is not None:
        destination.name = payload.name.strip()

    if payload.is_enabled is not None:
        destination.is_enabled = payload.is_enabled

    if payload.subscribed_events is not None:
        valid_event_types = {e.value for e in NotificationEventType}
        valid_event_types.add("*")
        for event_name in payload.subscribed_events:
            if event_name not in valid_event_types:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Unsupported event type '{event_name}'",
                )
        destination.subscribed_events = payload.subscribed_events

    if payload.signing_secret is not None:
        destination.signing_secret_enc = encrypt_destination_secret(payload.signing_secret)

    destination.updated_at = utc_now()

    # Record in audit ledger
    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_actor,
        actor_role="ADMIN",
        action="NOTIFICATION_DESTINATION_UPDATED",
        target_entity=str(destination.id),
        payload={
            "destination_id": str(destination.id),
            "name": destination.name,
            "destination_url": destination.destination_url,
            "is_enabled": destination.is_enabled,
            "subscribed_events": destination.subscribed_events,
            "has_signing_secret": bool(destination.signing_secret_enc),
        },
    )

    await session.commit()
    logger.info("Admin '%s' updated destination '%s' (%s)", admin_actor, destination.name, destination.id)
    return _to_destination_response(destination)


@router.delete(
    "/destinations/{destination_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete an outbound notification destination",
)
async def delete_destination(
    destination_id: UUID,
    admin_actor: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Remove a configured notification destination and cascade delete its deliveries."""
    res = await session.execute(
        select(NotificationDestinationModel).where(NotificationDestinationModel.id == destination_id)
    )
    destination = res.scalars().first()
    if not destination:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Destination '{destination_id}' not found",
        )

    dest_name = destination.name
    await session.delete(destination)

    # Record in audit ledger
    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_actor,
        actor_role="ADMIN",
        action="NOTIFICATION_DESTINATION_DELETED",
        target_entity=str(destination_id),
        payload={
            "destination_id": str(destination_id),
            "name": dest_name,
        },
    )

    await session.commit()
    logger.info("Admin '%s' deleted notification destination '%s' (%s)", admin_actor, dest_name, destination_id)
    return {"status": "DELETED", "destination_id": str(destination_id)}


@router.post(
    "/destinations/{destination_id}/test",
    response_model=NotificationDeliveryResponse,
    status_code=status.HTTP_200_OK,
    summary="Dispatch an administrative test notification to verify connectivity",
)
async def test_destination(
    destination_id: UUID,
    admin_actor: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> NotificationDeliveryResponse:
    """Dispatch an immediate, isolated test notification to the configured destination."""
    res = await session.execute(
        select(NotificationDestinationModel).where(NotificationDestinationModel.id == destination_id)
    )
    destination = res.scalars().first()
    if not destination:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Destination '{destination_id}' not found",
        )

    allow_local = settings.ENV in ("test", "testing")
    delivery = await NotificationDeliveryService.dispatch_test_notification(
        session=session,
        destination_id=destination_id,
        allow_local_for_testing=allow_local,
    )

    return _to_delivery_response(delivery, destination_name=destination.name)


# ---------------------------------------------------------------------------
# Delivery History and Retries
# ---------------------------------------------------------------------------


@router.get(
    "/deliveries",
    response_model=NotificationDeliveryListResponse,
    status_code=status.HTTP_200_OK,
    summary="List outbound notification delivery history",
)
async def list_deliveries(
    destination_id: Optional[UUID] = Query(None, description="Filter by destination ID"),
    delivery_status: Optional[str] = Query(None, alias="status", description="Filter by delivery status"),
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(50, ge=1, le=200, description="Page limit"),
    offset: int = Query(0, ge=0, description="Page offset"),
    admin_actor: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> NotificationDeliveryListResponse:
    """Retrieve paginated delivery history and audit outcomes."""
    base_query = select(NotificationDeliveryModel)
    count_query = select(func.count(NotificationDeliveryModel.id))

    if destination_id is not None:
        base_query = base_query.where(NotificationDeliveryModel.destination_id == destination_id)
        count_query = count_query.where(NotificationDeliveryModel.destination_id == destination_id)

    if delivery_status is not None:
        base_query = base_query.where(NotificationDeliveryModel.status == delivery_status.upper())
        count_query = count_query.where(NotificationDeliveryModel.status == delivery_status.upper())

    if event_type is not None:
        base_query = base_query.where(NotificationDeliveryModel.event_type == event_type)
        count_query = count_query.where(NotificationDeliveryModel.event_type == event_type)

    total_res = await session.execute(count_query)
    total = total_res.scalar() or 0

    records_query = (
        base_query
        .options(selectinload(NotificationDeliveryModel.destination))
        .order_by(desc(NotificationDeliveryModel.created_at))
        .offset(offset)
        .limit(limit)
    )
    result = await session.execute(records_query)
    records = result.scalars().all()

    return NotificationDeliveryListResponse(
        total=total,
        deliveries=[_to_delivery_response(r) for r in records],
    )


@router.post(
    "/deliveries/{delivery_id}/retry",
    response_model=NotificationDeliveryResponse,
    status_code=status.HTTP_200_OK,
    summary="Manually retry an eligible failed delivery",
)
async def retry_delivery(
    delivery_id: UUID,
    admin_actor: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> NotificationDeliveryResponse:
    """Manually trigger retry for a failed or retry-scheduled notification delivery."""
    query = (
        select(NotificationDeliveryModel)
        .options(selectinload(NotificationDeliveryModel.destination))
        .where(NotificationDeliveryModel.id == delivery_id)
    )
    res = await session.execute(query)
    delivery = res.scalars().first()
    if not delivery:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Delivery record '{delivery_id}' not found",
        )

    if delivery.status == "DELIVERED":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Delivery has already succeeded; retry prohibited to prevent duplicates",
        )

    allow_local = settings.ENV in ("test", "testing")
    # Reset status and dispatch immediately
    delivery.status = "PENDING"
    await NotificationDeliveryService.dispatch_delivery(
        session=session,
        delivery=delivery,
        allow_local_for_testing=allow_local,
    )
    await session.commit()

    return _to_delivery_response(delivery)


@router.post(
    "/deliveries/dispatch",
    status_code=status.HTTP_200_OK,
    summary="Trigger immediate batch dispatch of pending outbound notification deliveries",
)
async def dispatch_pending_deliveries(
    batch_size: int = Query(50, ge=1, le=200),
    admin_actor: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Process pending and retry-scheduled notification deliveries."""
    allow_local = settings.ENV in ("test", "testing")
    delivered_count = await NotificationDeliveryService.process_pending_deliveries(
        session=session,
        batch_size=batch_size,
        allow_local_for_testing=allow_local,
    )
    return {
        "status": "SUCCESS",
        "delivered_count": delivered_count,
    }


# ---------------------------------------------------------------------------
# Inbound Security Event Source Management Endpoints (Admin Protected)
# ---------------------------------------------------------------------------


@router.get(
    "/sources",
    response_model=List[InboundSourceResponse],
    status_code=status.HTTP_200_OK,
    summary="List all configured inbound security event sources",
)
async def list_inbound_sources(
    admin_actor: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> List[InboundSourceResponse]:
    """Retrieve all registered inbound event sources with secrets redacted."""
    query = select(InboundSourceModel).order_by(InboundSourceModel.created_at.desc())
    res = await session.execute(query)
    sources = res.scalars().all()
    return [_to_source_response(s) for s in sources]


@router.post(
    "/sources",
    response_model=InboundSourceResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new external inbound security event source",
)
async def create_inbound_source(
    payload: InboundSourceCreate,
    admin_actor: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> InboundSourceResponse:
    """Register an authorized external security source with encrypted shared secret."""
    slug = payload.source_id.strip().lower()

    # Check uniqueness
    existing_query = select(InboundSourceModel).where(InboundSourceModel.source_id == slug)
    existing_res = await session.execute(existing_query)
    if existing_res.scalars().first() is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Inbound source with identifier '{slug}' already exists",
        )

    provider_clean = payload.provider_type.strip().upper()
    if provider_clean not in ("GENERIC", "EDR", "SIEM"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider_type '{provider_clean}'. Supported: GENERIC, EDR, SIEM",
        )

    secret_enc = encrypt_destination_secret(payload.shared_secret)

    source = InboundSourceModel(
        id=uuid4(),
        source_id=slug,
        name=payload.name.strip(),
        provider_type=provider_clean,
        is_enabled=payload.is_enabled,
        auth_type=payload.auth_type.strip().upper(),
        shared_secret_enc=secret_enc,
        permitted_event_types=payload.permitted_event_types or [],
        created_by=admin_actor,
    )
    session.add(source)

    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_actor,
        actor_role="ADMIN",
        action="INBOUND_SOURCE_CREATED",
        target_entity=f"source:{source.source_id}",
        payload={
            "source_id": source.source_id,
            "name": source.name,
            "provider_type": source.provider_type,
            "is_enabled": source.is_enabled,
            "permitted_event_types": source.permitted_event_types,
        },
    )
    await session.commit()
    await session.refresh(source)

    return _to_source_response(source)


@router.get(
    "/sources/{source_identifier}",
    response_model=InboundSourceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get inbound source configuration by slug or UUID",
)
async def get_inbound_source(
    source_identifier: str,
    admin_actor: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> InboundSourceResponse:
    """Get single source configuration details."""
    source = await _resolve_source(session, source_identifier)
    return _to_source_response(source)


@router.patch(
    "/sources/{source_identifier}",
    response_model=InboundSourceResponse,
    status_code=status.HTTP_200_OK,
    summary="Update inbound source configuration or toggle enabled state",
)
async def update_inbound_source(
    source_identifier: str,
    payload: InboundSourceUpdate,
    admin_actor: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> InboundSourceResponse:
    """Update settings for an existing inbound event source."""
    source = await _resolve_source(session, source_identifier)

    changes: Dict[str, Any] = {}
    if payload.name is not None:
        source.name = payload.name.strip()
        changes["name"] = source.name
    if payload.provider_type is not None:
        p_type = payload.provider_type.strip().upper()
        if p_type not in ("GENERIC", "EDR", "SIEM"):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Unsupported provider_type '{p_type}'. Supported: GENERIC, EDR, SIEM",
            )
        source.provider_type = p_type
        changes["provider_type"] = source.provider_type
    if payload.is_enabled is not None:
        source.is_enabled = payload.is_enabled
        changes["is_enabled"] = source.is_enabled
    if payload.auth_type is not None:
        source.auth_type = payload.auth_type.strip().upper()
        changes["auth_type"] = source.auth_type
    if payload.permitted_event_types is not None:
        source.permitted_event_types = payload.permitted_event_types
        changes["permitted_event_types"] = source.permitted_event_types
    if payload.shared_secret is not None:
        source.shared_secret_enc = encrypt_destination_secret(payload.shared_secret)
        changes["shared_secret_updated"] = True

    source.updated_at = utc_now()
    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_actor,
        actor_role="ADMIN",
        action="INBOUND_SOURCE_UPDATED",
        target_entity=f"source:{source.source_id}",
        payload=changes,
    )
    await session.commit()
    await session.refresh(source)

    return _to_source_response(source)


@router.delete(
    "/sources/{source_identifier}",
    status_code=status.HTTP_200_OK,
    summary="Delete an inbound security event source",
)
async def delete_inbound_source(
    source_identifier: str,
    admin_actor: str = Depends(verify_admin_key),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Delete an inbound event source and cascade delete deduplication records."""
    source = await _resolve_source(session, source_identifier)
    source_id_str = source.source_id
    await session.delete(source)
    await AuditLedgerService.record_action(
        session=session,
        actor_id=admin_actor,
        actor_role="ADMIN",
        action="INBOUND_SOURCE_DELETED",
        target_entity=f"source:{source_id_str}",
        payload={"source_id": source_id_str},
    )
    await session.commit()

    return {"status": "DELETED", "source_id": source_id_str}


async def _resolve_source(session: AsyncSession, identifier: str) -> InboundSourceModel:
    """Resolve InboundSourceModel by UUID or source_id slug."""
    try:
        source_uuid = UUID(identifier)
        query = select(InboundSourceModel).where(
            or_(InboundSourceModel.id == source_uuid, InboundSourceModel.source_id == identifier)
        )
    except ValueError:
        query = select(InboundSourceModel).where(InboundSourceModel.source_id == identifier)

    res = await session.execute(query)
    source = res.scalars().first()
    if not source:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Inbound source '{identifier}' not found",
        )
    return source


# ---------------------------------------------------------------------------
# Controlled Inbound Event Ingestion Endpoint
# ---------------------------------------------------------------------------


@router.post(
    "/inbound/{source_slug}/events",
    response_model=InboundEventIngestResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Ingest authenticated external security event",
)
async def ingest_inbound_event(
    source_slug: str,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> InboundEventIngestResponse:
    """Securely receive, authenticate, validate, deduplicate, and normalize an external security event.

    Requires:
    - X-Waliya-Timestamp: ISO 8601 UTC or Unix timestamp (freshness checked: max 300s drift)
    - X-Waliya-Signature: HMAC-SHA256 signature calculated over raw request body
    - X-Waliya-Source-Id: Must match source_slug in path if provided
    """
    raw_body = await request.body()
    headers_dict = dict(request.headers)

    response = await inbound_ingestion_service.ingest_external_event(
        source_slug=source_slug,
        raw_body=raw_body,
        headers=headers_dict,
        session=session,
    )
    return response
