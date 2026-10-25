"""Durable event ingestion and transactional outbox persistence service."""

import logging
from typing import List, Tuple
from uuid import UUID

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import EventBatchRequest, EventBatchResponse, SecurityEventEnvelope
from waliya.db.models import AgentModel, EventModel, EventOutboxModel
from waliya.telemetry.normalizer import normalize_event

logger = logging.getLogger("waliya.telemetry.ingestion")


async def process_telemetry_batch(
    session: AsyncSession,
    batch: EventBatchRequest,
    authenticated_agent: AgentModel,
) -> EventBatchResponse:
    """Validate, normalize, and atomically persist a batch of telemetry events into PostgreSQL and outbox.

    Idempotency:
    If an event ID has already been persisted, it is safely acknowledged without duplicating
    database rows or corrupting outbox state.

    Args:
        session: Active asynchronous database transaction session.
        batch: Validated EventBatchRequest envelope.
        authenticated_agent: AgentModel of the verified submitting client.

    Returns:
        EventBatchResponse confirmation.

    Raises:
        HTTPException: If agent IDs mismatch or validation fails.
    """
    # 1. Authorize: Verify submitting agent matches batch agent_id
    if batch.agent_id != authenticated_agent.id:
        logger.warning(
            "Agent ID mismatch rejected. Authenticated=%s, Claimed=%s",
            authenticated_agent.id,
            batch.agent_id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Agent identity mismatch: Authenticated agent '{authenticated_agent.id}' cannot submit events for '{batch.agent_id}'",
        )

    # 2. Extract event IDs to query for duplicates in one round-trip
    event_ids: List[UUID] = [e.event_id for e in batch.events]
    existing_query = select(EventModel.id).where(EventModel.id.in_(event_ids))
    existing_result = await session.execute(existing_query)
    existing_event_ids = set(existing_result.scalars().all())

    new_events_count = 0
    duplicate_count = 0

    # 3. Process each event in the batch
    for event in batch.events:
        # Enforce agent ID consistency at the event level
        if event.agent_id and event.agent_id != authenticated_agent.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Event {event.event_id} specifies mismatched agent_id '{event.agent_id}'",
            )

        if event.event_id in existing_event_ids:
            # Idempotent skip: event was already durably persisted in a prior attempt
            duplicate_count += 1
            continue

        # Normalize the event payload
        normalized_data = normalize_event(event, authenticated_agent.id)

        # Create the durable Event record
        db_event = EventModel(
            id=event.event_id,
            agent_id=authenticated_agent.id,
            event_type=event.event_type.value,
            severity=event.severity.value,
            timestamp=event.timestamp,
            source=event.source,
            raw_payload=event.payload,
            normalized_payload=normalized_data,
        )
        session.add(db_event)

        # Create corresponding Transactional Outbox record in the SAME transaction
        outbox_payload = {
            "event_id": str(event.event_id),
            "agent_id": str(authenticated_agent.id),
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "timestamp": event.timestamp.isoformat(),
            "source": event.source,
            "normalized": normalized_data,
        }
        db_outbox = EventOutboxModel(
            event_id=event.event_id,
            stream_name="stream:telemetry:raw",
            payload=outbox_payload,
            status="PENDING",
        )
        session.add(db_outbox)
        new_events_count += 1

    # 4. Commit transaction atomically: both events and outbox are persisted together
    if new_events_count > 0:
        await session.commit()
        logger.info(
            "Batch %s persisted: %d new events, %d duplicate events ignored",
            batch.batch_id,
            new_events_count,
            duplicate_count,
        )

    return EventBatchResponse(
        batch_id=batch.batch_id,
        processed_count=len(batch.events),
        status="QUEUED",
    )
