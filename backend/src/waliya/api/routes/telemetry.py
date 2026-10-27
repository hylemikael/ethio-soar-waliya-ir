"""Telemetry ingestion and pipeline API endpoints."""

import logging
from typing import Any, Dict
from fastapi import APIRouter, Depends, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import EventBatchRequest, EventBatchResponse
from waliya.core.auth import (
    get_authenticated_agent,
    verify_operator_or_admin,
    verify_viewer_or_above,
)
from waliya.db.models import AgentModel, EventOutboxModel
from waliya.db.session import get_db_session
from waliya.telemetry.ingestion import process_telemetry_batch
from waliya.telemetry.outbox_publisher import OutboxPublisher

logger = logging.getLogger("waliya.api.routes.telemetry")

router = APIRouter(tags=["telemetry"])
outbox_publisher = OutboxPublisher()


@router.post(
    "/telemetry/ingest",
    response_model=EventBatchResponse,
    status_code=status.HTTP_200_OK,
    summary="Ingest batch of endpoint security events",
)
async def ingest_telemetry(
    batch: EventBatchRequest,
    authenticated_agent: AgentModel = Depends(get_authenticated_agent),
    session: AsyncSession = Depends(get_db_session),
) -> EventBatchResponse:
    """Accept, normalize, and atomically persist a batch of telemetry events.

    1. Enforces agent authentication and identity binding.
    2. Atomically records events and outbox entries into PostgreSQL.
    3. Dispatches pending outbox entries to Redis Streams.
    4. Safe on retries (idempotent).
    """
    # 1. Ingest and persist events + outbox entries within PostgreSQL transaction
    response = await process_telemetry_batch(
        session=session,
        batch=batch,
        authenticated_agent=authenticated_agent,
    )

    # 2. Immediately attempt dispatching pending outbox events to Redis Streams
    try:
        await outbox_publisher.publish_pending_events(session=session)
    except Exception as exc:
        # Non-blocking: events and outbox entries are safely committed in PostgreSQL
        logger.warning("Post-ingest outbox dispatch encountered an error: %s", exc)

    return response


@router.get(
    "/telemetry/outbox/status",
    status_code=status.HTTP_200_OK,
    summary="Get current transactional outbox status metrics",
)
async def get_outbox_status(
    _admin: str = Depends(verify_viewer_or_above),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Return observable metrics on pending, published, and failed outbox records."""
    counts_query = select(
        EventOutboxModel.status,
        func.count(EventOutboxModel.id),
    ).group_by(EventOutboxModel.status)

    result = await session.execute(counts_query)
    status_counts = dict(result.all())

    return {
        "stream_name": "stream:telemetry:raw",
        "pending": status_counts.get("PENDING", 0),
        "published": status_counts.get("PUBLISHED", 0),
        "failed": status_counts.get("FAILED", 0),
        "total": sum(status_counts.values()),
    }


@router.post(
    "/telemetry/outbox/flush",
    status_code=status.HTTP_200_OK,
    summary="Trigger immediate flush of pending or failed outbox events",
)
async def flush_outbox(
    _admin: str = Depends(verify_operator_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Force an outbox publication iteration to recover pending or failed events."""
    published_count = await outbox_publisher.publish_pending_events(session=session)
    return {
        "status": "COMPLETED",
        "published_count": published_count,
    }
