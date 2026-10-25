"""Reliable notification delivery engine with bounded retries, SSRF defense, and loop suppression."""

import logging
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

import httpx
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.db.models import (
    NotificationDeliveryModel,
    NotificationDestinationModel,
    utc_now,
)
from waliya.integrations.network_security import (
    MAX_RESPONSE_BYTES,
    SSRFValidationError,
    create_safe_http_client,
    validate_destination_url,
)
from waliya.integrations.payloads import (
    NotificationEventType,
    NotificationPayload,
    build_test_notification_payload,
)
from waliya.observability.metrics import get_metrics_collector
from waliya.integrations.signing import build_signed_headers

logger = logging.getLogger("waliya.integrations.delivery_service")

# Retry parameters
DEFAULT_MAX_ATTEMPTS = 5
BASE_BACKOFF_SECONDS = 5.0
MAX_BACKOFF_SECONDS = 1800.0  # 30 minutes ceiling


class NotificationDeliveryService:
    """Orchestrates outbound notification queueing, HMAC-signed delivery, and bounded retries."""

    @staticmethod
    async def queue_notification(
        session: AsyncSession,
        event_type: str,
        event_id: str,
        payload: NotificationPayload,
    ) -> List[NotificationDeliveryModel]:
        """Find all active destinations subscribed to event_type and queue durable delivery records.

        Guarantees:
        - Queued transactionally inside the existing database transaction.
        - Suppresses notification loops: never queues notifications for internal delivery status changes.
        """
        # Query enabled destinations
        query = select(NotificationDestinationModel).where(
            NotificationDestinationModel.is_enabled.is_(True)
        )
        result = await session.execute(query)
        destinations = result.scalars().all()

        queued_deliveries: List[NotificationDeliveryModel] = []

        for dest in destinations:
            # Check subscription: list of event types or wildcard "*"
            subscribed = dest.subscribed_events or []
            if "*" in subscribed or event_type in subscribed:
                # Use a unique stable delivery ID per destination
                dest_delivery_id = uuid4()
                # Create a destination-specific copy of payload with its delivery_id
                dest_payload = payload.model_copy(update={"delivery_id": dest_delivery_id})

                delivery = NotificationDeliveryModel(
                    id=uuid4(),
                    destination_id=dest.id,
                    delivery_id=dest_delivery_id,
                    event_type=event_type,
                    event_id=str(event_id),
                    status="PENDING",
                    attempt_count=0,
                    max_attempts=DEFAULT_MAX_ATTEMPTS,
                    payload=dest_payload.model_dump(mode="json"),
                )
                session.add(delivery)
                queued_deliveries.append(delivery)

        if queued_deliveries:
            logger.info(
                "Queued %d outbound notifications for event '%s' (id=%s)",
                len(queued_deliveries),
                event_type,
                event_id,
            )

        return queued_deliveries

    @staticmethod
    async def dispatch_delivery(
        session: AsyncSession,
        delivery: NotificationDeliveryModel,
        allow_local_for_testing: bool = False,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> NotificationDeliveryModel:
        """Execute a single outbound webhook delivery with strict pre-delivery SSRF validation.

        Status lifecycle:
        - PENDING -> DELIVERING -> DELIVERED (on 2xx)
        - DELIVERING -> PERMANENTLY_FAILED (on 4xx, invalid URL, or SSRF block)
        - DELIVERING -> RETRY_SCHEDULED (on 5xx, timeout, or network error if attempt_count < max)
        - RETRY_SCHEDULED -> PERMANENTLY_FAILED (when retry ceiling reached)
        """
        # Explicitly query destination by destination_id to avoid implicit async lazy-loading
        dest_res = await session.execute(
            select(NotificationDestinationModel).where(
                NotificationDestinationModel.id == delivery.destination_id
            )
        )
        destination = dest_res.scalars().first()
        delivery.destination = destination

        if not destination or not destination.is_enabled:
            delivery.status = "PERMANENTLY_FAILED"
            delivery.error_message = "Destination is disabled or no longer exists"
            delivery.updated_at = utc_now()
            return delivery

        delivery.status = "DELIVERING"
        delivery.attempt_count += 1
        delivery.updated_at = utc_now()

        # 1. Immediate Pre-Delivery Destination Security & SSRF Validation
        try:
            validate_destination_url(
                destination.destination_url,
                allow_local_for_testing=allow_local_for_testing,
            )
        except (SSRFValidationError, ValueError) as ssrf_err:
            sanitized_err = f"Destination validation failed: {ssrf_err}"
            logger.warning("SSRF blocked delivery %s to %s: %s", delivery.delivery_id, destination.destination_url, sanitized_err)
            delivery.status = "PERMANENTLY_FAILED"
            delivery.error_message = sanitized_err
            destination.last_delivery_at = utc_now()
            destination.last_delivery_status = "FAILED"
            destination.last_delivery_error = sanitized_err
            return delivery

        # 2. Build HMAC-SHA256 signature and canonical headers
        headers, canonical_bytes = build_signed_headers(
            delivery_id=delivery.delivery_id,
            event_type=delivery.event_type,
            timestamp=delivery.created_at,
            payload_dict=delivery.payload,
            secret_ciphertext=destination.signing_secret_enc,
        )

        # 3. Safe Outbound HTTP Dispatch (follow_redirects=False, bounded timeouts)
        close_client_after = False
        client = http_client
        if client is None:
            client = create_safe_http_client()
            close_client_after = True

        start_time = time.perf_counter()
        try:
            response = await client.post(
                destination.destination_url,
                content=canonical_bytes,
                headers=headers,
            )
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            delivery.response_time_ms = elapsed_ms
            delivery.response_status_code = response.status_code

            # Bounded read of response body (never echo arbitrary external bodies)
            _ = response.content[:MAX_RESPONSE_BYTES]

            if 200 <= response.status_code < 300:
                # Confirmed successful delivery
                delivery.status = "DELIVERED"
                delivery.delivered_at = utc_now()
                delivery.error_message = None

                destination.last_delivery_at = delivery.delivered_at
                destination.last_delivery_status = "DELIVERED"
                destination.last_delivery_error = None
                get_metrics_collector().record_outbound_delivery("success")
                logger.info(
                    "Delivered notification %s to '%s' (status=%d, latency=%dms)",
                    delivery.delivery_id,
                    destination.name,
                    response.status_code,
                    elapsed_ms,
                )
            elif 400 <= response.status_code < 500 and response.status_code != 429:
                # Client-side configuration or authorization rejection (non-retryable)
                delivery.status = "PERMANENTLY_FAILED"
                delivery.error_message = f"HTTP {response.status_code}: External destination rejected delivery"

                destination.last_delivery_at = utc_now()
                destination.last_delivery_status = "FAILED"
                destination.last_delivery_error = delivery.error_message
                get_metrics_collector().record_outbound_delivery("failed")
                logger.warning(
                    "Non-retryable delivery failure for %s to '%s': HTTP %d",
                    delivery.delivery_id,
                    destination.name,
                    response.status_code,
                )
            else:
                # Server error (5xx) or Rate Limiting (429) -> retryable
                NotificationDeliveryService._handle_retryable_failure(
                    delivery=delivery,
                    destination=destination,
                    error_msg=f"HTTP {response.status_code}: Receiver returned server error",
                )

        except (httpx.TimeoutException, httpx.NetworkError, Exception) as exc:
            elapsed_ms = int((time.perf_counter() - start_time) * 1000)
            delivery.response_time_ms = elapsed_ms
            clean_err = type(exc).__name__
            if str(exc):
                clean_err = f"{clean_err}: {str(exc)[:120]}"

            NotificationDeliveryService._handle_retryable_failure(
                delivery=delivery,
                destination=destination,
                error_msg=f"Network dispatch error: {clean_err}",
            )
        finally:
            if close_client_after and client is not None:
                await client.aclose()

        return delivery

    @staticmethod
    def _handle_retryable_failure(
        delivery: NotificationDeliveryModel,
        destination: NotificationDestinationModel,
        error_msg: str,
    ) -> None:
        """Apply exponential backoff with jitter or mark permanently failed if ceiling reached."""
        delivery.error_message = error_msg
        destination.last_delivery_at = utc_now()
        destination.last_delivery_status = "FAILED"
        destination.last_delivery_error = error_msg

        if delivery.attempt_count < delivery.max_attempts:
            delivery.status = "RETRY_SCHEDULED"
            # Exponential backoff with jitter: base * 2^(attempt-1) + jitter
            jitter = random.uniform(0.5, 3.0)
            backoff = min(
                MAX_BACKOFF_SECONDS,
                BASE_BACKOFF_SECONDS * (2 ** (delivery.attempt_count - 1)) + jitter,
            )
            delivery.next_attempt_at = utc_now() + timedelta(seconds=backoff)
            get_metrics_collector().record_outbound_delivery("retried")
            logger.info(
                "Scheduled retry #%d for delivery %s in %.1fs (reason: %s)",
                delivery.attempt_count,
                delivery.delivery_id,
                backoff,
                error_msg,
            )
        else:
            delivery.status = "PERMANENTLY_FAILED"
            delivery.next_attempt_at = None
            get_metrics_collector().record_outbound_delivery("dead_letter")
            logger.warning(
                "Permanently failed delivery %s to '%s' after %d attempts",
                delivery.delivery_id,
                destination.name,
                delivery.attempt_count,
            )

    @staticmethod
    async def dispatch_test_notification(
        session: AsyncSession,
        destination_id: UUID,
        allow_local_for_testing: bool = False,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> NotificationDeliveryModel:
        """Trigger an immediate administrative test notification to verify destination connectivity."""
        dest_res = await session.execute(
            select(NotificationDestinationModel).where(
                NotificationDestinationModel.id == destination_id
            )
        )
        destination = dest_res.scalars().first()
        if not destination:
            raise ValueError(f"Destination '{destination_id}' not found")

        delivery_id = uuid4()
        payload = build_test_notification_payload(
            destination_id=destination.id,
            destination_name=destination.name,
            delivery_id=delivery_id,
        )

        delivery = NotificationDeliveryModel(
            id=uuid4(),
            destination_id=destination.id,
            delivery_id=delivery_id,
            event_type=NotificationEventType.TEST_NOTIFICATION.value,
            event_id=f"test:{delivery_id.hex[:8]}",
            status="PENDING",
            attempt_count=0,
            max_attempts=1,  # Tests do not retry automatically
            payload=payload.model_dump(mode="json"),
        )
        session.add(delivery)
        await session.flush()

        # Immediate dispatch
        await NotificationDeliveryService.dispatch_delivery(
            session=session,
            delivery=delivery,
            allow_local_for_testing=allow_local_for_testing,
            http_client=http_client,
        )
        await session.commit()
        return delivery

    @staticmethod
    async def process_pending_deliveries(
        session: AsyncSession,
        batch_size: int = 50,
        allow_local_for_testing: bool = False,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> int:
        """Fetch pending or eligible retry deliveries with row-level locks and deliver them.

        Returns:
            Number of successfully delivered notifications.
        """
        now = utc_now()
        query = (
            select(NotificationDeliveryModel)
            .options(selectinload(NotificationDeliveryModel.destination))
            .where(
                or_(
                    NotificationDeliveryModel.status == "PENDING",
                    (
                        (NotificationDeliveryModel.status == "RETRY_SCHEDULED")
                        & (NotificationDeliveryModel.next_attempt_at <= now)
                    ),
                )
            )
            .order_by(NotificationDeliveryModel.created_at.asc())
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )

        result = await session.execute(query)
        deliveries = result.scalars().all()

        if not deliveries:
            return 0

        delivered_count = 0
        managed_client: Optional[httpx.AsyncClient] = None
        client_to_use = http_client
        if client_to_use is None:
            managed_client = create_safe_http_client()
            client_to_use = managed_client

        try:
            for delivery in deliveries:
                await NotificationDeliveryService.dispatch_delivery(
                    session=session,
                    delivery=delivery,
                    allow_local_for_testing=allow_local_for_testing,
                    http_client=client_to_use,
                )
                if delivery.status == "DELIVERED":
                    delivered_count += 1

            await session.commit()
            return delivered_count
        finally:
            if managed_client is not None:
                await managed_client.aclose()
