"""Inbound external security event ingestion, authentication, and pipeline dispatch service."""

from datetime import datetime, timezone
import json
import logging
from typing import Any, Dict, Optional
from uuid import UUID, uuid4

from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import InboundEventIngestResponse
from waliya.db.models import (
    EventModel,
    EventOutboxModel,
    InboundEventDedupModel,
    InboundSourceModel,
    utc_now,
)
from waliya.integrations.normalization import (
    MAX_INBOUND_PAYLOAD_BYTES,
    NormalizedExternalEvent,
    check_nesting_depth_and_prohibited_keys,
    normalize_inbound_security_event,
    parse_event_timestamp,
)
from waliya.integrations.signing import (
    decrypt_destination_secret,
    verify_notification_signature,
)
from waliya.observability.metrics import get_metrics_collector
from waliya.telemetry.outbox_publisher import OutboxPublisher

logger = logging.getLogger("waliya.integrations.inbound_service")

# Allowed timestamp drift in seconds (5 minutes)
MAX_TIMESTAMP_DRIFT_SECONDS = 300.0


class InboundIngestionService:
    """Orchestrates secure authentication, validation, deduplication, and ingestion

    of external security events into Waliya-IR's durable processing pipeline.
    """

    def __init__(self, outbox_publisher: Optional[OutboxPublisher] = None):
        self.outbox_publisher = outbox_publisher or OutboxPublisher()

    async def ingest_external_event(
        self,
        source_slug: str,
        raw_body: bytes,
        headers: Dict[str, str],
        session: AsyncSession,
    ) -> InboundEventIngestResponse:
        """Authenticate, validate, deduplicate, and durably ingest an external security event.

        Raises appropriate HTTPExceptions:
        - 400: Malformed header/timestamp, prohibited keys
        - 401: Missing/invalid signature, stale/future timestamp
        - 403: Disabled source, forbidden event type
        - 404: Source not found
        - 413: Body exceeds 1 MB limit
        - 422: Malformed JSON, missing external event ID
        """
        # 1. Payload size check
        if len(raw_body) > MAX_INBOUND_PAYLOAD_BYTES:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail=f"Inbound payload exceeds maximum size limit of {MAX_INBOUND_PAYLOAD_BYTES} bytes",
            )

        # 2. Look up configured inbound source
        source_query = select(InboundSourceModel).where(InboundSourceModel.source_id == source_slug)
        result = await session.execute(source_query)
        source = result.scalars().first()

        if source is None:
            logger.warning("Inbound request rejected: unknown source slug '%s'", source_slug)
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Inbound source '{source_slug}' is not registered",
            )

        # 3. Source enabled check
        if not source.is_enabled:
            logger.warning("Inbound request rejected: source '%s' is disabled", source_slug)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Inbound source '{source_slug}' is currently disabled",
            )

        # 4. Source ID header consistency check (case-insensitive lookup in headers)
        header_map = {k.lower(): v for k, v in headers.items()}
        source_id_header = header_map.get("x-waliya-source-id")
        if source_id_header and source_id_header.strip() != source_slug:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="X-Waliya-Source-Id header does not match endpoint source slug",
            )

        # 5. Timestamp freshness check (Replay attack protection)
        ts_header = header_map.get("x-waliya-timestamp")
        if not ts_header or not ts_header.strip():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing required X-Waliya-Timestamp header",
            )

        header_dt = self._parse_header_timestamp(ts_header.strip())
        now_utc = datetime.now(timezone.utc)
        drift = (now_utc - header_dt).total_seconds()

        if abs(drift) > MAX_TIMESTAMP_DRIFT_SECONDS:
            err_msg = f"Timestamp freshness error: Drift of {int(drift)}s exceeds allowed {int(MAX_TIMESTAMP_DRIFT_SECONDS)}s window"
            logger.warning("Source '%s' replay/freshness check failed: %s", source_slug, err_msg)
            # Record rejection metric
            await self._record_rejection(session, source, err_msg)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=err_msg,
            )

        # 6. Signature verification (Cryptographic authenticity)
        sig_header = header_map.get("x-waliya-signature")
        if not sig_header or not sig_header.strip():
            err_msg = "Missing required X-Waliya-Signature header"
            await self._record_rejection(session, source, err_msg)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=err_msg,
            )

        secret = decrypt_destination_secret(source.shared_secret_enc)
        if not secret:
            logger.error("Failed to decrypt signing secret for source '%s'", source_slug)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Security integration configuration error",
            )

        sig_valid = verify_notification_signature(secret, raw_body, sig_header.strip())
        if not sig_valid:
            err_msg = "Invalid HMAC-SHA256 signature"
            logger.warning("Source '%s' HMAC signature verification failed", source_slug)
            await self._record_rejection(session, source, err_msg)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=err_msg,
            )

        # 7. Parse and validate JSON structure
        try:
            payload_data = json.loads(raw_body.decode("utf-8"))
        except Exception as json_err:
            err_msg = f"Malformed JSON payload: {json_err}"
            await self._record_rejection(session, source, err_msg)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=err_msg,
            )

        if not isinstance(payload_data, dict):
            err_msg = "Inbound security event payload must be a JSON object"
            await self._record_rejection(session, source, err_msg)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=err_msg,
            )

        # 8. Check nesting depth and prohibited command keys
        try:
            check_nesting_depth_and_prohibited_keys(payload_data)
        except HTTPException as exc:
            await self._record_rejection(session, source, exc.detail)
            raise

        # 9. Extract external event ID
        header_event_id = header_map.get("x-waliya-event-id")
        external_event_id = (
            (header_event_id.strip() if header_event_id else None)
            or payload_data.get("external_event_id")
            or payload_data.get("detection_id")
            or payload_data.get("log_id")
            or payload_data.get("event_id")
            or payload_data.get("id")
        )
        if not external_event_id:
            err_msg = "Missing external event identifier in headers or payload"
            await self._record_rejection(session, source, err_msg)
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_CONTENT,
                detail=err_msg,
            )

        ext_id_str = str(external_event_id).strip()[:128]

        # 10. Persistent Deduplication Check (source-scoped)
        dedup_query = select(InboundEventDedupModel).where(
            InboundEventDedupModel.source_id == source.id,
            InboundEventDedupModel.external_event_id == ext_id_str,
        )
        dedup_res = await session.execute(dedup_query)
        existing_dedup = dedup_res.scalars().first()

        if existing_dedup is not None:
            # Duplicate detected: acknowledge idempotently without creating duplicate event/outbox
            source.total_events_received += 1
            source.total_events_deduplicated += 1
            source.last_received_at = utc_now()
            await session.commit()

            logger.info(
                "Source '%s' submitted duplicate external event '%s' (Internal: %s)",
                source_slug,
                ext_id_str,
                existing_dedup.internal_event_id,
            )
            get_metrics_collector().record_inbound_event("duplicate")
            return InboundEventIngestResponse(
                status="DUPLICATE",
                event_id=str(existing_dedup.internal_event_id) if existing_dedup.internal_event_id else None,
                external_event_id=ext_id_str,
                source_id=source.source_id,
                duplicate=True,
                received_at=utc_now(),
                message="Duplicate event previously accepted",
            )

        # 11. Normalize external event
        try:
            normalized: NormalizedExternalEvent = normalize_inbound_security_event(
                source=source,
                raw_payload=payload_data,
                fallback_external_id=ext_id_str,
            )
        except HTTPException as norm_err:
            await self._record_rejection(session, source, norm_err.detail)
            raise

        # 12. Check permitted event types
        if source.permitted_event_types and len(source.permitted_event_types) > 0:
            permitted_set = {t.upper() for t in source.permitted_event_types}
            if "*" not in permitted_set and normalized.event_type.upper() not in permitted_set:
                err_msg = f"Event type '{normalized.event_type}' is not permitted for source '{source.source_id}'"
                await self._record_rejection(session, source, err_msg)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=err_msg,
                )

        # 13. Persist Event, Outbox, and Dedup atomically
        internal_event_id = uuid4()
        now = utc_now()

        # Database Event: agent_id is strictly None (External source cannot impersonate agent)
        db_event = EventModel(
            id=internal_event_id,
            agent_id=None,
            event_type=normalized.event_type,
            severity=normalized.severity,
            timestamp=normalized.timestamp,
            source=f"external:{source.source_id}",
            raw_payload=payload_data,
            normalized_payload=normalized.to_normalized_payload(),
        )
        session.add(db_event)

        # Outbox message to route through Redis Streams (stream:telemetry:raw)
        outbox_payload = {
            "event_id": str(internal_event_id),
            "agent_id": None,
            "event_type": normalized.event_type,
            "severity": normalized.severity,
            "timestamp": normalized.timestamp.isoformat(),
            "source": f"external:{source.source_id}",
            "is_simulation": False,
            "normalized": normalized.to_normalized_payload(),
        }
        db_outbox = EventOutboxModel(
            event_id=internal_event_id,
            stream_name="stream:telemetry:raw",
            payload=outbox_payload,
            status="PENDING",
        )
        session.add(db_outbox)

        # Dedup tracking record
        db_dedup = InboundEventDedupModel(
            id=uuid4(),
            source_id=source.id,
            external_event_id=ext_id_str,
            internal_event_id=internal_event_id,
            status="ACCEPTED",
            received_at=now,
        )
        session.add(db_dedup)

        # Source metrics
        source.total_events_received += 1
        source.total_events_accepted += 1
        source.last_received_at = now
        source.last_error_message = None

        try:
            await session.commit()
        except IntegrityError:
            # Concurrent duplicate submission race condition resolved safely
            await session.rollback()
            query_again = select(InboundEventDedupModel).where(
                InboundEventDedupModel.source_id == source.id,
                InboundEventDedupModel.external_event_id == ext_id_str,
            )
            res_again = await session.execute(query_again)
            race_dedup = res_again.scalars().first()
            return InboundEventIngestResponse(
                status="DUPLICATE",
                event_id=str(race_dedup.internal_event_id) if race_dedup and race_dedup.internal_event_id else None,
                external_event_id=ext_id_str,
                source_id=source.source_id,
                duplicate=True,
                received_at=utc_now(),
                message="Duplicate event previously accepted",
            )

        # 14. Non-blocking outbox publication
        try:
            await self.outbox_publisher.publish_pending_events(session=session)
        except Exception as pub_exc:
            logger.warning("Post-ingest outbox publish error (events safely queued in DB): %s", pub_exc)

        logger.info(
            "External event '%s' from source '%s' accepted (Internal: %s, Type: %s, Sev: %s)",
            ext_id_str,
            source_slug,
            internal_event_id,
            normalized.event_type,
            normalized.severity,
        )
        get_metrics_collector().record_inbound_event("accepted")

        return InboundEventIngestResponse(
            status="ACCEPTED",
            event_id=str(internal_event_id),
            external_event_id=ext_id_str,
            source_id=source.source_id,
            duplicate=False,
            received_at=now,
            message="External security event accepted for processing",
        )

    def _parse_header_timestamp(self, ts_str: str) -> datetime:
        """Parse timestamp header string, supporting ISO 8601 or epoch."""
        # Check ISO format
        clean = ts_str.strip()
        if clean.endswith("Z"):
            clean = clean[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(clean)
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            pass

        # Check numeric epoch
        try:
            val = float(clean)
            if val > 1e11:
                val = val / 1000.0
            return datetime.fromtimestamp(val, tz=timezone.utc)
        except Exception:
            pass

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed X-Waliya-Timestamp header format: '{ts_str}'",
        )

    async def _record_rejection(
        self,
        session: AsyncSession,
        source: InboundSourceModel,
        reason: str,
    ) -> None:
        """Increment rejection count and record last error on source configuration."""
        try:
            source.total_events_received += 1
            source.total_events_rejected += 1
            source.last_error_message = str(reason)[:512]
            source.last_received_at = utc_now()
            get_metrics_collector().record_inbound_event("rejected")
            await session.commit()
        except Exception as exc:
            logger.warning("Failed to record rejection metric on source '%s': %s", source.source_id, exc)
