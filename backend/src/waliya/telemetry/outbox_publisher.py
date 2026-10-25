"""Transactional Outbox Publisher delivering pending events to Redis Streams."""

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from redis.asyncio import Redis
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.config import settings
from waliya.db.models import EventOutboxModel
from waliya.db.session import async_session_factory

logger = logging.getLogger("waliya.telemetry.outbox_publisher")

MAX_RETRIES = 5


class OutboxPublisher:
    """Delivers pending events from PostgreSQL transactional outbox to Redis Streams."""

    def __init__(self, redis_url: Optional[str] = None):
        self.redis_url = redis_url or settings.REDIS_URL

    async def get_redis_client(self) -> Redis:
        """Create and return an asynchronous Redis client."""
        return Redis.from_url(
            self.redis_url,
            socket_timeout=5.0,
            socket_connect_timeout=5.0,
            decode_responses=True,
        )

    async def publish_pending_events(
        self,
        batch_size: int = 100,
        session: Optional[AsyncSession] = None,
    ) -> int:
        """Fetch pending outbox records and deliver them to their target Redis Streams.

        Guarantees:
        - Delivery status is marked PUBLISHED only after Redis explicitly acknowledges the xadd write.
        - Failed publications remain in the outbox with an incremented retry_count and error log.
        - Records are never deleted silently.

        Args:
            batch_size: Maximum records to publish in this iteration.
            session: Optional existing database session. If omitted, a session is managed automatically.

        Returns:
            Number of successfully published events.
        """
        if session is not None:
            return await self._process_batch(session, batch_size)

        async with async_session_factory() as managed_session:
            return await self._process_batch(managed_session, batch_size)

    async def _process_batch(self, session: AsyncSession, batch_size: int) -> int:
        # Select pending or recoverable failed records
        query = (
            select(EventOutboxModel)
            .where(
                or_(
                    EventOutboxModel.status == "PENDING",
                    (EventOutboxModel.status == "FAILED") & (EventOutboxModel.retry_count < MAX_RETRIES),
                )
            )
            .order_by(EventOutboxModel.created_at.asc())
            .limit(batch_size)
            .with_for_update(skip_locked=True)
        )

        result = await session.execute(query)
        pending_records = result.scalars().all()

        if not pending_records:
            return 0

        redis_client = None
        published_count = 0

        try:
            redis_client = await self.get_redis_client()

            for record in pending_records:
                try:
                    payload_json = json.dumps(record.payload, default=str)
                    # Publish to Redis Stream using xadd
                    msg_id = await redis_client.xadd(
                        record.stream_name,
                        {"data": payload_json},
                    )

                    # Update record status only upon confirmed Redis ACK
                    if msg_id:
                        record.status = "PUBLISHED"
                        record.stream_message_id = msg_id.decode("utf-8") if isinstance(msg_id, bytes) else str(msg_id)
                        record.published_at = datetime.now(timezone.utc)
                        published_count += 1
                        logger.debug("Event %s published to stream with msg_id %s", record.event_id, msg_id)

                except Exception as err:
                    record.status = "FAILED"
                    record.retry_count += 1
                    record.last_error = f"{type(err).__name__}: {str(err)[:500]}"
                    logger.warning("Failed to publish outbox event %s to Redis: %s", record.event_id, err)

            # Persist all status updates to PostgreSQL
            await session.commit()

        except Exception as redis_conn_err:
            logger.error("Redis connection failed during outbox dispatch: %s", redis_conn_err)
            # Mark records as failed and record error
            for record in pending_records:
                record.status = "FAILED"
                record.retry_count += 1
                record.last_error = f"RedisConnectionError: {str(redis_conn_err)[:500]}"
            await session.commit()

        finally:
            if redis_client is not None:
                await redis_client.aclose()

        return published_count


outbox_publisher = OutboxPublisher()
