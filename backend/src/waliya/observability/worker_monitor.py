"""Redis Streams worker heartbeat recording and consumer lag diagnostics."""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from redis.asyncio import Redis

from waliya.contracts import DependencyHealthStatus, WorkerHealthItem

logger = logging.getLogger("waliya.observability.worker_monitor")

HEARTBEAT_TTL_SECONDS = 180
HEALTHY_HEARTBEAT_THRESHOLD_SECONDS = 60.0
DEGRADED_HEARTBEAT_THRESHOLD_SECONDS = 120.0
LAG_DEGRADED_THRESHOLD = 500


async def record_worker_heartbeat(
    redis: Redis,
    group_name: str,
    consumer_name: str,
    stream_name: str = "stream:telemetry:raw",
    processed_count: int = 0,
    error_count: int = 0,
    last_batch_size: int = 0,
) -> None:
    """Record worker heartbeat and operational metrics in Redis with bounded TTL."""
    try:
        now_iso = datetime.now(timezone.utc).isoformat()
        heartbeat_key = f"waliya:workers:heartbeat:{group_name}:{consumer_name}"
        active_set_key = f"waliya:workers:active_set:{group_name}"

        payload = {
            "worker_id": consumer_name,
            "group_name": group_name,
            "stream_name": stream_name,
            "timestamp": now_iso,
            "processed_count": str(processed_count),
            "error_count": str(error_count),
            "last_batch_size": str(last_batch_size),
        }

        # Save worker heartbeat hash and refresh expiration
        await redis.hset(heartbeat_key, mapping=payload)
        await redis.expire(heartbeat_key, HEARTBEAT_TTL_SECONDS)

        # Maintain active worker set
        await redis.sadd(active_set_key, consumer_name)
        await redis.expire(active_set_key, HEARTBEAT_TTL_SECONDS * 2)
    except Exception as exc:
        logger.warning("Failed to record worker heartbeat for '%s': %s", consumer_name, exc)


async def get_worker_health_summary(
    redis: Redis,
    stream_name: str = "stream:telemetry:raw",
    group_name: str = "waliya_detection_group",
) -> Tuple[List[WorkerHealthItem], int, int, int]:
    """Retrieve consumer lag, pending PEL size, and individual worker heartbeat states.

    Returns:
        Tuple of (worker_health_items, stream_length, stream_lag, pel_size).
    """
    stream_length = 0
    stream_lag = 0
    pel_size = 0
    workers: List[WorkerHealthItem] = []

    # 1. Inspect Stream Length
    try:
        stream_length = await redis.xlen(stream_name)
    except Exception as exc:
        logger.debug("Stream '%s' inspection error or stream does not exist: %s", stream_name, exc)
        stream_length = 0

    # 2. Inspect Consumer Group Lag and PEL Size
    try:
        groups_info = await redis.xinfo_groups(stream_name)
        for g in groups_info:
            if g.get("name") == group_name:
                pel_size = int(g.get("pending", 0))
                # Redis 7+ provides 'lag', older versions or empty streams may return None
                raw_lag = g.get("lag")
                stream_lag = int(raw_lag) if raw_lag is not None else 0
                break
    except Exception as exc:
        logger.debug("Consumer group '%s' inspection error: %s", group_name, exc)

    # 3. Query Active Worker Heartbeats
    try:
        active_set_key = f"waliya:workers:active_set:{group_name}"
        consumer_names = await redis.smembers(active_set_key)
        now = datetime.now(timezone.utc)

        for c_name in consumer_names:
            c_name_str = c_name if isinstance(c_name, str) else c_name.decode("utf-8")
            heartbeat_key = f"waliya:workers:heartbeat:{group_name}:{c_name_str}"
            h_data = await redis.hgetall(heartbeat_key)

            if not h_data:
                # Heartbeat expired; worker stopped reporting
                await redis.srem(active_set_key, c_name)
                continue

            # Decode bytes if needed
            decoded: Dict[str, str] = {
                (k if isinstance(k, str) else k.decode("utf-8")): (v if isinstance(v, str) else v.decode("utf-8"))
                for k, v in h_data.items()
            }

            ts_str = decoded.get("timestamp")
            hb_dt: Optional[datetime] = None
            age_seconds: Optional[float] = None
            if ts_str:
                try:
                    hb_dt = datetime.fromisoformat(ts_str)
                    age_seconds = max(0.0, (now - hb_dt).total_seconds())
                except ValueError:
                    pass

            processed_cnt = int(decoded.get("processed_count", 0))
            error_cnt = int(decoded.get("error_count", 0))

            # Evaluate health status based on heartbeat freshness and stream lag
            if age_seconds is None:
                worker_status = DependencyHealthStatus.UNKNOWN
            elif age_seconds > DEGRADED_HEARTBEAT_THRESHOLD_SECONDS:
                worker_status = DependencyHealthStatus.UNHEALTHY
            elif age_seconds > HEALTHY_HEARTBEAT_THRESHOLD_SECONDS or stream_lag > LAG_DEGRADED_THRESHOLD:
                worker_status = DependencyHealthStatus.DEGRADED
            else:
                worker_status = DependencyHealthStatus.HEALTHY

            workers.append(
                WorkerHealthItem(
                    worker_id=c_name_str,
                    group_name=group_name,
                    status=worker_status,
                    last_heartbeat=hb_dt,
                    heartbeat_age_seconds=round(age_seconds, 1) if age_seconds is not None else None,
                    processed_count=processed_cnt,
                    error_count=error_cnt,
                    stream_lag=stream_lag,
                    pending_pel_count=pel_size,
                )
            )
    except Exception as exc:
        logger.warning("Error reading worker heartbeats: %s", exc)

    return workers, stream_length, stream_lag, pel_size
