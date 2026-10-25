"""Streaming behavioral analytics engine using Exponentially Weighted Moving Averages (EWMA).

Computes rolling baselines, dynamic standard deviations, and explainable Z-score anomaly scores
for streaming security telemetry. Operates with bounded per-entity state in Redis.
"""

import logging
import math
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

from redis.asyncio import Redis

from waliya.contracts import AnomalyExplanation, SeverityEnum

logger = logging.getLogger("waliya.analytics.ewma")

# Default EWMA & statistical guardrails
DEFAULT_ALPHA = 0.1
DEFAULT_MIN_SAMPLES = 5  # Cold-start protection
DEFAULT_VARIANCE_FLOOR = 0.25  # Standard deviation floor = 0.5 (prevents near-zero variance sensitivity)
DEFAULT_Z_THRESHOLD = 3.0  # Alert when observation is >= 3 standard deviations from mean
STATE_TTL_SECONDS = 86400  # 24-hour expiration for bounded per-entity state


class EWMAAnalyticsEngine:
    """Streaming statistical anomaly detector using online EWMA baselining."""

    def __init__(
        self,
        redis_client: Redis,
        alpha: float = DEFAULT_ALPHA,
        min_samples: int = DEFAULT_MIN_SAMPLES,
        variance_floor: float = DEFAULT_VARIANCE_FLOOR,
        z_threshold: float = DEFAULT_Z_THRESHOLD,
    ):
        self.redis = redis_client
        self.alpha = alpha
        self.min_samples = min_samples
        self.variance_floor = variance_floor
        self.z_threshold = z_threshold

    async def evaluate_observation(
        self,
        metric_name: str,
        entity_id: str,
        observed_value: float,
    ) -> Optional[AnomalyExplanation]:
        """Compare an observed value against the entity's prior baseline before updating it.

        Guarantees:
        - Cold-start protection: Suppresses alerts until min_samples observations have been recorded.
        - Near-zero variance protection: Enforces variance_floor to avoid division-by-zero or hypersensitivity.
        - Prior baseline comparison: Computes Z-score using prior mean and prior standard deviation.
        - Bounded storage: Sets 24h TTL on all Redis state keys.

        Returns:
            AnomalyExplanation if an anomaly is detected; None otherwise.
        """
        state_key = f"waliya:ewma:{metric_name}:{entity_id}"
        state_data = await self.redis.hgetall(state_key)

        now_ts = datetime.now(timezone.utc).timestamp()

        # 1. Cold start check (no prior observations)
        if not state_data:
            initial_state = {
                "mean": str(observed_value),
                "variance": str(self.variance_floor),
                "count": "1",
                "last_updated": str(now_ts),
            }
            pipe = self.redis.pipeline()
            pipe.hset(state_key, mapping=initial_state)
            pipe.expire(state_key, STATE_TTL_SECONDS)
            await pipe.execute()
            return None

        # 2. Extract prior baseline parameters
        prior_mean = float(state_data.get("mean", observed_value))
        prior_variance = max(float(state_data.get("variance", self.variance_floor)), self.variance_floor)
        prior_count = int(state_data.get("count", 1))

        prior_std = math.sqrt(prior_variance)

        # 3. Calculate Z-score against prior baseline
        z_score = (observed_value - prior_mean) / prior_std if prior_std > 0 else 0.0

        # 4. Update EWMA baseline with the new observation
        new_mean = (1.0 - self.alpha) * prior_mean + self.alpha * observed_value
        # Exponentially weighted variance update
        diff = observed_value - new_mean
        new_variance = (1.0 - self.alpha) * prior_variance + self.alpha * (diff * diff)
        new_variance = max(new_variance, self.variance_floor)
        new_count = prior_count + 1

        # Save updated bounded state
        updated_state = {
            "mean": str(new_mean),
            "variance": str(new_variance),
            "count": str(new_count),
            "last_updated": str(now_ts),
        }
        pipe = self.redis.pipeline()
        pipe.hset(state_key, mapping=updated_state)
        pipe.expire(state_key, STATE_TTL_SECONDS)
        await pipe.execute()

        # 5. Check if threshold exceeded after sufficient training samples (cold start check)
        if prior_count < self.min_samples:
            logger.debug(
                "Entity '%s' metric '%s' sample count %d < min_samples %d; suppressing cold alert",
                entity_id,
                metric_name,
                prior_count,
                self.min_samples,
            )
            return None

        if z_score >= self.z_threshold:
            decision_reason = (
                f"Observed value {observed_value:.2f} exceeds baseline mean {prior_mean:.2f} "
                f"by {z_score:.2f} standard deviations (baseline std: {prior_std:.2f}, "
                f"threshold: {self.z_threshold:.1f}, sample_count: {prior_count})"
            )

            return AnomalyExplanation(
                metric_name=metric_name,
                observed_value=float(observed_value),
                baseline_mean=float(prior_mean),
                baseline_std=float(prior_std),
                z_score=float(z_score),
                threshold=float(self.z_threshold),
                alpha=float(self.alpha),
                decision_reason=decision_reason,
            )

        return None

    async def process_event(self, event_data: Dict[str, Any]) -> Optional[Tuple[str, AnomalyExplanation, SeverityEnum]]:
        """Extract streaming telemetry features from event and evaluate against EWMA baselines.

        Returns:
            Tuple of (dedup_key, AnomalyExplanation, SeverityEnum) if anomalous; None otherwise.
        """
        event_type = event_data.get("event_type")
        attrs = event_data.get("attributes") or event_data.get("normalized", {}).get("attributes") or {}
        now_ts = datetime.now(timezone.utc).timestamp()

        # Metric A: Authentication Failure Velocity
        if event_type == "AUTHENTICATION" and str(attrs.get("status", "")).upper() == "FAILURE":
            entity = str(attrs.get("src_ip") or attrs.get("user") or event_data.get("agent_id") or "unknown")
            window_key = f"waliya:ewma_win:auth_fail:{entity}"

            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(window_key, 0, now_ts - 60)
            pipe.zadd(window_key, {str(event_data.get("event_id")): now_ts})
            pipe.zcard(window_key)
            pipe.expire(window_key, 120)
            results = await pipe.execute()
            velocity = float(results[2])

            anomaly = await self.evaluate_observation("auth_failure_velocity", entity, velocity)
            if anomaly:
                severity = SeverityEnum.CRITICAL if anomaly.z_score >= 5.0 else SeverityEnum.HIGH
                return f"ANOMALY:auth_failure_velocity:{entity}", anomaly, severity

        # Metric B: Unique Destination Port Count
        elif event_type == "NETWORK_CONNECTION":
            entity = str(attrs.get("src_ip") or event_data.get("agent_id") or "unknown")
            dst_port = attrs.get("dst_port")
            if dst_port is not None:
                window_key = f"waliya:ewma_win:ports:{entity}"
                pipe = self.redis.pipeline()
                pipe.zremrangebyscore(window_key, 0, now_ts - 60)
                pipe.zadd(window_key, {str(dst_port): now_ts})
                pipe.zcard(window_key)
                pipe.expire(window_key, 120)
                results = await pipe.execute()
                port_count = float(results[2])

                anomaly = await self.evaluate_observation("unique_destination_ports", entity, port_count)
                if anomaly:
                    severity = SeverityEnum.HIGH if anomaly.z_score >= 5.0 else SeverityEnum.MEDIUM
                    return f"ANOMALY:unique_destination_ports:{entity}", anomaly, severity

        # Metric C: Burst File Modifications
        elif event_type == "FILE_INTEGRITY":
            entity = str(event_data.get("agent_id") or "unknown")
            window_key = f"waliya:ewma_win:fim:{entity}"
            pipe = self.redis.pipeline()
            pipe.zremrangebyscore(window_key, 0, now_ts - 60)
            pipe.zadd(window_key, {str(event_data.get("event_id")): now_ts})
            pipe.zcard(window_key)
            pipe.expire(window_key, 120)
            results = await pipe.execute()
            fim_count = float(results[2])

            anomaly = await self.evaluate_observation("burst_file_modifications", entity, fim_count)
            if anomaly:
                severity = SeverityEnum.HIGH if anomaly.z_score >= 5.0 else SeverityEnum.MEDIUM
                return f"ANOMALY:burst_file_modifications:{entity}", anomaly, severity

        return None
