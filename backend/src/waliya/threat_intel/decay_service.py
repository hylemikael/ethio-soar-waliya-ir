"""Deterministic and idempotent threat intelligence indicator confidence decay service."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional
from uuid import UUID

from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.db.models import ThreatIndicatorModel
from waliya.threat_intel.matcher import ThreatIntelMatcher

logger = logging.getLogger("waliya.threat_intel.decay")


class ThreatIntelDecayService:
    """Service providing deterministic, bounded decay of stale threat indicators."""

    @classmethod
    async def run_decay(
        cls,
        session: AsyncSession,
        actor_id: str,
        stale_days: int = 14,
        decay_points: int = 10,
        decay_interval_days: int = 7,
        min_confidence: int = 10,
        dry_run: bool = False,
        indicator_type: Optional[str] = None,
        source: Optional[str] = None,
        reference_now: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Execute deterministic confidence decay on active stale indicators.

        Guarantees:
        - Deterministic & Idempotent: repeated runs within the same interval apply 0 change.
        - Bounded: confidence never drops below min_confidence.
        - Safe: never deletes indicators or reactivates expired indicators.
        - Audited: writes cryptographic SHA-256 ledger record upon execution.
        """
        now_utc = reference_now or datetime.now(timezone.utc)

        # 1. Query active, non-expired indicators whose confidence is above the floor
        query = (
            select(ThreatIndicatorModel)
            .where(
                ThreatIndicatorModel.is_active == True,
                ThreatIndicatorModel.confidence > min_confidence,
                or_(
                    ThreatIndicatorModel.expires_at.is_(None),
                    ThreatIndicatorModel.expires_at > now_utc,
                ),
            )
        )

        if indicator_type:
            query = query.where(ThreatIndicatorModel.indicator_type == indicator_type.upper().strip())
        if source:
            query = query.where(ThreatIndicatorModel.source == source.strip())

        res = await session.execute(query)
        candidates = list(res.scalars().all())

        decayed_items: List[Dict[str, Any]] = []
        unaffected_count = 0

        stale_delta = timedelta(days=stale_days)
        interval_seconds = decay_interval_days * 86400

        for ind in candidates:
            baseline = ind.last_seen or ind.first_seen or ind.created_at
            if not baseline:
                unaffected_count += 1
                continue

            # Ensure timezone awareness
            if baseline.tzinfo is None:
                baseline = baseline.replace(tzinfo=timezone.utc)

            # Check if indicator has reached the staleness threshold
            if (now_utc - baseline).total_seconds() < stale_delta.total_seconds():
                unaffected_count += 1
                continue

            # Establish deterministic reference time for decay intervals
            if ind.last_decayed_at is not None:
                ref_time = ind.last_decayed_at
                if ref_time.tzinfo is None:
                    ref_time = ref_time.replace(tzinfo=timezone.utc)
            else:
                ref_time = baseline + stale_delta

            elapsed_seconds = (now_utc - ref_time).total_seconds()
            if elapsed_seconds < 0:
                unaffected_count += 1
                continue

            intervals = int(elapsed_seconds // interval_seconds)
            if intervals <= 0:
                unaffected_count += 1
                continue

            points_to_decay = intervals * decay_points
            new_conf = max(min_confidence, ind.confidence - points_to_decay)

            if new_conf >= ind.confidence:
                unaffected_count += 1
                continue

            decayed_timestamp = ref_time + timedelta(seconds=intervals * interval_seconds)

            decayed_items.append({
                "indicator_id": str(ind.id),
                "value": ind.value,
                "indicator_type": ind.indicator_type,
                "source": ind.source,
                "previous_confidence": ind.confidence,
                "new_confidence": new_conf,
                "intervals_decayed": intervals,
                "last_decayed_at": decayed_timestamp.isoformat(),
            })

            if not dry_run:
                ind.confidence = new_conf
                ind.last_decayed_at = decayed_timestamp
                ind.updated_at = now_utc

        if not dry_run and decayed_items:
            await session.commit()
            # Clear matcher cache so updated confidences take effect immediately
            ThreatIntelMatcher.clear_cache()

            audit_payload = {
                "stale_days": stale_days,
                "decay_points": decay_points,
                "decay_interval_days": decay_interval_days,
                "min_confidence": min_confidence,
                "decayed_count": len(decayed_items),
                "unaffected_count": unaffected_count,
                "is_dry_run": False,
            }
            await AuditLedgerService.record_action(
                session=session,
                actor_id=actor_id,
                action="THREAT_INTEL_DECAY_RUN",
                target_entity="threat_intel:decay",
                payload=audit_payload,
                actor_role="ADMIN",
            )
            await session.commit()
            logger.info("Executed threat intel decay: %d indicators decayed", len(decayed_items))

        return {
            "total_evaluated": len(candidates),
            "decayed_count": len(decayed_items),
            "unaffected_count": unaffected_count,
            "is_dry_run": dry_run,
            "stale_days_threshold": stale_days,
            "decay_points_per_interval": decay_points,
            "decay_interval_days": decay_interval_days,
            "min_confidence": min_confidence,
            "decayed_indicators": decayed_items,
        }
