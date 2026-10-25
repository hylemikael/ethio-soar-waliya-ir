"""Safe, idempotent threat intelligence feed synchronization service."""

from datetime import datetime, timedelta, timezone
import logging
import os
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

from sqlalchemy import desc, func, or_, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.config import settings
from waliya.db.models import FeedConfigurationModel, FeedSyncRunModel, ThreatIndicatorModel
from waliya.threat_intel.connectors import CONNECTORS
from waliya.threat_intel.connectors.base import (
    BaseFeedConnector,
    FeedAuthenticationError,
    FeedFetchError,
    FeedRateLimitError,
    FeedSecurityError,
    RawIndicatorRecord,
)
from waliya.threat_intel.normalizer import (
    IndicatorValidationError,
    detect_indicator_type,
    normalize_indicator,
)

logger = logging.getLogger("waliya.threat_intel.sync_service")


class ThreatIntelSyncService:
    """Service orchestrating external feed ingestion, idempotent upserting, and audit logging."""

    @staticmethod
    def get_api_key_for_feed(feed_id: str) -> Optional[str]:
        """Retrieve the configured API key for a feed from environment variables or settings."""
        clean_id = feed_id.strip().lower()
        if clean_id == "threatfox":
            return (
                settings.TI_THREATFOX_API_KEY
                or os.environ.get("WALIYA_TI_THREATFOX_API_KEY")
                or os.environ.get("THREATFOX_API_KEY")
            )
        elif clean_id == "urlhaus":
            return (
                settings.TI_URLHAUS_API_KEY
                or os.environ.get("WALIYA_TI_URLHAUS_API_KEY")
                or os.environ.get("URLHAUS_API_KEY")
            )
        return None

    @classmethod
    async def get_or_create_feed_config(
        cls,
        session: AsyncSession,
        feed_id: str,
    ) -> Optional[FeedConfigurationModel]:
        """Retrieve existing feed configuration or return None."""
        query = select(FeedConfigurationModel).where(FeedConfigurationModel.feed_id == feed_id)
        res = await session.execute(query)
        return res.scalar_one_or_none()

    @classmethod
    async def list_feeds(
        cls,
        session: AsyncSession,
    ) -> List[Tuple[FeedConfigurationModel, int]]:
        """List all configured feeds with live count of active indicators."""
        query = select(FeedConfigurationModel).order_by(FeedConfigurationModel.feed_id.asc())
        res = await session.execute(query)
        feeds = list(res.scalars().all())

        results: List[Tuple[FeedConfigurationModel, int]] = []
        for feed in feeds:
            # Count active indicators from this provider
            count_q = (
                select(func.count(ThreatIndicatorModel.id))
                .where(
                    ThreatIndicatorModel.source == feed.provider,
                    ThreatIndicatorModel.is_active == True,
                )
            )
            count_res = await session.execute(count_q)
            ind_count = count_res.scalar() or 0
            results.append((feed, ind_count))

        return results

    @classmethod
    async def sync_feed(
        cls,
        session: AsyncSession,
        feed_id: str,
        is_dry_run: bool = False,
        force: bool = False,
        triggered_by: str = "cli:manual",
        connector_override: Optional[BaseFeedConnector] = None,
    ) -> FeedSyncRunModel:
        """Execute synchronization for a specific feed with safe idempotent upserting."""
        feed = await cls.get_or_create_feed_config(session, feed_id)
        if not feed:
            raise ValueError(f"Feed '{feed_id}' is not configured in the platform database.")

        now_utc = datetime.now(timezone.utc)

        # 1. Check enabled state
        if not feed.is_enabled and not is_dry_run and not force:
            raise FeedFetchError(
                f"Feed '{feed_id}' is disabled. Enable it in the configuration or pass '--force' to proceed."
            )

        # 2. Enforce minimum sync interval
        min_interval_mins = getattr(settings, "TI_MIN_SYNC_INTERVAL_MINUTES", 15)
        if feed.last_sync_at and not force and not is_dry_run:
            elapsed = now_utc - feed.last_sync_at
            if elapsed < timedelta(minutes=min_interval_mins):
                remaining = int((timedelta(minutes=min_interval_mins) - elapsed).total_seconds() / 60)
                raise FeedRateLimitError(
                    f"Feed '{feed_id}' was synced recently ({feed.last_sync_at.strftime('%Y-%m-%d %H:%M:%S UTC')}). "
                    f"Please wait {max(1, remaining)} more minute(s) to respect provider rate limits, or use '--force'."
                )

        # 3. Lookup credentials
        api_key = cls.get_api_key_for_feed(feed_id)
        if not api_key and not connector_override:
            env_var = f"WALIYA_TI_{feed_id.upper()}_API_KEY"
            raise FeedAuthenticationError(
                f"Missing API key for feed '{feed_id}' ({feed.provider}). Please set environment variable '{env_var}'."
            )

        # 4. Resolve connector
        connector: BaseFeedConnector
        if connector_override:
            connector = connector_override
        else:
            conn_cls = CONNECTORS.get(feed_id.lower())
            if not conn_cls:
                raise ValueError(f"No connector registered for feed ID '{feed_id}'.")
            connector = conn_cls(
                timeout_seconds=float(getattr(settings, "TI_HTTP_TIMEOUT_SECONDS", 30)),
                max_records=int(getattr(settings, "TI_MAX_RECORDS_PER_SYNC", 1000)),
            )

        # 5. Create sync run record
        run = FeedSyncRunModel(
            id=uuid4(),
            feed_id=feed.feed_id,
            started_at=now_utc,
            status="RUNNING",
            is_dry_run=is_dry_run,
            triggered_by=triggered_by,
        )
        session.add(run)
        await session.flush()

        # 6. Fetch external indicators
        fetch_options = dict(feed.config_options or {})
        try:
            fetch_result = await connector.fetch_indicators(fetch_options, api_key=api_key)
        except Exception as exc:
            err_msg = connector.sanitize_string(str(exc), api_key)
            logger.error("Feed '%s' sync failed during fetch: %s", feed_id, err_msg)
            run.status = "FAILED"
            run.finished_at = datetime.now(timezone.utc)
            run.error_summary = err_msg
            run.diagnostics = {"error": err_msg, "exception_type": exc.__class__.__name__}

            feed.last_sync_at = now_utc
            feed.last_status = "FAILED"
            feed.last_error_summary = err_msg
            await session.commit()
            return run

        run.fetched_count = fetch_result.fetched_count
        raw_records = fetch_result.records

        # 7. Process records in bounded batches (chunk size 100)
        chunk_size = 100
        rejection_reasons: Dict[str, int] = {}
        skip_reasons: Dict[str, int] = {}

        inserted_count = 0
        updated_count = 0
        skipped_count = 0
        rejected_count = 0
        normalized_count = 0

        for i in range(0, len(raw_records), chunk_size):
            chunk = raw_records[i : i + chunk_size]
            valid_batch_records: List[Tuple[RawIndicatorRecord, str, str]] = []

            for raw_rec in chunk:
                # Check for unsupported indicator type
                if raw_rec.indicator_type in ("MD5_HASH", "MD5", "SHA1", "EMAIL", "CERTIFICATE"):
                    skipped_count += 1
                    reason = f"Unsupported type: {raw_rec.indicator_type}"
                    skip_reasons[reason] = skip_reasons.get(reason, 0) + 1
                    continue

                try:
                    target_type = raw_rec.indicator_type
                    if not target_type:
                        target_type = detect_indicator_type(raw_rec.value)
                    norm_type, norm_value = normalize_indicator(target_type, raw_rec.value)
                    valid_batch_records.append((raw_rec, norm_type, norm_value))
                    normalized_count += 1
                except IndicatorValidationError as exc:
                    rejected_count += 1
                    reason = f"{exc}"[:120]
                    rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
                    continue
                except Exception as exc:
                    rejected_count += 1
                    reason = f"Parse failure: {exc}"[:120]
                    rejection_reasons[reason] = rejection_reasons.get(reason, 0) + 1
                    continue

            if not valid_batch_records:
                continue

            # Query existing indicators for this batch to accurately count insert vs update
            norm_keys = [(t, v) for _, t, v in valid_batch_records]
            # Batch query for existence
            existing_query = select(ThreatIndicatorModel.indicator_type, ThreatIndicatorModel.value).where(
                ThreatIndicatorModel.source == feed.provider,
                or_(*[
                    (ThreatIndicatorModel.indicator_type == t) & (ThreatIndicatorModel.value == v)
                    for t, v in norm_keys
                ]),
            )
            ex_res = await session.execute(existing_query)
            existing_set = set(ex_res.all())

            for raw_rec, norm_type, norm_value in valid_batch_records:
                is_update = (norm_type, norm_value) in existing_set
                if is_update:
                    updated_count += 1
                else:
                    inserted_count += 1

                if not is_dry_run:
                    # Idempotent PostgreSQL upsert
                    stmt = pg_insert(ThreatIndicatorModel).values(
                        id=uuid4(),
                        indicator_type=norm_type,
                        value=norm_value,
                        source=feed.provider,
                        source_id=raw_rec.source_id,
                        confidence=raw_rec.confidence,
                        severity=raw_rec.severity,
                        threat_category=raw_rec.threat_category,
                        threat_actor=raw_rec.threat_actor,
                        tags=raw_rec.tags,
                        description=raw_rec.description,
                        first_seen=raw_rec.first_seen,
                        last_seen=raw_rec.last_seen,
                        expires_at=raw_rec.expires_at,
                        is_active=raw_rec.is_active,
                        created_at=now_utc,
                        updated_at=now_utc,
                    ).on_conflict_do_update(
                        constraint="uq_threat_indicators_type_value_source",
                        set_={
                            "source_id": raw_rec.source_id,
                            "confidence": raw_rec.confidence,
                            "severity": raw_rec.severity,
                            "threat_category": raw_rec.threat_category,
                            "tags": raw_rec.tags,
                            "description": raw_rec.description,
                            "last_seen": raw_rec.last_seen,
                            "expires_at": raw_rec.expires_at,
                            "is_active": raw_rec.is_active,
                            "updated_at": now_utc,
                        },
                    )
                    await session.execute(stmt)

            if not is_dry_run:
                await session.flush()

        # 8. Evaluate final status
        final_status = "SUCCESS"
        error_summary: Optional[str] = None

        if run.fetched_count > 0 and normalized_count == 0:
            final_status = "FAILED"
            error_summary = (
                f"Sync failed: All {run.fetched_count} fetched records were invalid or rejected during normalization."
            )
        elif rejected_count > 0 and normalized_count > 0:
            final_status = "PARTIAL"
            error_summary = (
                f"Partial sync: {inserted_count} new, {updated_count} updated, {rejected_count} rejected, {skipped_count} skipped."
            )
        elif run.fetched_count == 0:
            final_status = "SUCCESS"
            error_summary = "Feed returned zero records (clean query window)."

        run.finished_at = datetime.now(timezone.utc)
        run.status = final_status
        run.normalized_count = normalized_count
        run.inserted_count = inserted_count
        run.updated_count = updated_count
        run.skipped_count = skipped_count
        run.rejected_count = rejected_count
        run.error_summary = error_summary
        run.diagnostics = {
            "metadata": fetch_result.metadata,
            "rejection_reasons": rejection_reasons,
            "skip_reasons": skip_reasons,
        }

        # 9. Update feed configuration metadata
        feed.last_sync_at = now_utc
        feed.last_status = final_status
        feed.last_error_summary = error_summary
        if final_status in ("SUCCESS", "PARTIAL"):
            feed.last_successful_sync_at = now_utc

        await session.commit()
        if not is_dry_run:
            from waliya.threat_intel.matcher import ThreatIntelMatcher
            ThreatIntelMatcher.clear_cache()

        # 10. Record in tamper-evident SHA-256 audit ledger (if not dry run)
        if not is_dry_run:
            try:
                actor_role = "ADMIN" if "admin" in triggered_by.lower() else "SYSTEM"
                await AuditLedgerService.record_action(
                    session=session,
                    actor_id=triggered_by,
                    action="FEED_SYNC_COMPLETED",
                    target_entity=f"Feed:{feed.feed_id}",
                    payload={
                        "run_id": str(run.id),
                        "feed_id": feed.feed_id,
                        "provider": feed.provider,
                        "status": final_status,
                        "fetched_count": run.fetched_count,
                        "inserted_count": inserted_count,
                        "updated_count": updated_count,
                        "rejected_count": rejected_count,
                        "skipped_count": skipped_count,
                        "is_dry_run": False,
                    },
                    actor_role=actor_role,
                )
                await session.commit()
            except Exception as audit_exc:
                logger.error("Failed recording audit entry for feed sync '%s': %s", feed_id, audit_exc)
                # Audit ledger integrity failure should be raised or logged per project standards
                raise

        if not is_dry_run:
            from waliya.threat_intel.matcher import ThreatIntelMatcher
            ThreatIntelMatcher.clear_cache()

        return run
