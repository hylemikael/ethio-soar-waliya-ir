"""Operational diagnostics service aggregating subsystem health, worker status, backlogs, and stalled workflows."""

import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from redis.asyncio import Redis
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import (
    DependencyHealthItem,
    DependencyHealthStatus,
    OperationalBacklogsSummary,
    StalledOperationsSummary,
    SystemDiagnosticsResponse,
    WorkerHealthItem,
)
from waliya.db.models import (
    EventOutboxModel,
    FeedConfigurationModel,
    FeedSyncRunModel,
    InboundEventDedupModel,
    InboundSourceModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
    ResponseActionModel,
    ResponsePlanModel,
)
from waliya.observability.worker_monitor import get_worker_health_summary

logger = logging.getLogger("waliya.observability.diagnostics_service")

# Monotonic start time of the platform process
_PROCESS_START_TIME = datetime.now(timezone.utc)


class OperationalDiagnosticsService:
    """Aggregates multi-tier operational diagnostics across databases, workers, integrations, and SOAR execution."""

    @staticmethod
    async def get_system_diagnostics(
        session: AsyncSession,
        redis: Redis,
    ) -> SystemDiagnosticsResponse:
        """Collect and synthesize platform health, worker status, backlogs, and stalled workflows."""
        now_utc = datetime.now(timezone.utc)
        uptime_seconds = max(0.0, (now_utc - _PROCESS_START_TIME).total_seconds())

        dependencies: Dict[str, DependencyHealthItem] = {}

        # ----------------------------------------------------------------------
        # 1. Database Health Probe
        # ----------------------------------------------------------------------
        db_start = time.perf_counter()
        try:
            db_res = await session.execute(text("SELECT 1"))
            db_latency = (time.perf_counter() - db_start) * 1000.0
            if db_res.scalar() == 1:
                db_status = (
                    DependencyHealthStatus.DEGRADED
                    if db_latency > 1000.0
                    else DependencyHealthStatus.HEALTHY
                )
                dependencies["database"] = DependencyHealthItem(
                    name="PostgreSQL",
                    status=db_status,
                    latency_ms=round(db_latency, 2),
                    message="Database operational and responsive.",
                )
            else:
                dependencies["database"] = DependencyHealthItem(
                    name="PostgreSQL",
                    status=DependencyHealthStatus.UNHEALTHY,
                    latency_ms=round(db_latency, 2),
                    message="Unexpected response from database probe.",
                )
        except Exception as exc:
            db_latency = (time.perf_counter() - db_start) * 1000.0
            dependencies["database"] = DependencyHealthItem(
                name="PostgreSQL",
                status=DependencyHealthStatus.UNHEALTHY,
                latency_ms=round(db_latency, 2),
                message="Database connectivity failure.",
            )

        # ----------------------------------------------------------------------
        # 2. Redis Health Probe
        # ----------------------------------------------------------------------
        redis_start = time.perf_counter()
        try:
            pong = await redis.ping()
            redis_latency = (time.perf_counter() - redis_start) * 1000.0
            if pong:
                redis_status = (
                    DependencyHealthStatus.DEGRADED
                    if redis_latency > 500.0
                    else DependencyHealthStatus.HEALTHY
                )
                dependencies["redis"] = DependencyHealthItem(
                    name="Redis",
                    status=redis_status,
                    latency_ms=round(redis_latency, 2),
                    message="Redis stream cache operational and responsive.",
                )
            else:
                dependencies["redis"] = DependencyHealthItem(
                    name="Redis",
                    status=DependencyHealthStatus.UNHEALTHY,
                    latency_ms=round(redis_latency, 2),
                    message="Redis ping returned falsy response.",
                )
        except Exception as exc:
            redis_latency = (time.perf_counter() - redis_start) * 1000.0
            dependencies["redis"] = DependencyHealthItem(
                name="Redis",
                status=DependencyHealthStatus.UNHEALTHY,
                latency_ms=round(redis_latency, 2),
                message="Redis connectivity failure.",
            )

        # ----------------------------------------------------------------------
        # 3. Telemetry Worker & Stream Pipeline
        # ----------------------------------------------------------------------
        workers, stream_len, stream_lag, pel_size = await get_worker_health_summary(redis)

        if not workers:
            if stream_len > 0 or stream_lag > 0:
                worker_pipeline_status = DependencyHealthStatus.UNHEALTHY
                worker_msg = "No active consumer workers detected while stream has unprocessed events."
            else:
                worker_pipeline_status = DependencyHealthStatus.UNKNOWN
                worker_msg = "No consumer workers currently registered or active."
        else:
            if any(w.status == DependencyHealthStatus.UNHEALTHY for w in workers):
                worker_pipeline_status = DependencyHealthStatus.UNHEALTHY
                worker_msg = "One or more consumer workers missed heartbeats."
            elif any(w.status == DependencyHealthStatus.DEGRADED for w in workers) or stream_lag > 500:
                worker_pipeline_status = DependencyHealthStatus.DEGRADED
                worker_msg = "Consumer workers reporting lag or delayed heartbeats."
            else:
                worker_pipeline_status = DependencyHealthStatus.HEALTHY
                worker_msg = f"{len(workers)} active consumer worker(s) operating nominally."

        dependencies["telemetry_pipeline"] = DependencyHealthItem(
            name="Telemetry Pipeline",
            status=worker_pipeline_status,
            message=worker_msg,
            details={
                "stream_length": stream_len,
                "consumer_lag": stream_lag,
                "pel_size": pel_size,
                "active_workers_count": len(workers),
            },
        )

        # ----------------------------------------------------------------------
        # 4. Threat Intel Synchronization Status
        # ----------------------------------------------------------------------
        stale_feeds_count = 0
        try:
            feeds_q = select(FeedConfigurationModel).where(FeedConfigurationModel.is_enabled == True)
            feeds_res = await session.execute(feeds_q)
            active_feeds = feeds_res.scalars().all()

            failed_sync_runs_24h_q = (
                select(func.count(FeedSyncRunModel.id))
                .where(FeedSyncRunModel.status == "FAILED")
                .where(FeedSyncRunModel.start_time >= now_utc - timedelta(hours=24))
            )
            failed_sync_runs_cnt = (await session.execute(failed_sync_runs_24h_q)).scalar() or 0

            for feed in active_feeds:
                interval_sec = feed.update_interval_seconds or 3600
                if feed.last_sync_at:
                    stale_cutoff = now_utc - timedelta(seconds=interval_sec * 2)
                    if feed.last_sync_at < stale_cutoff:
                        stale_feeds_count += 1
                elif feed.created_at < now_utc - timedelta(seconds=interval_sec * 2):
                    stale_feeds_count += 1

            if len(active_feeds) == 0:
                ti_status = DependencyHealthStatus.HEALTHY
                ti_msg = "No threat intelligence feeds currently enabled."
            elif stale_feeds_count == len(active_feeds) and len(active_feeds) > 0:
                ti_status = DependencyHealthStatus.UNHEALTHY
                ti_msg = f"All {len(active_feeds)} threat intel feeds are stale or failing sync."
            elif stale_feeds_count > 0 or failed_sync_runs_cnt > 3:
                ti_status = DependencyHealthStatus.DEGRADED
                ti_msg = f"{stale_feeds_count} of {len(active_feeds)} feed(s) stale; {failed_sync_runs_cnt} sync failures in 24h."
            else:
                ti_status = DependencyHealthStatus.HEALTHY
                ti_msg = f"{len(active_feeds)} threat intel feed(s) synchronized and current."

            dependencies["threat_intel"] = DependencyHealthItem(
                name="Threat Intelligence",
                status=ti_status,
                message=ti_msg,
                details={
                    "active_feeds": len(active_feeds),
                    "stale_feeds": stale_feeds_count,
                    "failed_syncs_24h": failed_sync_runs_cnt,
                },
            )
        except Exception as exc:
            logger.warning("Diagnostics failed reading threat intel status: %s", exc)
            dependencies["threat_intel"] = DependencyHealthItem(
                name="Threat Intelligence",
                status=DependencyHealthStatus.UNKNOWN,
                message="Unable to assess threat intelligence feed health.",
            )

        # ----------------------------------------------------------------------
        # 5. Inbound Integrations Status
        # ----------------------------------------------------------------------
        inbound_dedup_count = 0
        try:
            sources_q = select(InboundSourceModel)
            sources_res = await session.execute(sources_q)
            sources = sources_res.scalars().all()

            dedup_cnt_q = select(func.count(InboundEventDedupModel.event_dedup_hash))
            inbound_dedup_count = (await session.execute(dedup_cnt_q)).scalar() or 0

            enabled_sources = [s for s in sources if s.is_enabled]
            degraded_sources = [s for s in enabled_sources if s.status == "DEGRADED" or s.error_count > 10]

            if not enabled_sources:
                inbound_status = DependencyHealthStatus.HEALTHY
                inbound_msg = "No inbound external integration sources configured."
            elif degraded_sources:
                inbound_status = DependencyHealthStatus.DEGRADED
                inbound_msg = f"{len(degraded_sources)} of {len(enabled_sources)} inbound source(s) reporting errors."
            else:
                inbound_status = DependencyHealthStatus.HEALTHY
                inbound_msg = f"{len(enabled_sources)} inbound integration source(s) operational."

            dependencies["inbound_integrations"] = DependencyHealthItem(
                name="Inbound Integrations",
                status=inbound_status,
                message=inbound_msg,
                details={
                    "total_sources": len(sources),
                    "enabled_sources": len(enabled_sources),
                    "degraded_sources": len(degraded_sources),
                    "dedup_cached_events": inbound_dedup_count,
                },
            )
        except Exception as exc:
            logger.warning("Diagnostics failed reading inbound integrations: %s", exc)
            dependencies["inbound_integrations"] = DependencyHealthItem(
                name="Inbound Integrations",
                status=DependencyHealthStatus.UNKNOWN,
                message="Unable to assess inbound integration health.",
            )

        # ----------------------------------------------------------------------
        # 6. Outbound Notifications & Webhooks Status
        # ----------------------------------------------------------------------
        pending_deliveries = 0
        retrying_deliveries = 0
        dead_letter_deliveries = 0
        try:
            dest_cnt_q = select(func.count(NotificationDestinationModel.id)).where(NotificationDestinationModel.is_enabled == True)
            enabled_dests = (await session.execute(dest_cnt_q)).scalar() or 0

            deliv_status_q = select(NotificationDeliveryModel.status, func.count(NotificationDeliveryModel.id)).group_by(NotificationDeliveryModel.status)
            deliv_res = await session.execute(deliv_status_q)
            deliv_map = {str(row[0]): int(row[1]) for row in deliv_res.all()}

            pending_deliveries = deliv_map.get("PENDING", 0) + deliv_map.get("IN_FLIGHT", 0)
            retrying_deliveries = deliv_map.get("RETRYING", 0)
            dead_letter_deliveries = deliv_map.get("DEAD_LETTER", 0)

            if dead_letter_deliveries > 0 or retrying_deliveries > 20:
                outbound_status = DependencyHealthStatus.DEGRADED
                outbound_msg = f"Delivery backlog: {dead_letter_deliveries} dead-lettered, {retrying_deliveries} retrying."
            else:
                outbound_status = DependencyHealthStatus.HEALTHY
                outbound_msg = f"{enabled_dests} outbound destination(s) active, queues healthy."

            dependencies["outbound_notifications"] = DependencyHealthItem(
                name="Outbound Notifications",
                status=outbound_status,
                message=outbound_msg,
                details={
                    "enabled_destinations": enabled_dests,
                    "pending": pending_deliveries,
                    "retrying": retrying_deliveries,
                    "dead_letter": dead_letter_deliveries,
                },
            )
        except Exception as exc:
            logger.warning("Diagnostics failed reading outbound notifications: %s", exc)
            dependencies["outbound_notifications"] = DependencyHealthItem(
                name="Outbound Notifications",
                status=DependencyHealthStatus.UNKNOWN,
                message="Unable to assess outbound notification health.",
            )

        # ----------------------------------------------------------------------
        # 7. Response Execution Engine & Stalled Workflows
        # ----------------------------------------------------------------------
        stalled_plans_cnt = 0
        uncertain_actions_cnt = 0
        stalled_outbox_cnt = 0
        stalled_details: List[Dict[str, Any]] = []

        try:
            # Stalled executing response plans (executing > 15 minutes)
            stalled_plan_cutoff = now_utc - timedelta(minutes=15)
            stalled_plans_q = (
                select(ResponsePlanModel.id, ResponsePlanModel.title, ResponsePlanModel.updated_at)
                .where(ResponsePlanModel.status == "EXECUTING")
                .where(ResponsePlanModel.updated_at < stalled_plan_cutoff)
            )
            stalled_plans_res = await session.execute(stalled_plans_q)
            for row in stalled_plans_res.all():
                stalled_plans_cnt += 1
                stalled_details.append({
                    "type": "STALLED_RESPONSE_PLAN",
                    "id": str(row[0]),
                    "title": row[1],
                    "last_updated": row[2].isoformat() if row[2] else None,
                })

            # Uncertain response actions
            uncertain_actions_q = (
                select(ResponseActionModel.id, ResponseActionModel.action, ResponseActionModel.issued_at)
                .where(ResponseActionModel.status == "OUTCOME_UNCERTAIN")
            )
            uncertain_actions_res = await session.execute(uncertain_actions_q)
            for row in uncertain_actions_res.all():
                uncertain_actions_cnt += 1
                stalled_details.append({
                    "type": "UNCERTAIN_RESPONSE_ACTION",
                    "id": str(row[0]),
                    "action": row[1],
                    "issued_at": row[2].isoformat() if row[2] else None,
                })

            # Stalled event outbox records (pending > 5 minutes)
            stalled_outbox_cutoff = now_utc - timedelta(minutes=5)
            stalled_outbox_q = (
                select(func.count(EventOutboxModel.id))
                .where(EventOutboxModel.status == "PENDING")
                .where(EventOutboxModel.created_at < stalled_outbox_cutoff)
            )
            stalled_outbox_cnt = (await session.execute(stalled_outbox_q)).scalar() or 0
            if stalled_outbox_cnt > 0:
                stalled_details.append({
                    "type": "STALLED_EVENT_OUTBOX",
                    "count": stalled_outbox_cnt,
                    "threshold": "PENDING > 5m",
                })

            if stalled_plans_cnt > 0 or uncertain_actions_cnt > 0 or stalled_outbox_cnt > 0:
                resp_status = DependencyHealthStatus.DEGRADED
                resp_msg = f"Operational attention needed: {stalled_plans_cnt} stalled plan(s), {uncertain_actions_cnt} uncertain action(s)."
            else:
                resp_status = DependencyHealthStatus.HEALTHY
                resp_msg = "Response orchestration engine operating nominally without stalled operations."

            dependencies["response_execution"] = DependencyHealthItem(
                name="Response Execution Engine",
                status=resp_status,
                message=resp_msg,
                details={
                    "stalled_plans": stalled_plans_cnt,
                    "uncertain_actions": uncertain_actions_cnt,
                    "stalled_outbox": stalled_outbox_cnt,
                },
            )
        except Exception as exc:
            logger.warning("Diagnostics failed reading response engine status: %s", exc)
            dependencies["response_execution"] = DependencyHealthItem(
                name="Response Execution Engine",
                status=DependencyHealthStatus.UNKNOWN,
                message="Unable to assess response engine health.",
            )

        # ----------------------------------------------------------------------
        # 8. Composite Health Evaluation
        # ----------------------------------------------------------------------
        dep_statuses = [d.status for d in dependencies.values()]
        if any(s == DependencyHealthStatus.UNHEALTHY for s in dep_statuses):
            composite_status = DependencyHealthStatus.UNHEALTHY
        elif any(s == DependencyHealthStatus.DEGRADED for s in dep_statuses):
            composite_status = DependencyHealthStatus.DEGRADED
        elif any(s == DependencyHealthStatus.UNKNOWN for s in dep_statuses):
            composite_status = DependencyHealthStatus.DEGRADED
        else:
            composite_status = DependencyHealthStatus.HEALTHY

        # ----------------------------------------------------------------------
        # 9. Synthesize Summaries
        # ----------------------------------------------------------------------
        backlogs = OperationalBacklogsSummary(
            telemetry_stream_length=stream_len,
            telemetry_stream_lag=stream_lag,
            telemetry_pel_size=pel_size,
            outbound_notifications_pending=pending_deliveries,
            outbound_notifications_retrying=retrying_deliveries,
            outbound_notifications_dead_letter=dead_letter_deliveries,
            inbound_events_dedup_cached=inbound_dedup_count,
        )

        stalled_summary = StalledOperationsSummary(
            stalled_executing_plans_count=stalled_plans_cnt,
            uncertain_actions_count=uncertain_actions_cnt,
            stalled_outbox_notifications_count=stalled_outbox_cnt,
            stale_threat_intel_feeds_count=stale_feeds_count,
            details=stalled_details if stalled_details else None,
        )

        return SystemDiagnosticsResponse(
            status=composite_status,
            timestamp=now_utc,
            uptime_seconds=round(uptime_seconds, 1),
            dependencies=dependencies,
            telemetry_workers=workers,
            backlogs=backlogs,
            stalled_operations=stalled_summary,
        )


_diagnostics_service = OperationalDiagnosticsService()


def get_diagnostics_service() -> OperationalDiagnosticsService:
    """Retrieve global diagnostics service instance."""
    return _diagnostics_service
