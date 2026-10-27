"""System health, liveness, and readiness endpoints."""

from datetime import datetime, timezone
from fastapi import APIRouter, Depends, Response, status
from redis.asyncio import Redis
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.config import settings
from waliya.contracts import (
    LivenessResponse,
    OperationalMetricsResponse,
    ReadinessCheckItem,
    ReadinessResponse,
    SystemDiagnosticsResponse,
)
from waliya.core.auth import verify_auditor_or_admin, verify_viewer_or_above
from waliya.db.session import engine, get_db_session
from waliya.observability.diagnostics_service import OperationalDiagnosticsService
from waliya.observability.metrics import get_metrics_collector

router = APIRouter(prefix="/health", tags=["Health"])


@router.get(
    "",
    response_model=LivenessResponse,
    summary="Application Health Probe",
    include_in_schema=False,
)
@router.get(
    "/liveness",
    response_model=LivenessResponse,
    summary="Application Liveness Probe",
    description="Minimal probe confirming the FastAPI server process is responsive. Does not leak configuration.",
)
async def get_liveness() -> LivenessResponse:
    """Return static up status for container orchestrators and load balancers."""
    return LivenessResponse(
        status="UP",
        timestamp=datetime.now(timezone.utc),
        version="2.0.0",
    )


@router.get(
    "/readiness",
    response_model=ReadinessResponse,
    summary="Application Readiness Probe",
    description="Evaluates downstream connectivity to PostgreSQL and Redis. Returns 503 if dependencies are unreachable.",
)
async def get_readiness(response: Response) -> ReadinessResponse:
    """Check database and redis readiness."""
    checks = {
        "database": ReadinessCheckItem.DISCONNECTED,
        "redis": ReadinessCheckItem.DISCONNECTED,
    }

    # 1. Probe Database Connectivity
    try:
        async with engine.connect() as conn:
            result = await conn.execute(text("SELECT 1"))
            if result.scalar() == 1:
                checks["database"] = ReadinessCheckItem.CONNECTED
    except Exception:
        checks["database"] = ReadinessCheckItem.DISCONNECTED

    # 2. Probe Redis Connectivity
    try:
        from redis.asyncio import Redis
        from waliya.config import settings

        client = Redis.from_url(settings.REDIS_URL, socket_timeout=3.0, socket_connect_timeout=3.0)
        pong = await client.ping()
        await client.aclose()
        if pong:
            checks["redis"] = ReadinessCheckItem.CONNECTED
    except Exception:
        checks["redis"] = ReadinessCheckItem.DISCONNECTED

    # Determine composite readiness
    all_ready = all(val == ReadinessCheckItem.CONNECTED for val in checks.values())

    if not all_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return ReadinessResponse(
            status="NOT_READY",
            timestamp=datetime.now(timezone.utc),
            checks=checks,
        )

    return ReadinessResponse(
        status="READY",
        timestamp=datetime.now(timezone.utc),
        checks=checks,
    )


@router.get(
    "/diagnostics",
    response_model=SystemDiagnosticsResponse,
    summary="Comprehensive Operational Diagnostics",
    description="Administrative diagnostic probe evaluating subsystem health, worker heartbeats, queue lag, and stalled operations.",
)
async def get_system_diagnostics(
    _admin: str = Depends(verify_auditor_or_admin),
    session: AsyncSession = Depends(get_db_session),
) -> SystemDiagnosticsResponse:
    """Collect and return operational diagnostics across all platform services and background workers."""
    redis_client = Redis.from_url(
        settings.REDIS_URL,
        socket_timeout=3.0,
        socket_connect_timeout=3.0,
        decode_responses=True,
    )
    try:
        diagnostics = await OperationalDiagnosticsService.get_system_diagnostics(
            session=session,
            redis=redis_client,
        )
        return diagnostics
    finally:
        await redis_client.aclose()


@router.get(
    "/metrics",
    response_model=OperationalMetricsResponse,
    summary="Operational Performance Metrics",
    description="Administrative operational metrics with strictly bounded cardinality across HTTP requests, ingestion, and delivery pipelines.",
)
async def get_system_metrics(
    _admin: str = Depends(verify_viewer_or_above),
) -> OperationalMetricsResponse:
    """Return in-memory bounded operational metrics."""
    return get_metrics_collector().get_metrics()
