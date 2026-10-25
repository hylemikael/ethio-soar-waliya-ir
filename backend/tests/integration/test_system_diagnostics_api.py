"""Integration tests for operational diagnostics, health monitoring, and bounded metrics APIs."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.config import settings
from waliya.contracts import DependencyHealthStatus
from waliya.db.models import (
    AgentModel,
    EventModel,
    IncidentModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
    ResponseActionModel,
    utc_now,
)


@pytest.mark.asyncio
async def test_diagnostics_endpoint_unauthorized(async_client: AsyncClient):
    """Verify diagnostics endpoint rejects unauthenticated requests with 401 or 403."""
    res = await async_client.get("/api/v1/health/diagnostics")
    assert res.status_code in (401, 403)


@pytest.mark.asyncio
async def test_metrics_endpoint_unauthorized(async_client: AsyncClient):
    """Verify metrics endpoint rejects unauthenticated requests with 401 or 403."""
    res = await async_client.get("/api/v1/health/metrics")
    assert res.status_code in (401, 403)


@pytest.mark.asyncio
async def test_diagnostics_endpoint_authorized_nominal(async_client: AsyncClient):
    """Verify diagnostics returns structured health, queues, and latency without leaking secrets."""
    headers = {"X-Admin-Key": settings.ADMIN_API_KEY}
    res = await async_client.get("/api/v1/health/diagnostics", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # Validate composite status and uptime
    assert data["status"] in ["HEALTHY", "DEGRADED", "UNHEALTHY"]
    assert "uptime_seconds" in data
    assert data["uptime_seconds"] >= 0

    # Validate core dependencies
    deps = data["dependencies"]
    assert "database" in deps
    assert "redis" in deps
    assert "telemetry_pipeline" in deps
    assert "threat_intel" in deps
    assert "inbound_integrations" in deps
    assert "outbound_notifications" in deps
    assert "response_execution" in deps

    assert deps["database"]["status"] in ["HEALTHY", "DEGRADED"]
    assert deps["database"]["latency_ms"] is not None
    assert deps["redis"]["status"] in ["HEALTHY", "DEGRADED"]
    assert deps["redis"]["latency_ms"] is not None

    # Validate backlogs schema
    backlogs = data["backlogs"]
    assert "telemetry_stream_length" in backlogs
    assert "telemetry_stream_lag" in backlogs
    assert "telemetry_pel_size" in backlogs
    assert "outbound_notifications_pending" in backlogs
    assert "outbound_notifications_retrying" in backlogs
    assert "outbound_notifications_dead_letter" in backlogs
    assert "inbound_events_dedup_cached" in backlogs

    # Validate stalled operations schema
    stalled = data["stalled_operations"]
    assert "stalled_executing_plans_count" in stalled
    assert "uncertain_actions_count" in stalled
    assert "stalled_outbox_notifications_count" in stalled
    assert "stale_threat_intel_feeds_count" in stalled

    # Security check: verify no credentials or secrets leaked
    body_str = res.text.lower()
    assert "password" not in body_str
    assert "secret_key" not in body_str
    assert "database_url" not in body_str
    assert settings.ADMIN_API_KEY.lower() not in body_str


@pytest.mark.asyncio
async def test_diagnostics_detects_uncertain_actions_as_degraded(
    async_client: AsyncClient,
    db_session: AsyncSession,
):
    """Verify diagnostics detects uncertain response actions and flags response engine as DEGRADED."""
    # 1. Create a minimal agent and incident
    agent = AgentModel(
        hostname="test-diag-host",
        os_family="linux",
        os_version="Ubuntu 24.04",
        primary_ip="10.0.0.99",
        mac_address="00:11:22:33:44:55",
        agent_version="2.0.0",
        api_token_hash=f"hash_{uuid4().hex}",
        secret_key_enc="enc_secret_key",
        status="ONLINE",
    )
    db_session.add(agent)
    await db_session.flush()

    incident = IncidentModel(
        title="Test Incident for Diagnostics",
        description="Testing diagnostics",
        status="INVESTIGATING",
        severity="HIGH",
        composite_risk_score=75.0,
    )
    db_session.add(incident)
    await db_session.flush()

    # 2. Add an action with OUTCOME_UNCERTAIN
    uncertain_action = ResponseActionModel(
        incident_id=incident.id,
        agent_id=agent.id,
        action="ISOLATE_HOST",
        parameters={"duration_seconds": 300},
        status="OUTCOME_UNCERTAIN",
        sequence=1,
        issued_at=utc_now(),
        expires_at=utc_now(),
        signature="test_sig",
    )
    db_session.add(uncertain_action)
    await db_session.commit()

    # 3. Call diagnostics
    headers = {"X-Admin-Key": settings.ADMIN_API_KEY}
    res = await async_client.get("/api/v1/health/diagnostics", headers=headers)
    assert res.status_code == 200
    data = res.json()

    # 4. Verify detection
    stalled = data["stalled_operations"]
    assert stalled["uncertain_actions_count"] >= 1
    assert data["dependencies"]["response_execution"]["status"] == "DEGRADED"

    # Cleanup test data to prevent state pollution across test suite
    await db_session.delete(uncertain_action)
    await db_session.delete(incident)
    await db_session.delete(agent)
    await db_session.commit()


@pytest.mark.asyncio
async def test_metrics_endpoint_authorized(async_client: AsyncClient):
    """Verify metrics returns bounded counters for HTTP requests and event pipelines."""
    # Generate some HTTP traffic
    await async_client.get("/api/v1/health/liveness")
    await async_client.get("/api/v1/health/readiness")

    headers = {"X-Admin-Key": settings.ADMIN_API_KEY}
    res = await async_client.get("/api/v1/health/metrics", headers=headers)
    assert res.status_code == 200
    data = res.json()

    assert "http_requests_total" in data
    assert "avg_request_duration_ms" in data
    assert "telemetry_processed_total" in data
    assert "telemetry_errors_total" in data
    assert "inbound_events_total" in data
    assert "outbound_deliveries_total" in data

    # Verify bounded label cardinality (no arbitrary URLs or query strings)
    for key in data["http_requests_total"].keys():
        assert "_" in key
        assert any(key.endswith(f"_{cls}xx") for cls in [1, 2, 3, 4, 5])


@pytest.mark.asyncio
async def test_correlation_header_in_responses(async_client: AsyncClient):
    """Verify every HTTP response returns X-Request-ID, honoring custom or generating new."""
    # 1. Without header -> generated req_
    res1 = await async_client.get("/api/v1/health/liveness")
    assert res1.status_code == 200
    assert "X-Request-ID" in res1.headers
    assert res1.headers["X-Request-ID"].startswith("req_")

    # 2. With valid custom header -> echoed
    custom_trace = "trace-secops-98765"
    res2 = await async_client.get(
        "/api/v1/health/liveness",
        headers={"X-Request-ID": custom_trace},
    )
    assert res2.status_code == 200
    assert res2.headers["X-Request-ID"] == custom_trace
