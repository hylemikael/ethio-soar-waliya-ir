"""Integration tests for health, liveness, and readiness API endpoints."""

from unittest.mock import patch
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_liveness_endpoint_success(async_client: AsyncClient):
    """Verify that liveness endpoint returns 200 OK without exposing secrets."""
    response = await async_client.get("/api/v1/health/liveness")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "UP"
    assert data["version"] == "2.0.0"
    assert "timestamp" in data

    # Ensure no internal secrets or configuration are leaked
    body_str = response.text.lower()
    assert "password" not in body_str
    assert "secret" not in body_str
    assert "database_url" not in body_str


@pytest.mark.asyncio
async def test_readiness_endpoint_all_services_connected(async_client: AsyncClient):
    """Verify readiness returns 200 READY when PostgreSQL and Redis are online."""
    response = await async_client.get("/api/v1/health/readiness")
    data = response.json()

    assert response.status_code == 200
    assert data["status"] == "READY"
    assert "checks" in data
    assert data["checks"]["database"] == "CONNECTED"
    assert data["checks"]["redis"] == "CONNECTED"


@pytest.mark.asyncio
async def test_readiness_endpoint_reports_503_when_service_disconnected(async_client: AsyncClient):
    """Verify readiness returns 503 NOT_READY when a downstream service fails."""
    with patch("waliya.config.settings.REDIS_URL", "redis://:wrong@127.0.0.1:9999/0"):
        response = await async_client.get("/api/v1/health/readiness")
        data = response.json()

        assert response.status_code == 503
        assert data["status"] == "NOT_READY"
        assert data["checks"]["redis"] == "DISCONNECTED"
