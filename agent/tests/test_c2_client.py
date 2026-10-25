"""Tests for outbound C2 HTTPS client, retries, and error handling."""

from uuid import UUID, uuid4

import httpx
import pytest

from waliya_agent.c2.client import WaliyaC2Client
from waliya_agent.config import ServerConfig


@pytest.mark.asyncio
async def test_c2_client_heartbeat_success(mock_agent_id: UUID):
    """Test successful heartbeat transmission and pending task response."""
    server_conf = ServerConfig(url="http://mock-server:8000", max_retries=1)

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Authorization") == "Bearer test-token-123"
        assert request.headers.get("X-Agent-ID") == str(mock_agent_id)
        assert request.url.path == f"/api/v1/agents/{mock_agent_id}/heartbeat"
        return httpx.Response(200, json={"status": "ACK", "pending_tasks": 2})

    client = WaliyaC2Client(server_config=server_conf, agent_id=mock_agent_id, api_token="test-token-123")
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://mock-server:8000",
        headers=client._client.headers,
    )

    resp = await client.send_heartbeat(
        hostname="test-host",
        primary_ip="192.168.1.50",
        os_version="Linux-6.8",
        agent_version="2.0.0",
        cpu_percent=12.5,
        memory_used_mb=1024,
    )
    assert resp is not None
    assert resp["status"] == "ACK"
    assert resp["pending_tasks"] == 2
    await client.aclose()


@pytest.mark.asyncio
async def test_c2_client_unauthorized_error(mock_agent_id: UUID):
    """Verify that HTTP 401 unauthorized returns None and logs error without crashing."""
    server_conf = ServerConfig(url="http://mock-server:8000", max_retries=0)

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"detail": "Invalid agent credentials"})

    client = WaliyaC2Client(server_config=server_conf, agent_id=mock_agent_id, api_token="bad-token")
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://mock-server:8000",
        headers=client._client.headers,
    )

    resp = await client.send_heartbeat(
        hostname="test-host",
        primary_ip="127.0.0.1",
        os_version="Linux",
        agent_version="2.0.0",
        cpu_percent=0.0,
        memory_used_mb=0,
    )
    assert resp is None
    await client.aclose()


@pytest.mark.asyncio
async def test_c2_client_telemetry_batch_upload(mock_agent_id: UUID):
    """Test telemetry batch upload and receipt acknowledgment."""
    server_conf = ServerConfig(url="http://mock-server:8000", max_retries=1)

    event1_id = str(uuid4())
    event2_id = str(uuid4())
    events = [
        {"event_id": event1_id, "event_type": "PROCESS_EXECUTION", "payload": {"pid": 123}},
        {"event_id": event2_id, "event_type": "FILE_INTEGRITY", "payload": {"file_path": "/tmp/test"}},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/telemetry/ingest"
        return httpx.Response(200, json={"batch_id": str(uuid4()), "processed_count": 2, "status": "QUEUED"})

    client = WaliyaC2Client(server_config=server_conf, agent_id=mock_agent_id, api_token="test-token-123")
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://mock-server:8000",
        headers=client._client.headers,
    )

    success, accepted = await client.upload_telemetry_batch(events)
    assert success is True
    assert accepted == [event1_id, event2_id]
    await client.aclose()


@pytest.mark.asyncio
async def test_c2_client_transient_retry_backoff(mock_agent_id: UUID):
    """Test retry behavior when transient connection failures occur."""
    server_conf = ServerConfig(url="http://mock-server:8000", max_retries=2, retry_backoff_factor=1.0)
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts < 2:
            raise httpx.ConnectError("Connection refused by peer")
        return httpx.Response(200, json={"status": "ACK", "pending_tasks": 0})

    client = WaliyaC2Client(server_config=server_conf, agent_id=mock_agent_id, api_token="test-token")
    client._client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="http://mock-server:8000",
        headers=client._client.headers,
    )

    resp = await client.send_heartbeat(
        hostname="test-host",
        primary_ip="127.0.0.1",
        os_version="Linux",
        agent_version="2.0.0",
        cpu_percent=1.0,
        memory_used_mb=100,
    )
    assert resp is not None
    assert attempts == 2  # Succeeded on 2nd attempt
    await client.aclose()
