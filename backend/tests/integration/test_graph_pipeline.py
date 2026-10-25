"""Integration tests for correlation graph pipeline, consumer updates, and API endpoints."""

import uuid
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.contracts import EventTypeEnum, SeverityEnum
from waliya.core.crypto import hash_agent_token
from waliya.correlation.graph_engine import EntityGraphManager, get_graph_manager
from waliya.db.models import AgentModel, EventModel, EventOutboxModel, FindingModel
from waliya.db.session import async_session_factory
from waliya.telemetry.consumer_worker import TelemetryConsumerWorker


@pytest_asyncio.fixture
async def graph_test_agent():
    """Create a verified test agent for graph pipeline tests."""
    agent_id = uuid.uuid4()
    raw_token = f"graph-agent-token-{uuid.uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-sensor-graph-01",
        os_family="linux",
        os_version="Ubuntu 24.04 LTS",
        primary_ip="192.168.1.75",
        mac_address="00:1A:2B:3C:4D:75",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc="enc_secret_placeholder",
    )

    async with async_session_factory() as session:
        session.add(agent)
        await session.commit()

    yield {"id": agent_id, "token": raw_token}

    # Cleanup
    async with async_session_factory() as session:
        await session.execute(delete(FindingModel).where(FindingModel.agent_id == agent_id))
        await session.execute(delete(EventOutboxModel).where(
            EventOutboxModel.event_id.in_(
                select(EventModel.id).where(EventModel.agent_id == agent_id)
            )
        ))
        await session.execute(delete(EventModel).where(EventModel.agent_id == agent_id))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest.mark.asyncio
async def test_correlation_endpoints_authorization(async_client: AsyncClient):
    """Verify that correlation API endpoints fail closed without administrative credentials."""
    # 1. Graph snapshot
    resp_snap_no_auth = await async_client.get("/api/v1/correlation/graph")
    assert resp_snap_no_auth.status_code == 401

    resp_snap_bad_auth = await async_client.get(
        "/api/v1/correlation/graph",
        headers={"X-Admin-Key": "wrong-key"},
    )
    assert resp_snap_bad_auth.status_code == 403

    resp_snap_ok = await async_client.get(
        "/api/v1/correlation/graph",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert resp_snap_ok.status_code == 200
    assert "nodes" in resp_snap_ok.json()
    assert "edges" in resp_snap_ok.json()

    # 2. Graph stats
    resp_stats_no_auth = await async_client.get("/api/v1/correlation/stats")
    assert resp_stats_no_auth.status_code == 401

    resp_stats_ok = await async_client.get(
        "/api/v1/correlation/stats",
        headers={"Authorization": f"Bearer {settings.ADMIN_API_KEY}"},
    )
    assert resp_stats_ok.status_code == 200
    assert "node_count" in resp_stats_ok.json()
    assert "edge_count" in resp_stats_ok.json()

    # 3. Graph prune trigger
    resp_prune_no_auth = await async_client.post("/api/v1/correlation/prune")
    assert resp_prune_no_auth.status_code == 401

    resp_prune_ok = await async_client.post(
        "/api/v1/correlation/prune",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert resp_prune_ok.status_code == 200
    assert resp_prune_ok.json()["status"] == "COMPLETED"


@pytest.mark.asyncio
async def test_stream_consumer_updates_correlation_graph(
    async_client: AsyncClient,
    graph_test_agent: dict,
):
    """Verify that validated telemetry consumed by worker automatically populates the correlation graph."""
    agent_id = graph_test_agent["id"]
    token = graph_test_agent["token"]

    event_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc).isoformat()

    # Initialize dedicated consumer group for this test
    test_group = f"grp_graph_{uuid.uuid4().hex[:6]}"
    worker = TelemetryConsumerWorker(
        consumer_name=f"worker_graph_{uuid.uuid4().hex[:6]}",
        group_name=test_group,
    )
    await worker.init_consumer_group(id="$")

    # Ingest Process Execution telemetry
    batch_payload = {
        "batch_id": str(uuid.uuid4()),
        "agent_id": str(agent_id),
        "events": [
            {
                "event_id": str(event_id),
                "event_type": EventTypeEnum.PROCESS_EXECUTION.value,
                "severity": SeverityEnum.INFORMATIONAL.value,
                "timestamp": now_utc,
                "source": "auditd",
                "agent_id": str(agent_id),
                "payload": {
                    "pid": 7712,
                    "ppid": 1,
                    "exe": "/usr/bin/nginx",
                    "username": "www-data",
                    "cmdline": "nginx -g 'daemon off;'",
                },
            }
        ],
    }

    ingest_resp = await async_client.post(
        "/api/v1/telemetry/ingest",
        json=batch_payload,
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ingest_resp.status_code == 200

    # Worker consumes batch and updates the application graph
    try:
        processed = await worker.process_batch(count=5, block_ms=1000)
        assert processed >= 1

        # Query correlation graph API
        graph_resp = await async_client.get(
            "/api/v1/correlation/graph",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert graph_resp.status_code == 200
        graph_data = graph_resp.json()

        node_ids = {n["id"] for n in graph_data["nodes"]}
        expected_host_node = f"host:{agent_id}"
        expected_proc_node = f"process:{agent_id}:7712:nginx"
        expected_user_node = "user:www-data"

        assert expected_host_node in node_ids
        assert expected_proc_node in node_ids
        assert expected_user_node in node_ids

        # Query ego subgraph around the process
        sub_resp = await async_client.get(
            f"/api/v1/correlation/graph?center_node={expected_proc_node}&depth=1",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert sub_resp.status_code == 200
        sub_data = sub_resp.json()
        sub_node_ids = {n["id"] for n in sub_data["nodes"]}
        assert expected_proc_node in sub_node_ids

    finally:
        await worker.close()
