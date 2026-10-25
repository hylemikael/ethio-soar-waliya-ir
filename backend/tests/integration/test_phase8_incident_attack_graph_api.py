"""Integration tests for Phase 8: Attack Graph APIs, Incident Reconstruction, and Security Invariants."""

import uuid
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete

from waliya.config import settings
from waliya.contracts import EventTypeEnum, SeverityEnum
from waliya.core.crypto import hash_agent_token
from waliya.correlation.graph_engine import get_graph_manager
from waliya.db.models import AgentModel, EventModel, FindingModel, IncidentModel
from waliya.db.session import async_session_factory
from waliya.incidents.graph_service import IncidentGraphService


@pytest_asyncio.fixture
async def p8_incident_with_events():
    """Create a verified incident with attached findings and events in PostgreSQL."""
    agent_id = uuid.uuid4()
    incident_id = uuid.uuid4()
    event1_id = uuid.uuid4()
    event2_id = uuid.uuid4()
    finding1_id = uuid.uuid4()
    finding2_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    raw_token = f"p8-agent-token-{uuid.uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-p8-sensor-01",
        os_family="linux",
        os_version="Ubuntu 24.04 LTS",
        primary_ip="192.168.1.88",
        mac_address="00:1A:2B:3C:4D:88",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc="enc_secret_placeholder",
    )

    ev1 = EventModel(
        id=event1_id,
        agent_id=agent_id,
        event_type="AUTHENTICATION",
        severity="INFORMATIONAL",
        timestamp=now_utc,
        source="sshd",
        raw_payload={},
        normalized_payload={
            "attributes": {
                "user": "root",
                "src_ip": "198.51.100.99",
                "service": "sshd",
                "status": "SUCCESS",
            }
        },
    )

    ev2 = EventModel(
        id=event2_id,
        agent_id=agent_id,
        event_type="PROCESS_EXECUTION",
        severity="HIGH",
        timestamp=now_utc,
        source="auditd",
        raw_payload={},
        normalized_payload={
            "attributes": {
                "pid": 8810,
                "exe": "/bin/bash",
                "username": "root",
                "cmdline": "bash -i",
            }
        },
    )

    incident = IncidentModel(
        id=incident_id,
        title="Unauthorized Root Access on Host",
        description="Root SSH login followed by interactive shell",
        severity="HIGH",
        status="INVESTIGATING",
        composite_risk_score=78.5,
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=[f"host:{agent_id}", "user:root", "ip:198.51.100.99"],
        mitre_attack_ids=["T1078.003"],
        is_simulation=False,
    )

    f1 = FindingModel(
        id=finding1_id,
        incident_id=incident_id,
        event_id=event1_id,
        agent_id=agent_id,
        severity="INFORMATIONAL",
        confidence=0.9,
        explanation={"rule_name": "SSH Root Login", "rule_id": "RULE-AUTH-001"},
        dedup_key=f"auth:{agent_id}:{event1_id}",
        timestamp=now_utc,
    )

    f2 = FindingModel(
        id=finding2_id,
        incident_id=incident_id,
        event_id=event2_id,
        agent_id=agent_id,
        severity="HIGH",
        confidence=0.95,
        explanation={"rule_name": "Interactive Root Shell", "rule_id": "RULE-PROC-002"},
        dedup_key=f"proc:{agent_id}:{event2_id}",
        timestamp=now_utc,
    )

    async with async_session_factory() as session:
        session.add(agent)
        session.add(ev1)
        session.add(ev2)
        session.add(incident)
        session.add(f1)
        session.add(f2)
        await session.commit()

    yield {
        "incident_id": incident_id,
        "agent_id": agent_id,
        "event1_id": event1_id,
        "event2_id": event2_id,
        "finding1_id": finding1_id,
        "finding2_id": finding2_id,
    }

    # Cleanup
    async with async_session_factory() as session:
        await session.execute(delete(FindingModel).where(FindingModel.incident_id == incident_id))
        await session.execute(delete(IncidentModel).where(IncidentModel.id == incident_id))
        await session.execute(delete(EventModel).where(EventModel.id.in_([event1_id, event2_id])))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest.mark.asyncio
async def test_correlation_attack_paths_and_traversal_api(async_client: AsyncClient):
    """Verify authorization, bounds enforcement, and traversal on correlation API."""
    # 1. Authorization checks
    no_auth_resp = await async_client.get("/api/v1/correlation/attack-paths")
    assert no_auth_resp.status_code == 401

    bad_auth_resp = await async_client.get(
        "/api/v1/correlation/attack-paths",
        headers={"X-Admin-Key": "invalid-key"},
    )
    assert bad_auth_resp.status_code == 403

    # 2. Get attack paths
    ok_resp = await async_client.get(
        "/api/v1/correlation/attack-paths?max_depth=4&max_paths=5",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert ok_resp.status_code == 200
    assert isinstance(ok_resp.json(), list)

    # 3. Parameter bounds validation: max_depth > 6 must be rejected with 422
    invalid_depth = await async_client.get(
        "/api/v1/correlation/attack-paths?max_depth=10",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert invalid_depth.status_code == 422

    # 4. Entity neighbors query on missing entity returns 404
    missing_ent = await async_client.get(
        "/api/v1/correlation/entities/nonexistent:node:123/neighbors",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert missing_ent.status_code == 404

    # 5. Populate an entity in global manager and query neighbors
    mgr = get_graph_manager()
    mgr.graph.add_node("user:admin", entity_type="User", label="admin")
    mgr.graph.add_node("host:jump-01", entity_type="Host", label="jump-01")
    mgr.graph.add_edge("user:admin", "host:jump-01", relation="AUTHENTICATED_TO", weight=1.0)

    nbr_resp = await async_client.get(
        "/api/v1/correlation/entities/user:admin/neighbors",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert nbr_resp.status_code == 200
    nbr_data = nbr_resp.json()
    assert nbr_data["entity"]["id"] == "user:admin"
    assert len(nbr_data["neighbors"]) >= 1


@pytest.mark.asyncio
async def test_incident_attack_graph_reconstruction_and_api(
    async_client: AsyncClient,
    p8_incident_with_events: dict,
):
    """Verify that an incident attack graph is dynamically reconstructed from evidence and exposed via REST."""
    inc_id = p8_incident_with_events["incident_id"]

    # 1. Fetch incident graph via API
    graph_resp = await async_client.get(
        f"/api/v1/incidents/{inc_id}/graph",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()

    assert graph_data["incident_id"] == str(inc_id)
    assert len(graph_data["nodes"]) >= 3
    node_ids = {n["id"] for n in graph_data["nodes"]}
    assert "user:root" in node_ids
    assert "ip:198.51.100.99" in node_ids

    # Edges must contain verified evidence references and provenance
    assert len(graph_data["edges"]) >= 2
    for edge in graph_data["edges"]:
        assert edge["source"] in node_ids
        assert edge["target"] in node_ids
        assert edge["provenance"]
        assert edge["confidence"] > 0.0

    # 2. Query incident attack paths endpoint
    paths_resp = await async_client.get(
        f"/api/v1/incidents/{inc_id}/attack-paths",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert paths_resp.status_code == 200
    paths_data = paths_resp.json()
    assert isinstance(paths_data, list)

    # 3. Trigger manual graph refresh endpoint
    refresh_resp = await async_client.post(
        f"/api/v1/incidents/{inc_id}/graph/refresh",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert refresh_resp.status_code == 200
    refreshed_data = refresh_resp.json()
    assert refreshed_data["incident_id"] == str(inc_id)
    assert len(refreshed_data["nodes"]) >= 3

    # Check incident update history records GRAPH_REBUILT
    detail_resp = await async_client.get(
        f"/api/v1/incidents/{inc_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert detail_resp.status_code == 200
    history = detail_resp.json().get("update_history", [])
    assert any(h.get("action") == "GRAPH_REBUILT" for h in history)


@pytest.mark.asyncio
async def test_simulation_isolation_in_attack_graphs(async_client: AsyncClient):
    """Verify that simulated incidents never mix synthetic entities into production graphs."""
    sim_run_id = f"sim_run_{uuid.uuid4().hex[:8]}"
    sim_inc_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)

    sim_incident = IncidentModel(
        id=sim_inc_id,
        title="[SIMULATION] Web Shell Activity",
        description="Simulated attack path",
        severity="HIGH",
        status="OPEN",
        composite_risk_score=65.0,
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=["sim-sensor-01", "ip:198.51.100.222"],
        is_simulation=True,
        simulation_run_id=sim_run_id,
        entity_graph_snapshot={
            "incident_id": str(sim_inc_id),
            "nodes": [
                {"id": "ip:198.51.100.222", "type": "IPAddress", "label": "198.51.100.222", "properties": {}},
                {"id": "host:sim-sensor-01", "type": "Host", "label": "sim-sensor-01", "properties": {}},
            ],
            "edges": [
                {
                    "source": "ip:198.51.100.222",
                    "target": "host:sim-sensor-01",
                    "relation": "CONNECTED_TO",
                    "weight": 1.0,
                    "confidence": 1.0,
                    "provenance": "simulation",
                }
            ],
            "attack_paths": [],
            "generated_at": now_utc.isoformat(),
            "stats": {},
        },
    )

    async with async_session_factory() as session:
        session.add(sim_incident)
        await session.commit()

    try:
        # Fetch simulation graph
        resp = await async_client.get(
            f"/api/v1/incidents/{sim_inc_id}/graph",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert resp.status_code == 200
        snap = resp.json()
        assert snap["incident_id"] == str(sim_inc_id)
        # Verify all nodes are simulated entities
        for n in snap["nodes"]:
            assert "sim" in n["id"] or "198.51.100" in n["id"]
    finally:
        async with async_session_factory() as session:
            await session.execute(delete(IncidentModel).where(IncidentModel.id == sim_inc_id))
            await session.commit()
