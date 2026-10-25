"""Integration tests for incident reconstruction and cross-layer investigation API."""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4
from httpx import AsyncClient

from waliya.config import settings
from waliya.contracts import SeverityEnum
from waliya.db.models import AgentModel, EventModel, FindingModel, IncidentModel, RuleModel
from waliya.db.session import async_session_factory


@pytest.mark.asyncio
async def test_reconstruction_api_authorization_and_404(async_client: AsyncClient):
    """Verify endpoint authentication enforcement and 404 handling."""
    random_id = uuid4()

    # 1. Reject without auth
    res_no_auth = await async_client.get(f"/api/v1/incidents/{random_id}/reconstruction")
    assert res_no_auth.status_code in (401, 403)

    # 2. Return 404 for non-existent incident
    res_404 = await async_client.get(
        f"/api/v1/incidents/{random_id}/reconstruction",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_404.status_code == 404
    assert f"Incident '{random_id}' not found" in res_404.json()["detail"]


@pytest.mark.asyncio
async def test_reconstruction_api_end_to_end_workflow(async_client: AsyncClient):
    """Verify end-to-end incident reconstruction retrieval with graph, ATT&CK, and timeline."""
    incident_id = uuid4()
    agent_id = uuid4()
    now_utc = datetime.now(timezone.utc)
    ev_id = uuid4()
    rule_id = uuid4()

    async with async_session_factory() as session:
        # Agent
        agent = AgentModel(
            id=agent_id,
            hostname=f"host-recon-api-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Ubuntu 24.04 LTS",
            primary_ip="10.0.8.20",
            mac_address="52:54:00:88:77:66",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"hash-{uuid4().hex}",
            secret_key_enc="enc_secret",
            registered_at=now_utc,
            last_heartbeat=now_utc,
        )
        session.add(agent)

        # Rule
        rule = RuleModel(
            id=rule_id,
            rule_id=f"RULE-RECON-SHELL-{uuid4().hex[:6]}",
            name="Unix Shell Execution",
            description="Detects interactive shell",
            severity="HIGH",
            event_type="PROCESS_EXECUTION",
            conditions=[],
            mitre_attack_ids=["T1059.004"],
            is_active=False,
        )
        session.add(rule)

        # Event
        ev = EventModel(
            id=ev_id,
            agent_id=agent_id,
            event_type="PROCESS_EXECUTION",
            severity="HIGH",
            timestamp=now_utc,
            source="auditd",
            raw_payload={},
            normalized_payload={"attributes": {"exe": "/bin/sh", "username": "www-data"}},
        )
        session.add(ev)

        # Finding
        f = FindingModel(
            id=uuid4(),
            incident_id=incident_id,
            event_id=ev_id,
            rule_id=rule_id,
            severity="HIGH",
            confidence=0.85,
            timestamp=now_utc,
            explanation={"rule_id": rule.rule_id, "mitre_attack_ids": ["T1059.004"]},
            is_simulation=False,
        )
        session.add(f)

        # Incident
        incident = IncidentModel(
            id=incident_id,
            title="Interactive Shell Activity on Web Server",
            description="Integration test incident for reconstruction",
            severity="HIGH",
            status="INVESTIGATING",
            composite_risk_score=80.0,
            first_seen=now_utc,
            last_seen=now_utc,
            affected_entities=[f"host:{agent_id}"],
            is_simulation=False,
        )
        session.add(incident)
        await session.commit()

    # Call reconstruction API
    res = await async_client.get(
        f"/api/v1/incidents/{incident_id}/reconstruction",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["incident_id"] == str(incident_id)
    assert data["incident_title"] == "Interactive Shell Activity on Web Server"
    assert data["severity"] == "HIGH"
    assert len(data["timeline"]) >= 2  # Event + Finding

    # Check that MITRE ATT&CK technique was resolved
    mapped_item = next((it for it in data["timeline"] if it["mitre_techniques"]), None)
    assert mapped_item is not None
    assert mapped_item["mitre_techniques"][0]["technique_id"] == "T1059.004"

    # Check consistency report
    assert data["consistency_report"]["is_consistent"] is True
    assert data["consistency_report"]["checks_run"] == 12

    # Check coverage summary
    assert data["coverage_summary"]["total_observations"] >= 2
    assert data["coverage_summary"]["correlated_findings_count"] == 1
    assert data["coverage_summary"]["chronological_events_count"] == 1

    # Check limitations are present
    assert len(data["limitations"]) > 0


@pytest.mark.asyncio
async def test_reconstruction_api_empty_incident(async_client: AsyncClient):
    """Verify safe handling of an incident with zero findings or events."""
    incident_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    async with async_session_factory() as session:
        incident = IncidentModel(
            id=incident_id,
            title="Empty Incident For Testing",
            description="Testing reconstruction with zero records",
            severity="LOW",
            status="OPEN",
            composite_risk_score=10.0,
            first_seen=now_utc,
            last_seen=now_utc,
            affected_entities=[],
            is_simulation=False,
        )
        session.add(incident)
        await session.commit()

    res = await async_client.get(
        f"/api/v1/incidents/{incident_id}/reconstruction",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res.status_code == 200
    data = res.json()

    assert data["incident_id"] == str(incident_id)
    assert len(data["timeline"]) == 0
    assert data["coverage_summary"]["total_observations"] == 0
    assert data["consistency_report"]["is_consistent"] is True
