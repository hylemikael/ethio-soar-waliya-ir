"""Integration tests for evidence-backed MITRE ATT&CK coverage API."""

import pytest
from datetime import datetime, timezone
from uuid import uuid4
from httpx import AsyncClient

from waliya.config import settings
from waliya.contracts import MitreMappingStateEnum
from waliya.db.models import AgentModel, EventModel, FindingModel, IncidentModel, RuleModel
from waliya.db.session import async_session_factory


@pytest.mark.asyncio
async def test_mitre_coverage_api_authorization_and_404(async_client: AsyncClient):
    """Verify endpoint authentication enforcement and 404 handling."""
    random_id = uuid4()

    # 1. Reject without admin key
    res_no_auth = await async_client.get(f"/api/v1/incidents/{random_id}/mitre-coverage")
    assert res_no_auth.status_code in (401, 403)

    # 2. Return 404 for non-existent incident
    res_404 = await async_client.get(
        f"/api/v1/incidents/{random_id}/mitre-coverage",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_404.status_code == 404
    assert f"Incident '{random_id}' not found" in res_404.json()["detail"]


@pytest.mark.asyncio
async def test_mitre_coverage_api_evidence_backed_workflow(async_client: AsyncClient):
    """Verify complete end-to-end coverage retrieval with mapped, unmapped, and insufficient evidence."""
    incident_id = uuid4()
    agent_id = uuid4()
    ev_mapped_id = uuid4()
    ev_unmapped_id = uuid4()
    rule_sudo_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    async with async_session_factory() as session:
        # 1. Monitored agent
        agent = AgentModel(
            id=agent_id,
            hostname=f"host-mitre-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Ubuntu 24.04 LTS",
            primary_ip="10.0.10.88",
            mac_address="52:54:00:99:88:77",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"hash-{uuid4().hex}",
            secret_key_enc="enc_secret",
            registered_at=now_utc,
            last_heartbeat=now_utc,
        )
        session.add(agent)

        # 2. Detection Rule
        rule_sudo = RuleModel(
            id=rule_sudo_id,
            rule_id=f"RULE-PROC-SUDO-ELEVATION-{uuid4().hex[:6]}",
            name="Sudo Elevation Privilege Escalation",
            description="Detects unauthorized sudo elevation",
            severity="HIGH",
            event_type="PROCESS_EXECUTION",
            conditions=[],
            mitre_attack_ids=["T1548.003"],
            is_active=False,
        )
        session.add(rule_sudo)

        # 3. Telemetry Events
        ev_mapped = EventModel(
            id=ev_mapped_id,
            agent_id=agent_id,
            event_type="PROCESS_EXECUTION",
            severity="HIGH",
            timestamp=now_utc,
            source="auditd",
            raw_payload={},
            normalized_payload={"attributes": {"exe": "/usr/bin/sudo", "username": "appuser"}},
        )
        ev_unmapped = EventModel(
            id=ev_unmapped_id,
            agent_id=agent_id,
            event_type="PROCESS_EXECUTION",
            severity="MEDIUM",
            timestamp=now_utc,
            source="osquery",
            raw_payload={},
            normalized_payload={"attributes": {"process_count": 450}},
        )
        session.add_all([ev_mapped, ev_unmapped])

        # 4. Incident with T1548.003 and unbacked T1078.003 in metadata
        incident = IncidentModel(
            id=incident_id,
            title="Adversary Privilege Escalation Campaign",
            description="Multi-stage behavioral incident",
            severity="HIGH",
            status="INVESTIGATING",
            composite_risk_score=85.0,
            affected_entities=[f"host:{agent_id}", "user:appuser"],
            mitre_attack_ids=["T1548.003", "T1078.003"],
        )
        session.add(incident)

        # 5. Finding 1: Mapped (Sudo Abuse)
        f_mapped = FindingModel(
            id=uuid4(),
            rule_id=rule_sudo_id,
            event_id=ev_mapped_id,
            agent_id=agent_id,
            incident_id=incident_id,
            severity="HIGH",
            confidence=0.92,
            explanation={
                "name": "Sudo Privilege Elevation",
                "mitre_attack_ids": ["T1548.003"],
            },
            timestamp=now_utc,
        )

        # 6. Finding 2: Unmapped (Anomaly Heuristic)
        f_unmapped = FindingModel(
            id=uuid4(),
            rule_id=None,
            event_id=ev_unmapped_id,
            agent_id=agent_id,
            incident_id=incident_id,
            severity="MEDIUM",
            confidence=0.65,
            explanation={
                "rule_id": "HEURISTIC-PROC-SPIKE",
                "name": "Statistical Baseline Outlier",
            },
            timestamp=now_utc,
        )
        session.add_all([f_mapped, f_unmapped])
        await session.commit()

    # 7. Request MITRE coverage through API
    resp = await async_client.get(
        f"/api/v1/incidents/{incident_id}/mitre-coverage",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert resp.status_code == 200
    data = resp.json()

    # 8. Assert coverage response structure
    assert data["incident_id"] == str(incident_id)
    assert data["catalog_version"] == "v15.1"
    assert data["distinct_techniques_count"] == 2
    assert data["mapped_findings_count"] == 1
    assert data["unmapped_findings_count"] == 1
    assert data["insufficient_evidence_count"] == 1

    # Verify techniques array
    techniques = {t["technique_id"]: t for t in data["techniques"]}
    assert "T1548.003" in techniques
    assert "T1078.003" in techniques

    t_sudo = techniques["T1548.003"]
    assert t_sudo["mapping_state"] == "MAPPED"
    assert t_sudo["confidence"] == 92
    assert str(ev_mapped_id) in t_sudo["evidence_event_ids"]
    assert "auditd" in t_sudo["rationale"]

    t_valid = techniques["T1078.003"]
    assert t_valid["mapping_state"] == "INSUFFICIENT_EVIDENCE"
    assert len(t_valid["evidence_event_ids"]) == 0
    assert "not supported by any finding" in t_valid["rationale"]

    # Verify tactics breakdown
    assert "Privilege Escalation" in data["tactics"]
    priv_esc = [t["technique_id"] for t in data["tactics"]["Privilege Escalation"]]
    assert "T1548.003" in priv_esc

    # Verify unmapped findings
    assert len(data["unmapped_findings"]) == 1
    unmapped = data["unmapped_findings"][0]
    assert unmapped["rule_id"] == "HEURISTIC-PROC-SPIKE"
    assert "heuristic" in unmapped["reason"].lower()

    # Verify limitations disclosure
    assert len(data["limitations"]) >= 4
