"""Integration tests for Incident Management API, correlation pipeline, and risk scoring."""

import json
import uuid
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.contracts import EventTypeEnum, IncidentStatusEnum, SeverityEnum
from waliya.core.crypto import hash_agent_token
from waliya.db.models import AgentModel, EventModel, EventOutboxModel, FindingModel, IncidentModel, RuleModel
from waliya.db.session import async_session_factory
from waliya.detection.builtin_rules import seed_builtin_rules
from waliya.telemetry.consumer_worker import TelemetryConsumerWorker


@pytest_asyncio.fixture
async def incident_agent():
    """Create a verified test agent for incident pipeline tests."""
    agent_id = uuid.uuid4()
    raw_token = f"incident-agent-token-{uuid.uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-sensor-incidents-01",
        os_family="linux",
        os_version="Debian 12 Bookworm",
        primary_ip="192.168.10.45",
        mac_address="00:1B:44:11:3A:B7",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc="enc_secret_placeholder",
    )

    async with async_session_factory() as session:
        session.add(agent)
        await session.commit()

    yield {"id": agent_id, "token": raw_token}

    # Teardown
    async with async_session_factory() as session:
        # Delete findings, outbox, events, incidents, agent
        res = await session.execute(
            select(FindingModel.incident_id).where(FindingModel.agent_id == agent_id)
        )
        inc_ids = [row[0] for row in res.all() if row[0] is not None]

        await session.execute(delete(FindingModel).where(FindingModel.agent_id == agent_id))
        if inc_ids:
            await session.execute(delete(IncidentModel).where(IncidentModel.id.in_(inc_ids)))

        await session.execute(
            delete(EventOutboxModel).where(
                EventOutboxModel.event_id.in_(
                    select(EventModel.id).where(EventModel.agent_id == agent_id)
                )
            )
        )
        await session.execute(delete(EventModel).where(EventModel.agent_id == agent_id))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest.mark.asyncio
async def test_incident_api_authorization(async_client: AsyncClient):
    """Verify that all incident management endpoints enforce strict administrative authentication."""
    fake_id = uuid.uuid4()

    # 1. List incidents
    res_list_no_auth = await async_client.get("/api/v1/incidents")
    assert res_list_no_auth.status_code == 401

    res_list_bad_auth = await async_client.get(
        "/api/v1/incidents",
        headers={"X-Admin-Key": "invalid-token"},
    )
    assert res_list_bad_auth.status_code == 403

    res_list_ok = await async_client.get(
        "/api/v1/incidents",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_list_ok.status_code == 200
    assert isinstance(res_list_ok.json(), list)

    # 2. Get incident by ID (nonexistent)
    res_get_no_auth = await async_client.get(f"/api/v1/incidents/{fake_id}")
    assert res_get_no_auth.status_code == 401

    res_get_404 = await async_client.get(
        f"/api/v1/incidents/{fake_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_get_404.status_code == 404

    # 3. Patch status (nonexistent)
    res_patch_404 = await async_client.patch(
        f"/api/v1/incidents/{fake_id}/status",
        json={"status": "INVESTIGATING", "note": "Initial triage"},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_patch_404.status_code == 404

    # 4. Evidence (nonexistent)
    res_evidence_404 = await async_client.get(
        f"/api/v1/incidents/{fake_id}/evidence",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_evidence_404.status_code == 404

    # 5. Graph (nonexistent)
    res_graph_404 = await async_client.get(
        f"/api/v1/incidents/{fake_id}/graph",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_graph_404.status_code == 404


@pytest.mark.asyncio
async def test_end_to_end_correlation_multi_finding_and_host_separation(
    async_client: AsyncClient,
    incident_agent: dict,
):
    """Verify end-to-end telemetry ingestion -> stream consumer -> correlation into incident.

    Validates:
    - Multiple related findings correlate into a single incident.
    - Risk score aggregates composite factors and MITRE ATT&CK techniques.
    - Unrelated finding on the same host remains in a separate incident.
    - REST API allows querying incident, evidence timeline, graph snapshot, and updating status.
    """
    agent_id = incident_agent["id"]
    token = incident_agent["token"]

    # Ensure builtin rules are seeded
    async with async_session_factory() as session:
        await seed_builtin_rules(session)

    # 1. Initialize consumer worker with dedicated test group
    group_name = f"inc_test_group_{uuid.uuid4().hex[:6]}"
    worker = TelemetryConsumerWorker(
        consumer_name=f"inc_consumer_{uuid.uuid4().hex[:6]}",
        group_name=group_name,
    )
    await worker.init_consumer_group(id="$")

    now_utc = datetime.now(timezone.utc).isoformat()
    ev1_id = uuid.uuid4()
    ev2_id = uuid.uuid4()
    ev_unrelated_id = uuid.uuid4()

    # Event 1: Privilege Escalation by user 'malicious_actor'
    event1 = {
        "event_id": str(ev1_id),
        "event_type": EventTypeEnum.PROCESS_EXECUTION.value,
        "severity": SeverityEnum.HIGH.value,
        "timestamp": now_utc,
        "source": "auditd",
        "agent_id": str(agent_id),
        "payload": {
            "exe": "/usr/bin/sudo",
            "username": "malicious_actor",
            "pid": 4120,
            "cmdline": "sudo -i",
        },
    }

    # Event 2: File integrity modification by user 'malicious_actor' (web shell creation)
    # Notice: shares user 'malicious_actor' and triggers RULE-FIM-004-WEBSHELL
    event2 = {
        "event_id": str(ev2_id),
        "event_type": EventTypeEnum.FILE_INTEGRITY.value,
        "severity": SeverityEnum.HIGH.value,
        "timestamp": now_utc,
        "source": "fim_ebpf",
        "agent_id": str(agent_id),
        "payload": {
            "file_path": "/var/www/html/exploit.php",
            "action": "CREATED",
            "sha256": "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
            "size_bytes": 1024,
            "is_executable": True,
            "user": "malicious_actor",
        },
    }

    # Event 3: Privilege escalation by a COMPLETELY UNRELATED user 'service_daemon' on same host
    event_unrelated = {
        "event_id": str(ev_unrelated_id),
        "event_type": EventTypeEnum.PROCESS_EXECUTION.value,
        "severity": SeverityEnum.HIGH.value,
        "timestamp": now_utc,
        "source": "auditd",
        "agent_id": str(agent_id),
        "payload": {
            "exe": "/usr/bin/pkexec",
            "username": "service_daemon",
            "pid": 9012,
            "cmdline": "pkexec check-update",
        },
    }

    # 2. Ingest batch of telemetry events
    ingest_resp = await async_client.post(
        "/api/v1/telemetry/ingest",
        json={
            "batch_id": str(uuid.uuid4()),
            "agent_id": str(agent_id),
            "events": [event1, event2, event_unrelated],
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert ingest_resp.status_code == 200

    # 3. Run consumer worker to process batch
    processed_count = await worker.process_batch(count=10, block_ms=1000)
    assert processed_count >= 3

    # 4. Verify in DB: Findings created and correlated
    async with async_session_factory() as session:
        f1_res = await session.execute(select(FindingModel).where(FindingModel.event_id == ev1_id))
        f1 = f1_res.scalars().first()
        assert f1 is not None, "Finding for event 1 must exist"

        f2_res = await session.execute(select(FindingModel).where(FindingModel.event_id == ev2_id))
        f2 = f2_res.scalars().first()
        assert f2 is not None, "Finding for event 2 must exist"

        f_unrelated_res = await session.execute(select(FindingModel).where(FindingModel.event_id == ev_unrelated_id))
        f_unrelated = f_unrelated_res.scalars().first()
        assert f_unrelated is not None, "Finding for unrelated event must exist"

        # Verify f1 and f2 are attached to the same correlated incident
        assert f1.incident_id is not None
        assert f2.incident_id is not None
        assert f1.incident_id == f2.incident_id, "Related findings must share the same correlated incident!"

        # Verify f_unrelated is in a SEPARATE incident (host separation invariant)
        assert f_unrelated.incident_id is not None
        assert f_unrelated.incident_id != f1.incident_id, "Unrelated findings on same host must not be merged!"

        primary_incident_id = f1.incident_id

    # 5. Verify GET /api/v1/incidents
    list_resp = await async_client.get(
        "/api/v1/incidents",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert list_resp.status_code == 200
    incidents_list = list_resp.json()
    assert len(incidents_list) >= 2

    matching = next((inc for inc in incidents_list if inc["incident_id"] == str(primary_incident_id)), None)
    assert matching is not None
    assert matching["findings_count"] >= 2
    assert matching["status"] == "OPEN"
    assert matching["composite_risk_score"] > 50.0

    # 6. Verify GET /api/v1/incidents/{incident_id}
    detail_resp = await async_client.get(
        f"/api/v1/incidents/{primary_incident_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["incident_id"] == str(primary_incident_id)
    assert "user:malicious_actor" in detail["affected_entities"]
    # Check MITRE ATT&CK techniques aggregated (T1548.003 + T1505.003)
    assert "T1548.003" in detail["mitre_attack_ids"]
    assert "T1505.003" in detail["mitre_attack_ids"]
    # Explainable risk factor breakdown
    assert "decision_reason" in detail["risk_explanation"]
    assert detail["risk_explanation"]["mitre_attack_count"] >= 2
    assert detail["risk_explanation"]["multi_stage_bonus"] > 0

    # 7. Verify GET /api/v1/incidents/{incident_id}/evidence
    evidence_resp = await async_client.get(
        f"/api/v1/incidents/{primary_incident_id}/evidence",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert evidence_resp.status_code == 200
    evidence = evidence_resp.json()
    assert evidence["incident_id"] == str(primary_incident_id)
    assert len(evidence["timeline"]) >= 2

    # 8. Verify GET /api/v1/incidents/{incident_id}/graph
    graph_resp = await async_client.get(
        f"/api/v1/incidents/{primary_incident_id}/graph",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert graph_data["incident_id"] == str(primary_incident_id)
    assert isinstance(graph_data["nodes"], list)

    # 9. Verify PATCH /api/v1/incidents/{incident_id}/status lifecycle transitions
    # Step A: OPEN -> INVESTIGATING
    patch1_resp = await async_client.patch(
        f"/api/v1/incidents/{primary_incident_id}/status",
        json={"status": "INVESTIGATING", "note": "Security analyst assigned for triage."},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert patch1_resp.status_code == 200
    assert patch1_resp.json()["current_status"] == "INVESTIGATING"

    # Step B: INVESTIGATING -> RESOLVED
    patch2_resp = await async_client.patch(
        f"/api/v1/incidents/{primary_incident_id}/status",
        json={"status": "RESOLVED", "note": "Malicious script deleted, sudo credentials revoked."},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert patch2_resp.status_code == 200
    assert patch2_resp.json()["current_status"] == "RESOLVED"

    # Verify updated detail shows RESOLVED and audit trail in update_history
    detail_after_resp = await async_client.get(
        f"/api/v1/incidents/{primary_incident_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    detail_after = detail_after_resp.json()
    assert detail_after["status"] == "RESOLVED"
    history = detail_after["update_history"]
    assert any(h.get("action") == "STATUS_CHANGED" and h.get("new_status") == "INVESTIGATING" for h in history)
    assert any(h.get("action") == "STATUS_CHANGED" and h.get("new_status") == "RESOLVED" for h in history)

    # 10. Verify Evidence Manifest Integrity and Sealing
    assert evidence["evidence_manifest"]["status"] == "UNSEALED"
    assert evidence["evidence_manifest"]["is_verified"] is False
    assert len(evidence["evidence_manifest"]["items"]) >= 2

    # Seal evidence
    seal_resp = await async_client.post(
        f"/api/v1/incidents/{primary_incident_id}/seal-evidence",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert seal_resp.status_code == 200
    assert seal_resp.json()["status"] == "VERIFIED"
    manifest_hash = seal_resp.json()["manifest_hash"]
    assert manifest_hash is not None

    # After sealing: evidence reports VERIFIED
    evidence_after_seal = await async_client.get(
        f"/api/v1/incidents/{primary_incident_id}/evidence",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert evidence_after_seal.status_code == 200
    ev_data = evidence_after_seal.json()
    assert ev_data["evidence_manifest"]["is_verified"] is True
    assert ev_data["evidence_manifest"]["status"] == "VERIFIED"
    assert ev_data["evidence_manifest"]["stored_hash"] == manifest_hash

    # 11. Verify GET /api/v1/incidents/{incident_id}/export dossier
    export_resp = await async_client.get(
        f"/api/v1/incidents/{primary_incident_id}/export",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert export_resp.status_code == 200
    dossier = export_resp.json()
    assert "Waliya-IR" in dossier["platform"]
    assert dossier["dossier_integrity_hash"] is not None
    assert dossier["incident"]["incident_id"] == str(primary_incident_id)
    assert len(dossier["forensic_timeline"]) >= 2
    assert dossier["evidence_manifest"]["is_verified"] is True


@pytest.mark.asyncio
async def test_incident_filtering_empty_and_tamper_detection(
    async_client: AsyncClient,
    incident_agent: dict,
):
    """Test incident filtering, empty graphs, zero-finding sealing rejection, and tamper detection."""
    agent_id = incident_agent["id"]
    test_inc_id = uuid.uuid4()

    now_utc = datetime.now(timezone.utc)
    dummy_inc = IncidentModel(
        id=test_inc_id,
        incident_number=99999,
        title="Tamper Detection Verification Incident",
        description="Testing evidence integrity verification and tamper detection",
        severity="HIGH",
        status="OPEN",
        composite_risk_score=75.0,
        first_seen=now_utc,
        last_seen=now_utc,
    )

    async with async_session_factory() as session:
        session.add(dummy_inc)
        await session.commit()

    try:
        # 1. Sealing with zero findings fails with 400
        res_seal_empty = await async_client.post(
            f"/api/v1/incidents/{test_inc_id}/seal-evidence",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert res_seal_empty.status_code == 400
        assert "zero associated evidence" in res_seal_empty.json()["detail"]

        # 2. Graph for incident without snapshot returns valid empty GraphSnapshot
        res_graph = await async_client.get(
            f"/api/v1/incidents/{test_inc_id}/graph",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert res_graph.status_code == 200
        graph_data = res_graph.json()
        assert graph_data["nodes"] == []
        assert graph_data["edges"] == []

        # 3. Filter incidents by non-matching status
        res_filter_none = await async_client.get(
            "/api/v1/incidents?status=CLOSED&severity=INFORMATIONAL",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert res_filter_none.status_code == 200
        assert not any(i["incident_id"] == str(test_inc_id) for i in res_filter_none.json())

        # 4. Attach an event and finding
        event_id = uuid.uuid4()
        finding_id = uuid.uuid4()
        test_event = EventModel(
            id=event_id,
            agent_id=agent_id,
            event_type="PROCESS_EXECUTION",
            severity="HIGH",
            timestamp=now_utc,
            source="linux_sensor",
            raw_payload={"pid": 4321, "cmd": "/usr/bin/nc -e /bin/bash"},
            normalized_payload={"pid": 4321, "cmd": "/usr/bin/nc -e /bin/bash"},
        )
        test_finding = FindingModel(
            id=finding_id,
            event_id=event_id,
            agent_id=agent_id,
            incident_id=test_inc_id,
            severity="HIGH",
            confidence=1.0,
            explanation={"rule_name": "Reverse Shell Spawned"},
            timestamp=now_utc,
            dedup_key="nc_revshell",
        )

        async with async_session_factory() as session:
            session.add(test_event)
            session.add(test_finding)
            await session.commit()

        # 5. Seal evidence
        res_seal = await async_client.post(
            f"/api/v1/incidents/{test_inc_id}/seal-evidence",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert res_seal.status_code == 200
        sealed_hash = res_seal.json()["manifest_hash"]

        # Verify evidence status is VERIFIED
        res_ev_verified = await async_client.get(
            f"/api/v1/incidents/{test_inc_id}/evidence",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert res_ev_verified.status_code == 200
        assert res_ev_verified.json()["evidence_manifest"]["is_verified"] is True
        assert res_ev_verified.json()["evidence_manifest"]["status"] == "VERIFIED"

        # 6. Tamper simulation: Alter the underlying normalized event payload in DB
        async with async_session_factory() as session:
            ev_to_tamper = await session.get(EventModel, event_id)
            if ev_to_tamper:
                ev_to_tamper.normalized_payload = {"pid": 4321, "cmd": "/usr/bin/innocent_utility"}
                await session.commit()

        # 7. Check evidence verification detects the tamper
        res_ev_tampered = await async_client.get(
            f"/api/v1/incidents/{test_inc_id}/evidence",
            headers={"X-Admin-Key": settings.ADMIN_API_KEY},
        )
        assert res_ev_tampered.status_code == 200
        tamper_manifest = res_ev_tampered.json()["evidence_manifest"]
        assert tamper_manifest["is_verified"] is False
        assert tamper_manifest["status"] == "TAMPER_DETECTED"
        assert tamper_manifest["stored_hash"] == sealed_hash
        assert tamper_manifest["manifest_hash"] != sealed_hash

    finally:
        # Cleanup
        async with async_session_factory() as session:
            await session.execute(delete(FindingModel).where(FindingModel.incident_id == test_inc_id))
            await session.execute(delete(IncidentModel).where(IncidentModel.id == test_inc_id))
            await session.execute(delete(EventModel).where(EventModel.id == event_id))
            await session.commit()
