"""Integration tests for SOAR playbooks, secure agent C2 channel, and verified containment."""

import uuid
from uuid import UUID, uuid4
from datetime import datetime, timezone
import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.contracts import (
    CommandEnvelope,
    IncidentStatusEnum,
    ResponseActionEnum,
    ResponseStateEnum,
    SeverityEnum,
)
from waliya.core.crypto import (
    compute_command_signature,
    encrypt_agent_secret,
    hash_agent_token,
    verify_command_signature,
)
from waliya.db.models import (
    AgentModel,
    AuditLedgerModel,
    IncidentModel,
    PlaybookModel,
    PlaybookRunModel,
    ResponseActionModel,
)
from waliya.db.session import async_session_factory
from waliya.soar.playbook_engine import BUILTIN_PLAYBOOKS, seed_builtin_playbooks


@pytest_asyncio.fixture
async def soar_agent():
    """Create a verified test agent with encrypted HMAC signing secret."""
    agent_id = uuid.uuid4()
    raw_token = f"soar-agent-token-{uuid.uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)
    raw_secret = f"agent-hmac-secret-{uuid.uuid4().hex}"
    secret_enc = encrypt_agent_secret(raw_secret, settings.SECRET_KEY)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-sensor-soar-01",
        os_family="linux",
        os_version="Ubuntu 24.04 LTS",
        primary_ip="192.168.100.22",
        mac_address="00:1C:42:AA:BB:CC",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc=secret_enc,
    )

    async with async_session_factory() as session:
        session.add(agent)
        await session.commit()

    yield {
        "id": agent_id,
        "token": raw_token,
        "secret": raw_secret,
    }

    # Teardown
    async with async_session_factory() as session:
        await session.execute(delete(ResponseActionModel).where(ResponseActionModel.agent_id == agent_id))
        await session.execute(delete(PlaybookRunModel).where(PlaybookRunModel.executed_by == "test_admin"))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest_asyncio.fixture
async def active_incident(soar_agent: dict):
    """Create an active security incident for response actions."""
    inc_id = uuid.uuid4()
    now_utc = datetime.now(timezone.utc)
    agent_id = soar_agent["id"]

    incident = IncidentModel(
        id=inc_id,
        title="Active SSH Brute Force Incident",
        description="Multiple failed SSH authentications from external IP",
        severity=SeverityEnum.HIGH.value,
        status=IncidentStatusEnum.OPEN.value,
        composite_risk_score=85.0,
        risk_explanation={"score": 85.0},
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=[f"host:{agent_id}", "user:root", "ip:198.51.100.88"],
        mitre_attack_ids=["T1110.001"],
        update_history=[],
    )

    async with async_session_factory() as session:
        session.add(incident)
        await session.commit()

    yield incident

    # Teardown
    async with async_session_factory() as session:
        await session.execute(delete(ResponseActionModel).where(ResponseActionModel.incident_id == inc_id))
        await session.execute(delete(PlaybookRunModel).where(PlaybookRunModel.incident_id == inc_id))
        await session.execute(delete(IncidentModel).where(IncidentModel.id == inc_id))
        await session.commit()


@pytest.mark.asyncio
async def test_agent_c2_authentication_and_isolation(
    async_client: AsyncClient,
    soar_agent: dict,
):
    """Verify agent task channel requires valid Bearer token and rejects agent cross-impersonation."""
    agent_id = soar_agent["id"]
    token = soar_agent["token"]
    imposter_id = uuid.uuid4()

    # 1. Heartbeat unauthenticated -> 401
    hb_unauth = await async_client.post(f"/api/v1/agents/{agent_id}/heartbeat")
    assert hb_unauth.status_code == 401

    # 2. Heartbeat wrong agent ID -> 403
    hb_imposter = await async_client.post(
        f"/api/v1/agents/{imposter_id}/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert hb_imposter.status_code == 403

    # 3. Heartbeat valid -> 200
    hb_ok = await async_client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert hb_ok.status_code == 200
    assert hb_ok.json()["status"] == "ACK"

    # 4. Poll tasks imposter -> 403
    poll_imposter = await async_client.post(
        f"/api/v1/agents/{imposter_id}/tasks/poll",
        json={"last_sequence": 0},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert poll_imposter.status_code == 403


@pytest.mark.asyncio
async def test_end_to_end_playbook_to_verified_containment(
    async_client: AsyncClient,
    soar_agent: dict,
    active_incident: IncidentModel,
):
    """Demonstrate complete closed-loop SOAR response workflow:

    Playbook Execution -> Pending Approval -> Admin Approval ->
    Agent Polling & HMAC Verification -> Execution Receipt ->
    Inconclusive Verification Check -> Positive OS Verification ->
    Incident Transition to CONTAINED -> Tamper-Evident Audit Ledger Verification.
    """
    agent_id = soar_agent["id"]
    token = soar_agent["token"]
    secret = soar_agent["secret"]
    incident_id = active_incident.id

    # 1. Seed playbooks and select BRUTEFORCE containment playbook
    async with async_session_factory() as session:
        await seed_builtin_playbooks(session)

    playbook_id = UUID("11111111-2222-3333-4444-555555555551")

    # 2. Trigger Playbook Execution
    exec_resp = await async_client.post(
        "/api/v1/soar/playbooks/execute",
        json={
            "playbook_id": str(playbook_id),
            "incident_id": str(incident_id),
            "agent_id": str(agent_id),
            "dry_run": False,
        },
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert exec_resp.status_code == 200
    run_summary = exec_resp.json()
    assert run_summary["status"] == "PENDING_APPROVAL"
    run_id = run_summary["run_id"]

    # 3. Inspect Run Details: Action was created in PENDING_APPROVAL status
    run_detail_resp = await async_client.get(
        f"/api/v1/soar/runs/{run_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert run_detail_resp.status_code == 200
    run_data = run_detail_resp.json()
    assert len(run_data["actions"]) == 1
    action_info = run_data["actions"][0]
    assert action_info["status"] == "PENDING_APPROVAL"
    command_id = action_info["command_id"]

    # 4. Agent polls for tasks while action is PENDING_APPROVAL -> Queue is empty!
    poll_empty_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/tasks/poll",
        json={"last_sequence": 0},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert poll_empty_resp.status_code == 200
    assert poll_empty_resp.json() is None

    # 5. Fetch action DB record ID
    async with async_session_factory() as session:
        act_res = await session.execute(
            select(ResponseActionModel).where(ResponseActionModel.command_id == UUID(command_id))
        )
        action_db = act_res.scalars().first()
        action_db_id = action_db.id

    # 6. Admin Approves the Action
    approve_resp = await async_client.post(
        f"/api/v1/soar/actions/{action_db_id}/approve",
        json={"reason": "Security analyst confirmed malicious SSH brute force source"},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert approve_resp.status_code == 200
    assert approve_resp.json()["status"] == "QUEUED"

    # 7. Agent Heartbeat: notices 1 pending task!
    hb_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/heartbeat",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert hb_resp.status_code == 200
    assert hb_resp.json()["pending_tasks"] == 1

    # 8. Agent Polls: receives signed CommandEnvelope
    poll_task_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/tasks/poll",
        json={"last_sequence": 0},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert poll_task_resp.status_code == 200
    command_envelope = poll_task_resp.json()
    assert command_envelope is not None
    assert command_envelope["command_id"] == command_id
    assert command_envelope["action"] == "BLOCK_IP"
    assert command_envelope["parameters"]["ip_address"] == "198.51.100.88"

    # 9. Cryptographic HMAC Signature Verification on Agent Side
    valid_sig = verify_command_signature(
        received_signature=command_envelope["signature"],
        command_id=UUID(command_envelope["command_id"]),
        agent_id=UUID(command_envelope["agent_id"]),
        action=command_envelope["action"],
        parameters=command_envelope["parameters"],
        sequence=command_envelope["sequence"],
        nonce=UUID(command_envelope["nonce"]),
        issued_at=datetime.fromisoformat(command_envelope["issued_at"]),
        expires_at=datetime.fromisoformat(command_envelope["expires_at"]),
        secret_key=secret,
    )
    assert valid_sig is True, "HMAC-SHA256 signature verification must succeed!"

    # Verify tampering with any parameter fails signature verification
    tampered_sig = verify_command_signature(
        received_signature=command_envelope["signature"],
        command_id=UUID(command_envelope["command_id"]),
        agent_id=UUID(command_envelope["agent_id"]),
        action=command_envelope["action"],
        parameters={"ip_address": "8.8.8.8"},  # Tampered parameter!
        sequence=command_envelope["sequence"],
        nonce=UUID(command_envelope["nonce"]),
        issued_at=datetime.fromisoformat(command_envelope["issued_at"]),
        expires_at=datetime.fromisoformat(command_envelope["expires_at"]),
        secret_key=secret,
    )
    assert tampered_sig is False, "Tampered parameters must fail signature check!"

    # 10. Agent Submits Execution Receipt
    receipt_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/receipts",
        json={
            "command_id": command_id,
            "status": "EXECUTED",
            "exit_code": 0,
            "output": "iptables -I WALIYA_BLOCK -s 198.51.100.88 -j DROP executed",
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert receipt_resp.status_code == 200
    # Crucial: receipt status must be VERIFYING (not contained yet)
    assert receipt_resp.json()["status"] == "VERIFYING"

    # 11. Agent Submits Inconclusive Telemetry Check
    inconclusive_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/verification",
        json={
            "command_id": command_id,
            "observed_state": {
                "firewall_rules": [],  # Empty/missing rule
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert inconclusive_resp.status_code == 200
    assert inconclusive_resp.json()["status"] == "VERIFICATION_INCONCLUSIVE"

    # Verify Incident remains OPEN because verification was inconclusive
    inc_check1 = await async_client.get(
        f"/api/v1/incidents/{incident_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert inc_check1.json()["status"] == "OPEN"

    # 12. Agent Submits Positive Verification Telemetry (Confirmed Kernel Firewall Rule)
    # Note: Transitioning from VERIFYING to VERIFIED_CONTAINED
    verified_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/verification",
        json={
            "command_id": command_id,
            "observed_state": {
                "firewall_rules": [
                    "-A WALIYA_BLOCK -s 198.51.100.88/32 -j DROP",
                ],
            },
        },
        headers={"Authorization": f"Bearer {token}"},
    )
    assert verified_resp.status_code == 200
    assert verified_resp.json()["status"] == "VERIFIED_CONTAINED"

    # 13. Verify Incident Status is now CONTAINED
    inc_check2 = await async_client.get(
        f"/api/v1/incidents/{incident_id}",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert inc_check2.json()["status"] == "CONTAINED"
    history = inc_check2.json()["update_history"]
    assert any(h.get("action") == "INCIDENT_CONTAINED" for h in history)

    # 14. Cryptographically Verify Audit Ledger Chain Integrity
    audit_verify_resp = await async_client.get(
        "/api/v1/soar/audit/verify",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert audit_verify_resp.status_code == 200
    audit_res = audit_verify_resp.json()
    assert audit_res["verified"] is True
    assert audit_res["tamper_detected"] is False
    assert audit_res["total_records"] >= 3


@pytest.mark.asyncio
async def test_unauthorized_action_approval_and_rejection(
    async_client: AsyncClient,
    soar_agent: dict,
    active_incident: IncidentModel,
):
    """Verify security controls around action approvals and rejection."""
    agent_id = soar_agent["id"]
    fake_action_id = uuid4()

    # 1. Approval without admin key -> 401
    appr_no_auth = await async_client.post(
        f"/api/v1/soar/actions/{fake_action_id}/approve",
        json={"reason": "test"},
    )
    assert appr_no_auth.status_code == 401

    # 2. Approval with bad admin key -> 403
    appr_bad_auth = await async_client.post(
        f"/api/v1/soar/actions/{fake_action_id}/approve",
        json={"reason": "test"},
        headers={"X-Admin-Key": "wrong-key"},
    )
    assert appr_bad_auth.status_code == 403

    # 3. Create real action in PENDING_APPROVAL
    async with async_session_factory() as session:
        action = ResponseActionModel(
            id=uuid4(),
            command_id=uuid4(),
            incident_id=active_incident.id,
            agent_id=agent_id,
            action="BLOCK_IP",
            parameters={"ip_address": "198.51.100.222"},
            status=ResponseStateEnum.PENDING_APPROVAL.value,
            sequence=99,
            nonce=uuid4(),
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
            signature="0" * 64,
        )
        session.add(action)
        await session.commit()
        act_id = action.id

    # 4. Reject the action
    reject_resp = await async_client.post(
        f"/api/v1/soar/actions/{act_id}/reject",
        json={"reason": "Analyst determined alert was benign false positive"},
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert reject_resp.status_code == 200
    assert reject_resp.json()["status"] == "REJECTED"


@pytest.mark.asyncio
async def test_expired_command_handling_on_poll(
    async_client: AsyncClient,
    soar_agent: dict,
    active_incident: IncidentModel,
):
    """Verify commands past expiration deadline are transitioned to EXPIRED on poll."""
    agent_id = soar_agent["id"]
    token = soar_agent["token"]

    past_time = datetime(2020, 1, 1, tzinfo=timezone.utc)
    cmd_id = uuid4()

    async with async_session_factory() as session:
        action = ResponseActionModel(
            id=uuid4(),
            command_id=cmd_id,
            incident_id=active_incident.id,
            agent_id=agent_id,
            action="BLOCK_IP",
            parameters={"ip_address": "198.51.100.99"},
            status=ResponseStateEnum.QUEUED.value,
            sequence=100,
            nonce=uuid4(),
            issued_at=past_time,
            expires_at=past_time,  # Already expired!
            signature="0" * 64,
        )
        session.add(action)
        await session.commit()

    # Agent polls for tasks
    poll_resp = await async_client.post(
        f"/api/v1/agents/{agent_id}/tasks/poll",
        json={"last_sequence": 0},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert poll_resp.status_code == 200
    assert poll_resp.json() is None

    # Check that action in DB is now EXPIRED
    async with async_session_factory() as session:
        res = await session.execute(
            select(ResponseActionModel.status).where(ResponseActionModel.command_id == cmd_id)
        )
        status_val = res.scalar()
        assert status_val == ResponseStateEnum.EXPIRED.value


@pytest.mark.asyncio
async def test_soar_actions_runs_and_audit_records_endpoints(
    async_client: AsyncClient,
    soar_agent: dict,
    active_incident: IncidentModel,
):
    """Test REST API retrieval of actions, runs, and audit records."""
    # 1. GET /api/v1/soar/actions
    res_actions = await async_client.get(
        "/api/v1/soar/actions",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_actions.status_code == 200
    actions = res_actions.json()
    assert isinstance(actions, list)

    # 2. Filter actions by status
    res_act_filtered = await async_client.get(
        "/api/v1/soar/actions?status=PENDING_APPROVAL",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_act_filtered.status_code == 200
    for a in res_act_filtered.json():
        assert a["status"] == "PENDING_APPROVAL"

    # 3. GET /api/v1/soar/runs
    res_runs = await async_client.get(
        "/api/v1/soar/runs",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_runs.status_code == 200
    runs = res_runs.json()
    assert isinstance(runs, list)

    # 4. GET /api/v1/soar/audit/records
    res_records = await async_client.get(
        "/api/v1/soar/audit/records",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_records.status_code == 200
    records = res_records.json()
    assert isinstance(records, list)

    # 5. GET /api/v1/agents (authenticated & unauthorized)
    res_agents_unauth = await async_client.get("/api/v1/agents")
    assert res_agents_unauth.status_code == 401

    res_agents = await async_client.get(
        "/api/v1/agents",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_agents.status_code == 200
    agents_list = res_agents.json()
    assert isinstance(agents_list, list)
    assert any(ag["id"] == str(soar_agent["id"]) for ag in agents_list)
