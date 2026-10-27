"""Integration tests for SOAR governed response plans API endpoints and audit ledger integration."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.contracts import (
    ActionRiskClassificationEnum,
    ResponseActionEnum,
    ResponsePlanStatusEnum,
)
from waliya.core.crypto import encrypt_agent_secret, hash_agent_token
from waliya.db.models import (
    AgentModel,
    AuditLedgerModel,
    IncidentModel,
    ResponseActionModel,
    ResponsePlanModel,
)
from waliya.db.session import async_session_factory
from waliya.main import create_app


@pytest.fixture
def api_headers():
    return {"X-Admin-Key": settings.ADMIN_API_KEY}


@pytest_asyncio.fixture
async def plan_fixture():
    """Create agent and incident fixtures for API tests."""
    agent_id = uuid4()
    inc_id = uuid4()
    raw_token = f"agent-token-{uuid4().hex}"
    raw_secret = f"agent-secret-{uuid4().hex}"
    now_utc = datetime.now(timezone.utc)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-api-test-agent",
        os_family="linux",
        os_version="Ubuntu 24.04",
        primary_ip="192.168.10.15",
        mac_address="52:54:00:12:34:56",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER),
        secret_key_enc=encrypt_agent_secret(raw_secret, settings.SECRET_KEY),
    )

    incident = IncidentModel(
        id=inc_id,
        title="Command Injection via Webhook",
        description="Detected anomalous curl process spawned by web application",
        severity="CRITICAL",
        status="OPEN",
        composite_risk_score=90.0,
        risk_explanation={"score": 90.0},
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=[f"host:{agent_id}", "user:www-data"],
        mitre_attack_ids=["T1059.004"],
        update_history=[],
        is_simulation=False,
    )

    async with async_session_factory() as session:
        session.add(agent)
        session.add(incident)
        await session.commit()

    yield {
        "agent_id": str(agent_id),
        "incident_id": str(inc_id),
        "incident_uuid": inc_id,
    }

    # Teardown
    async with async_session_factory() as session:
        await session.execute(delete(ResponseActionModel).where(ResponseActionModel.agent_id == agent_id))
        await session.execute(delete(ResponsePlanModel).where(ResponsePlanModel.incident_id == inc_id))
        await session.execute(delete(IncidentModel).where(IncidentModel.id == inc_id))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest.mark.asyncio
async def test_action_registry_endpoint(api_headers):
    """Verify action registry endpoint returns all 7 allowlisted actions and enforces authorization."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Unauthorized requests
        res = await ac.get("/api/v1/soar/actions/registry")
        assert res.status_code == 401

        res = await ac.get("/api/v1/soar/actions/registry", headers={"X-Admin-Key": "invalid-key"})
        assert res.status_code == 403

        # Authorized request
        res = await ac.get("/api/v1/soar/actions/registry", headers=api_headers)
        assert res.status_code == 200
        data = res.json()
        assert len(data) == 8

        action_names = {entry["action_type"] for entry in data}
        expected_actions = {
            "BLOCK_IP",
            "UNBLOCK_IP",
            "ISOLATE_HOST",
            "RESTORE_HOST",
            "TERMINATE_PROCESS",
            "QUARANTINE_FILE",
            "COLLECT_FORENSIC_ARTIFACT",
            "RECOVER_WEBSITE_FILE",
        }
        assert action_names == expected_actions

        # Verify entry schema
        first_entry = data[0]
        assert "risk_classification" in first_entry
        assert "default_requires_approval" in first_entry
        assert "default_timeout_seconds" in first_entry
        assert "parameter_fields" in first_entry


@pytest.mark.asyncio
async def test_response_plan_end_to_end_api_lifecycle(api_headers, plan_fixture):
    """Verify complete plan lifecycle via REST API: Create -> List -> Submit -> Approve -> Execute."""
    app = create_app()
    ctx = plan_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Create Response Plan
        create_payload = {
            "incident_id": ctx["incident_id"],
            "title": "API Test Containment Plan",
            "description": "Block attacker IP and terminate compromised process",
            "actions": [
                {
                    "action": "BLOCK_IP",
                    "parameters": {"ip_address": "198.51.100.11", "direction": "BOTH"},
                    "agent_id": ctx["agent_id"],
                    "requires_approval": True,
                },
                {
                    "action": "TERMINATE_PROCESS",
                    "parameters": {"pid": 2048, "process_name": "curl", "kill_tree": False},
                    "agent_id": ctx["agent_id"],
                    "requires_approval": True,
                },
            ],
            "dry_run": True,
            "submit_for_approval": False,
        }

        res = await ac.post("/api/v1/soar/plans", json=create_payload, headers=api_headers)
        assert res.status_code == 201
        plan_data = res.json()
        plan_id = plan_data["id"]
        assert plan_data["title"] == "API Test Containment Plan"
        assert plan_data["status"] == "DRAFT"
        assert plan_data["risk_level"] == "DESTRUCTIVE"
        assert plan_data["requires_approval"] is True
        assert len(plan_data["actions"]) == 2

        # 2. List Response Plans
        res = await ac.get("/api/v1/soar/plans", headers=api_headers)
        assert res.status_code == 200
        plans_list = res.json()
        assert any(p["id"] == plan_id for p in plans_list)

        # 3. Get Plan Details
        res = await ac.get(f"/api/v1/soar/plans/{plan_id}", headers=api_headers)
        assert res.status_code == 200
        assert res.json()["id"] == plan_id

        # 4. Submit Plan for Approval
        res = await ac.post(f"/api/v1/soar/plans/{plan_id}/submit", headers=api_headers)
        assert res.status_code == 200
        submitted_data = res.json()
        assert submitted_data["status"] == "PENDING_APPROVAL"
        assert submitted_data["approval_hash"] is not None

        # 5. Approve Plan
        approval_payload = {"reason": "Verified malicious outbound connection in packet logs"}
        res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json=approval_payload,
            headers=api_headers,
        )
        assert res.status_code == 200
        approved_data = res.json()
        assert approved_data["status"] == "APPROVED"
        assert approved_data["approved_by"] is not None
        assert approved_data["approval_reason"] == approval_payload["reason"]

        # 6. Execute Plan
        exec_payload = {"dry_run": True, "idempotency_key": f"key-{plan_id[:8]}"}
        res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json=exec_payload,
            headers=api_headers,
        )
        assert res.status_code == 200
        executed_data = res.json()
        assert executed_data["status"] == "SUCCEEDED"
        assert executed_data["execution_summary"] is not None
        assert len(executed_data["execution_summary"]["results"]) == 2

        # Verify audit ledger has tamper-evident records
        async with async_session_factory() as session:
            stmt = (
                select(AuditLedgerModel)
                .where(AuditLedgerModel.target_entity == f"response_plan:{plan_id}")
                .order_by(AuditLedgerModel.sequence_number.asc())
            )
            audit_res = await session.execute(stmt)
            audit_rows = audit_res.scalars().all()
            actions_logged = [r.action for r in audit_rows]
            assert "RESPONSE_PLAN_CREATED" in actions_logged
            assert "RESPONSE_PLAN_SUBMITTED" in actions_logged
            assert "RESPONSE_PLAN_APPROVED" in actions_logged
            assert "RESPONSE_PLAN_EXECUTING" in actions_logged
            assert "RESPONSE_PLAN_EXECUTED" in actions_logged


@pytest.mark.asyncio
async def test_response_plan_rejection_and_cancellation_api(api_headers, plan_fixture):
    """Verify rejection of pending plans and cancellation of draft plans."""
    app = create_app()
    ctx = plan_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Create plan submitted immediately
        payload = {
            "incident_id": ctx["incident_id"],
            "title": "Rejection Test Plan",
            "actions": [
                {
                    "action": "COLLECT_FORENSIC_ARTIFACT",
                    "parameters": {"artifact_type": "LOGS"},
                    "agent_id": ctx["agent_id"],
                    "requires_approval": False,
                }
            ],
            "dry_run": True,
            "submit_for_approval": True,
        }
        res = await ac.post("/api/v1/soar/plans", json=payload, headers=api_headers)
        assert res.status_code == 201
        plan_id = res.json()["id"]

        # Reject plan
        rejection_payload = {"reason": "Insufficient evidence to warrant host disruption"}
        res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/reject",
            json=rejection_payload,
            headers=api_headers,
        )
        assert res.status_code == 200
        assert res.json()["status"] == "REJECTED"
        assert res.json()["rejection_reason"] == rejection_payload["reason"]

        # Create another plan in DRAFT and cancel it
        payload["submit_for_approval"] = False
        res = await ac.post("/api/v1/soar/plans", json=payload, headers=api_headers)
        plan_id_2 = res.json()["id"]

        cancel_payload = {"reason": "Analyst withdrew plan"}
        res = await ac.post(
            f"/api/v1/soar/plans/{plan_id_2}/cancel",
            json=cancel_payload,
            headers=api_headers,
        )
        assert res.status_code == 200
        assert res.json()["status"] == "CANCELLED"
        assert res.json()["cancellation_reason"] == cancel_payload["reason"]


@pytest.mark.asyncio
async def test_unapproved_plan_execution_fails_api(api_headers, plan_fixture):
    """Verify execution of unapproved plans fails with HTTP 400."""
    app = create_app()
    ctx = plan_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        payload = {
            "incident_id": ctx["incident_id"],
            "title": "Unapproved Execution Plan",
            "actions": [
                {
                    "action": "COLLECT_FORENSIC_ARTIFACT",
                    "parameters": {"artifact_type": "LOGS"},
                    "agent_id": ctx["agent_id"],
                }
            ],
            "dry_run": True,
            "submit_for_approval": False,
        }
        res = await ac.post("/api/v1/soar/plans", json=payload, headers=api_headers)
        plan_id = res.json()["id"]

        # Attempt to execute while still in DRAFT
        res = await ac.post(f"/api/v1/soar/plans/{plan_id}/execute", json={}, headers=api_headers)
        assert res.status_code == 400
        assert "Cannot transition response plan from DRAFT to EXECUTING" in res.json()["detail"]


@pytest.mark.asyncio
async def test_simulation_incident_live_override_api(api_headers, plan_fixture):
    """Verify simulation incident forcibly constrains execution to dry_run=True."""
    app = create_app()
    ctx = plan_fixture

    # Update incident to simulation
    async with async_session_factory() as session:
        res = await session.execute(select(IncidentModel).where(IncidentModel.id == ctx["incident_uuid"]))
        inc = res.scalars().first()
        inc.is_simulation = True
        inc.simulation_run_id = "sim-api-789"
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        payload = {
            "incident_id": ctx["incident_id"],
            "title": "Simulation Safety Plan",
            "actions": [
                {
                    "action": "COLLECT_FORENSIC_ARTIFACT",
                    "parameters": {"artifact_type": "LOGS"},
                    "agent_id": ctx["agent_id"],
                }
            ],
            "dry_run": False,  # Requesting live mode
            "submit_for_approval": True,
        }
        res = await ac.post("/api/v1/soar/plans", json=payload, headers=api_headers)
        plan_id = res.json()["id"]

        # Approve
        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approved simulation run"},
            headers=api_headers,
        )

        # Execute requesting live mode
        res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"dry_run": False},
            headers=api_headers,
        )
        assert res.status_code == 200
        data = res.json()
        # Enforced dry_run=True
        assert data["dry_run"] is True
        assert data["is_simulation"] is True
        assert data["status"] == "SUCCEEDED"
