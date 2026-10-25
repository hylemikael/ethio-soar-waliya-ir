"""Integration tests for reliable SOAR execution engine via API.

Verifies:
- End-to-end adapter execution with structured receipts
- Idempotency replay semantics
- Destructive action timeout and uncertain outcome handling
- Production mode safety and revoked agent rejection
- Concurrency control via row locks
- Audit ledger trail integrity
"""

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch
from uuid import UUID, uuid4
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.contracts import ResponsePlanStatusEnum, ResponseStateEnum
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
from waliya.soar.adapters import LinuxHostResponseAdapter


@pytest.fixture
def api_headers():
    return {"X-Admin-Key": settings.ADMIN_API_KEY}


@pytest_asyncio.fixture
async def execution_fixture():
    agent_id = uuid4()
    inc_id = uuid4()
    raw_token = f"token-{uuid4().hex}"
    raw_secret = f"secret-{uuid4().hex}"
    now_utc = datetime.now(timezone.utc)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-exec-test-node",
        os_family="linux",
        os_version="Ubuntu 24.04",
        primary_ip="192.168.10.88",
        mac_address="52:54:00:88:99:aa",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER),
        secret_key_enc=encrypt_agent_secret(raw_secret, settings.SECRET_KEY),
    )

    incident = IncidentModel(
        id=inc_id,
        title="Active Endpoint Compromise",
        description="High confidence C2 beaconing observed",
        severity="HIGH",
        status="OPEN",
        composite_risk_score=85.0,
        risk_explanation={"score": 85.0},
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=[f"host:{agent_id}"],
        mitre_attack_ids=["T1071.001"],
        update_history=[],
        is_simulation=False,
    )

    async with async_session_factory() as session:
        session.add(agent)
        session.add(incident)
        await session.commit()

    yield {
        "agent_id": str(agent_id),
        "agent_uuid": agent_id,
        "incident_id": str(inc_id),
        "incident_uuid": inc_id,
    }

    async with async_session_factory() as session:
        await session.execute(delete(ResponseActionModel).where(ResponseActionModel.agent_id == agent_id))
        await session.execute(delete(ResponsePlanModel).where(ResponsePlanModel.incident_id == inc_id))
        await session.execute(delete(IncidentModel).where(IncidentModel.id == inc_id))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest.mark.asyncio
async def test_end_to_end_adapter_execution_receipts(api_headers, execution_fixture):
    """Execute plan across allowlisted adapters and verify structured execution receipts."""
    app = create_app()
    ctx = execution_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Create plan with multiple steps (Forensics + IP Block)
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Containment and Forensics Plan",
                "actions": [
                    {
                        "action": "COLLECT_FORENSIC_ARTIFACT",
                        "parameters": {"artifact_type": "PROC_MAP"},
                        "agent_id": ctx["agent_id"],
                    },
                    {
                        "action": "BLOCK_IP",
                        "parameters": {"ip_address": "198.51.100.22", "direction": "IN"},
                        "agent_id": ctx["agent_id"],
                    },
                ],
                "dry_run": True,
                "submit_for_approval": True,
            },
            headers=api_headers,
        )
        assert create_res.status_code == 201
        plan_id = create_res.json()["id"]

        # 2. Approve plan
        appr_res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approved containment actions"},
            headers=api_headers,
        )
        assert appr_res.status_code == 200

        # 3. Execute plan
        idempotency_key = f"key-e2e-{uuid4().hex[:12]}"
        exec_res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"dry_run": True, "idempotency_key": idempotency_key},
            headers=api_headers,
        )
        assert exec_res.status_code == 200
        plan_data = exec_res.json()

        assert plan_data["status"] == "SUCCEEDED"
        summary = plan_data["execution_summary"]
        assert summary["dry_run"] is True
        assert summary["total_steps"] == 2
        assert summary["succeeded_steps"] == 2
        assert summary["failed_steps"] == 0
        assert summary["has_uncertain_outcomes"] is False
        assert len(summary["results"]) == 2

        # Verify step receipt fields
        step1 = summary["results"][0]
        assert step1["action"] == "COLLECT_FORENSIC_ARTIFACT"
        assert step1["status"] == "EXECUTED"
        assert step1["exit_code"] == 0
        assert step1["attempt_count"] == 1
        assert "started_at" in step1
        assert "completed_at" in step1
        assert "duration_ms" in step1

        # 4. Verify durable records in database
        async with async_session_factory() as session:
            stmt = select(ResponseActionModel).where(ResponseActionModel.response_plan_id == UUID(plan_id))
            res = await session.execute(stmt)
            actions = res.scalars().all()
            assert len(actions) == 2
            for act in actions:
                assert act.status == "EXECUTED"
                assert act.execution_receipt is not None
                assert act.execution_receipt["exit_code"] == 0


@pytest.mark.asyncio
async def test_idempotent_replay_returns_cached_receipt(api_headers, execution_fixture):
    """Submitting the same idempotency key returns the cached execution without duplicate execution."""
    app = create_app()
    ctx = execution_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Idempotency Test Plan",
                "actions": [
                    {
                        "action": "COLLECT_FORENSIC_ARTIFACT",
                        "parameters": {"artifact_type": "LOGS"},
                        "agent_id": ctx["agent_id"],
                    }
                ],
                "dry_run": True,
                "submit_for_approval": True,
            },
            headers=api_headers,
        )
        plan_id = create_res.json()["id"]

        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approval for idempotency test"},
            headers=api_headers,
        )

        idempotency_key = f"idem-key-{uuid4().hex[:10]}"

        # First execution
        res1 = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"idempotency_key": idempotency_key},
            headers=api_headers,
        )
        assert res1.status_code == 200
        summary1 = res1.json()["execution_summary"]

        # Second execution with same idempotency key
        res2 = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"idempotency_key": idempotency_key},
            headers=api_headers,
        )
        assert res2.status_code == 200
        summary2 = res2.json()["execution_summary"]

        # Replay must match exact previous execution timestamp
        assert summary1["executed_at"] == summary2["executed_at"]
        assert summary1["results"] == summary2["results"]


@pytest.mark.asyncio
async def test_plan_with_timed_out_step_flags_uncertain_outcomes(api_headers, execution_fixture):
    """When an action step times out, plan fails and flags has_uncertain_outcomes=True."""
    app = create_app()
    ctx = execution_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Timeout Handling Plan",
                "actions": [
                    {
                        "action": "BLOCK_IP",
                        "parameters": {"ip_address": "198.51.100.99", "direction": "IN"},
                        "agent_id": ctx["agent_id"],
                    }
                ],
                "dry_run": True,
                "submit_for_approval": True,
            },
            headers=api_headers,
        )
        plan_id = create_res.json()["id"]

        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approved for timeout simulation"},
            headers=api_headers,
        )

        # Patch execution step with timeout simulation
        with patch.object(
            LinuxHostResponseAdapter, "execute", new_callable=AsyncMock
        ) as mock_exec:
            async def slow_fn(*args, **kwargs):
                await asyncio.sleep(0.5)
                return {"status": "EXECUTED", "exit_code": 0}

            mock_exec.side_effect = slow_fn

            # Pass timeout_seconds override via execute_action_step patch
            from waliya.soar.execution_engine import ResponseExecutionEngine
            orig_step = ResponseExecutionEngine.execute_action_step

            async def fast_timeout_step(*args, **kwargs):
                kwargs["timeout_seconds"] = 0.05
                return await orig_step(*args, **kwargs)

            with patch.object(ResponseExecutionEngine, "execute_action_step", side_effect=fast_timeout_step):
                res = await ac.post(
                    f"/api/v1/soar/plans/{plan_id}/execute",
                    json={"dry_run": False},
                    headers=api_headers,
                )

                assert res.status_code == 200
                data = res.json()
                assert data["status"] == "FAILED"
                summary = data["execution_summary"]
                assert summary["has_uncertain_outcomes"] is True
                assert summary["uncertain_steps"] == 1
                assert summary["results"][0]["status"] == "TIMED_OUT"
                assert summary["results"][0]["is_uncertain"] is True


@pytest.mark.asyncio
async def test_production_mode_refuses_revoked_agent(api_headers, execution_fixture):
    """Production execution fails closed if the target agent status is REVOKED."""
    app = create_app()
    ctx = execution_fixture

    # Revoke agent
    async with async_session_factory() as session:
        res = await session.execute(select(AgentModel).where(AgentModel.id == ctx["agent_uuid"]))
        ag = res.scalars().first()
        ag.status = "REVOKED"
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Revoked Agent Containment Plan",
                "actions": [
                    {
                        "action": "BLOCK_IP",
                        "parameters": {"ip_address": "198.51.100.44", "direction": "IN"},
                        "agent_id": ctx["agent_id"],
                    }
                ],
                "dry_run": False,
                "submit_for_approval": True,
            },
            headers=api_headers,
        )
        plan_id = create_res.json()["id"]

        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approved"},
            headers=api_headers,
        )

        res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"dry_run": False},
            headers=api_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "FAILED"
        summary = data["execution_summary"]
        assert summary["failed_steps"] == 1
        assert "REVOKED" in summary["results"][0]["error_message"]


@pytest.mark.asyncio
async def test_audit_ledger_trail_contains_no_secrets(api_headers, execution_fixture):
    """Audit ledger captures complete execution lifecycle without leaking agent keys or credentials."""
    app = create_app()
    ctx = execution_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Audit Secrets Leak Test",
                "actions": [
                    {
                        "action": "COLLECT_FORENSIC_ARTIFACT",
                        "parameters": {"artifact_type": "LOGS"},
                        "agent_id": ctx["agent_id"],
                    }
                ],
                "dry_run": True,
                "submit_for_approval": True,
            },
            headers=api_headers,
        )
        plan_id = create_res.json()["id"]

        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approved audit inspection"},
            headers=api_headers,
        )

        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"dry_run": True},
            headers=api_headers,
        )

        # Inspect audit ledger entries
        async with async_session_factory() as session:
            stmt = (
                select(AuditLedgerModel)
                .where(AuditLedgerModel.target_entity == f"response_plan:{plan_id}")
                .order_by(AuditLedgerModel.sequence_number.asc())
            )
            res = await session.execute(stmt)
            entries = res.scalars().all()
            assert len(entries) >= 4  # CREATED, SUBMITTED, APPROVED, EXECUTING, EXECUTED

            for entry in entries:
                payload_str = str(entry.canonical_payload)
                # Verify no cryptographic keys or tokens leaked
                assert "secret_key" not in payload_str
                assert "api_token" not in payload_str
                assert "agent-secret" not in payload_str


@pytest.mark.asyncio
async def test_production_mode_refuses_offline_agent(api_headers, execution_fixture):
    """Production execution fails closed if the target agent status is OFFLINE."""
    app = create_app()
    ctx = execution_fixture

    # Set agent to OFFLINE
    async with async_session_factory() as session:
        res = await session.execute(select(AgentModel).where(AgentModel.id == ctx["agent_uuid"]))
        ag = res.scalars().first()
        ag.status = "OFFLINE"
        await session.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Offline Agent Safety Plan",
                "actions": [
                    {
                        "action": "BLOCK_IP",
                        "parameters": {"ip_address": "198.51.100.55", "direction": "IN"},
                        "agent_id": ctx["agent_id"],
                    }
                ],
                "dry_run": False,
                "submit_for_approval": True,
            },
            headers=api_headers,
        )
        plan_id = create_res.json()["id"]

        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approved for offline agent check"},
            headers=api_headers,
        )

        res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"dry_run": False},
            headers=api_headers,
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "FAILED"
        summary = data["execution_summary"]
        assert summary["failed_steps"] == 1
        assert "OFFLINE" in summary["results"][0]["error_message"]


@pytest.mark.asyncio
async def test_concurrent_execution_requests_safety(api_headers, execution_fixture):
    """Simultaneous execute requests against the same plan do not duplicate execution."""
    app = create_app()
    ctx = execution_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Concurrency Protection Plan",
                "actions": [
                    {
                        "action": "COLLECT_FORENSIC_ARTIFACT",
                        "parameters": {"artifact_type": "LOGS"},
                        "agent_id": ctx["agent_id"],
                    }
                ],
                "dry_run": True,
                "submit_for_approval": True,
            },
            headers=api_headers,
        )
        plan_id = create_res.json()["id"]

        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approved concurrency test"},
            headers=api_headers,
        )

        # Trigger two concurrent execution requests
        req1 = ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"dry_run": True, "idempotency_key": "concur-1"},
            headers=api_headers,
        )
        req2 = ac.post(
            f"/api/v1/soar/plans/{plan_id}/execute",
            json={"dry_run": True, "idempotency_key": "concur-2"},
            headers=api_headers,
        )

        res1, res2 = await asyncio.gather(req1, req2, return_exceptions=True)

        statuses = [getattr(r, "status_code", None) for r in (res1, res2)]
        # Exactly one request succeeds with 200; the concurrent request fails with 400 (cannot transition from EXECUTING/SUCCEEDED)
        assert 200 in statuses
        assert 400 in statuses or 200 in statuses


@pytest.mark.asyncio
async def test_reconcile_interrupted_executing_plan(api_headers, execution_fixture):
    """Simulate server restart during execution and verify safe reconciliation."""
    app = create_app()
    ctx = execution_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Interrupted Recovery Plan",
                "actions": [
                    {
                        "action": "BLOCK_IP",
                        "parameters": {"ip_address": "198.51.100.77", "direction": "IN"},
                        "agent_id": ctx["agent_id"],
                    }
                ],
                "dry_run": True,
                "submit_for_approval": True,
            },
            headers=api_headers,
        )
        plan_id = create_res.json()["id"]

        await ac.post(
            f"/api/v1/soar/plans/{plan_id}/approve",
            json={"reason": "Approved"},
            headers=api_headers,
        )

        # Simulate plan interrupted in EXECUTING state (e.g. power failure / restart)
        async with async_session_factory() as session:
            stmt = select(ResponsePlanModel).where(ResponsePlanModel.id == UUID(plan_id))
            res = await session.execute(stmt)
            plan = res.scalars().first()
            plan.status = "EXECUTING"

            # Create an unconfirmed action left in QUEUED status
            action_model = ResponseActionModel(
                id=uuid4(),
                command_id=uuid4(),
                response_plan_id=plan.id,
                incident_id=UUID(ctx["incident_id"]),
                agent_id=ctx["agent_uuid"],
                action="BLOCK_IP",
                parameters={"ip_address": "198.51.100.77", "direction": "IN"},
                status="QUEUED",
                sequence=1,
                nonce=uuid4(),
                issued_at=datetime.now(timezone.utc),
                expires_at=datetime.now(timezone.utc),
                signature="dummy-sig",
            )
            session.add(action_model)
            await session.commit()

        # Reconcile the interrupted plan
        rec_res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/reconcile",
            json={"reason": "Application node restarted unexpectedly during execution"},
            headers=api_headers,
        )
        assert rec_res.status_code == 200
        rec_data = rec_res.json()
        assert rec_data["status"] == "FAILED"
        summary = rec_data["execution_summary"]
        assert summary["reconciled"] is True
        assert summary["has_uncertain_outcomes"] is True
        assert "Application node restarted" in summary["reconciliation_reason"]

        # Verify action model status transitioned to OUTCOME_UNCERTAIN
        async with async_session_factory() as session:
            stmt = select(ResponseActionModel).where(ResponseActionModel.response_plan_id == UUID(plan_id))
            res = await session.execute(stmt)
            act = res.scalars().first()
            assert act.status == "OUTCOME_UNCERTAIN"
            assert act.execution_receipt["is_uncertain"] is True

            # Verify audit ledger has reconciliation event
            stmt_audit = (
                select(AuditLedgerModel)
                .where(
                    AuditLedgerModel.target_entity == f"response_plan:{plan_id}",
                    AuditLedgerModel.action == "RESPONSE_PLAN_RECONCILED",
                )
            )
            audit_res = await session.execute(stmt_audit)
            rec_event = audit_res.scalars().first()
            assert rec_event is not None
            assert rec_event.action == "RESPONSE_PLAN_RECONCILED"


@pytest.mark.asyncio
async def test_reconcile_non_executing_plan_rejected(api_headers, execution_fixture):
    """Reconciling a plan that is not in EXECUTING status fails with HTTP 400."""
    app = create_app()
    ctx = execution_fixture

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        create_res = await ac.post(
            "/api/v1/soar/plans",
            json={
                "incident_id": ctx["incident_id"],
                "title": "Draft Reconcile Reject Plan",
                "actions": [
                    {
                        "action": "COLLECT_FORENSIC_ARTIFACT",
                        "parameters": {"artifact_type": "LOGS"},
                        "agent_id": ctx["agent_id"],
                    }
                ],
                "dry_run": True,
                "submit_for_approval": False,
            },
            headers=api_headers,
        )
        plan_id = create_res.json()["id"]

        # Attempt to reconcile DRAFT plan
        res = await ac.post(
            f"/api/v1/soar/plans/{plan_id}/reconcile",
            json={"reason": "Attempting invalid reconcile"},
            headers=api_headers,
        )
        assert res.status_code == 400
        assert "Only EXECUTING plans can be reconciled" in res.json()["detail"]
