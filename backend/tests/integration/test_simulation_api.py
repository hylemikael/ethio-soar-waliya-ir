"""Integration tests for Purple-Team Simulation Runs and Coverage APIs."""

from datetime import datetime, timezone
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import delete

from waliya.config import settings
from waliya.core.crypto import hash_agent_token
from waliya.db.models import AgentModel, FindingModel, IncidentModel, RuleModel, SimulationRunModel
from waliya.db.session import async_session_factory


@pytest.mark.asyncio
async def test_simulation_endpoints_authorization(async_client: AsyncClient):
    """Verify that all simulation endpoints require administrative authorization."""
    # 1. Register run
    resp_reg_no_auth = await async_client.post("/api/v1/simulations/runs", json={
        "run_id": "sim-auth-test-1",
        "trace_id": "trace-auth-test-1",
        "scenario_id": "web-shell",
        "scenario_name": "Web Shell",
        "target_rule_id": "RULE-FIM-004-WEBSHELL",
    })
    assert resp_reg_no_auth.status_code == 401

    resp_reg_bad_auth = await async_client.post(
        "/api/v1/simulations/runs",
        json={
            "run_id": "sim-auth-test-1",
            "trace_id": "trace-auth-test-1",
            "scenario_id": "web-shell",
            "scenario_name": "Web Shell",
            "target_rule_id": "RULE-FIM-004-WEBSHELL",
        },
        headers={"X-Admin-Key": "wrong-key"},
    )
    assert resp_reg_bad_auth.status_code == 403

    # 2. List runs
    resp_list_no_auth = await async_client.get("/api/v1/simulations/runs")
    assert resp_list_no_auth.status_code == 401

    # 3. Coverage
    resp_cov_no_auth = await async_client.get("/api/v1/simulations/coverage")
    assert resp_cov_no_auth.status_code == 401


@pytest.mark.asyncio
async def test_agent_token_cannot_access_admin_simulations(async_client: AsyncClient):
    """An ordinary endpoint-agent Bearer token must NOT grant access to simulation admin APIs."""
    agent_id = uuid.uuid4()
    raw_token = f"agent-regular-{uuid.uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)

    async with async_session_factory() as session:
        agent = AgentModel(
            id=agent_id,
            hostname="test-sensor-agent",
            os_family="linux",
            os_version="Ubuntu",
            primary_ip="192.168.1.10",
            mac_address="00:11:22:33:44:55",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=token_hash,
            secret_key_enc="enc_secret",
        )
        session.add(agent)
        await session.commit()

    try:
        # Agent attempts to call simulation register endpoint
        resp = await async_client.post(
            "/api/v1/simulations/runs",
            json={
                "run_id": f"sim-agent-{uuid.uuid4().hex[:8]}",
                "trace_id": f"trace-{uuid.uuid4().hex[:8]}",
                "scenario_id": "web-shell",
                "scenario_name": "Web Shell",
                "target_rule_id": "RULE-FIM-004-WEBSHELL",
            },
            headers={"Authorization": f"Bearer {raw_token}"},
        )
        assert resp.status_code in [401, 403]
    finally:
        async with async_session_factory() as session:
            await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
            await session.commit()


@pytest.mark.asyncio
async def test_simulation_run_registration_lifecycle(async_client: AsyncClient):
    """Test run registration, duplicate rejection, and idempotent retry."""
    run_id = f"sim-reg-{uuid.uuid4().hex[:8]}"
    trace_id = f"trace-reg-{uuid.uuid4().hex[:8]}"
    admin_headers = {"X-Admin-Key": settings.ADMIN_API_KEY}

    payload = {
        "run_id": run_id,
        "trace_id": trace_id,
        "scenario_id": "web-shell",
        "scenario_name": "Suspicious Web File",
        "mitre_attack_ids": ["T1505.003"],
        "target_rule_id": "RULE-FIM-004-WEBSHELL",
        "is_negative_test": False,
        "expected_detection": True,
    }

    # 1. Initial Registration
    resp1 = await async_client.post("/api/v1/simulations/runs", json=payload, headers=admin_headers)
    assert resp1.status_code == 201
    data1 = resp1.json()
    assert data1["run_id"] == run_id
    assert data1["status"] == "RUNNING"
    assert data1["is_simulation"] is True

    # 2. Idempotent Retry with identical parameters -> 200 OK
    resp2 = await async_client.post("/api/v1/simulations/runs", json=payload, headers=admin_headers)
    assert resp2.status_code in [200, 201]
    data2 = resp2.json()
    assert data2["run_id"] == run_id

    # 3. Conflicting Registration (same run_id, different scenario) -> 409 Conflict
    conflict_payload = dict(payload)
    conflict_payload["scenario_id"] = "brute-force"
    resp3 = await async_client.post("/api/v1/simulations/runs", json=conflict_payload, headers=admin_headers)
    assert resp3.status_code == 409


@pytest.mark.asyncio
async def test_backend_independent_verification_on_finalize(async_client: AsyncClient):
    """Verify that backend derives actual outcomes from database findings rather than client claims."""
    admin_headers = {"X-Admin-Key": settings.ADMIN_API_KEY}
    run_id = f"sim-verify-{uuid.uuid4().hex[:8]}"
    trace_id = f"trace-verify-{uuid.uuid4().hex[:8]}"

    # Register positive test for web-shell
    reg_payload = {
        "run_id": run_id,
        "trace_id": trace_id,
        "scenario_id": "web-shell",
        "scenario_name": "Suspicious Web File",
        "mitre_attack_ids": ["T1505.003"],
        "target_rule_id": "RULE-FIM-004-WEBSHELL",
        "is_negative_test": False,
        "expected_detection": True,
    }
    reg_resp = await async_client.post("/api/v1/simulations/runs", json=reg_payload, headers=admin_headers)
    assert reg_resp.status_code == 201

    # Client falsely claims PASS with 0 actual findings in database
    finalize_payload = {
        "events_submitted_count": 1,
        "events_accepted_count": 1,
        "client_status": "PASS",
    }
    fin_resp = await async_client.post(
        f"/api/v1/simulations/runs/{run_id}/finalize",
        json=finalize_payload,
        headers=admin_headers,
    )
    assert fin_resp.status_code == 200
    fin_data = fin_resp.json()

    # Backend MUST reject false pass: no finding exists in DB, so verdict is FAIL!
    assert fin_data["status"] == "FAIL"
    assert fin_data["observed_detection"] is False
    assert len(fin_data["matching_finding_ids"]) == 0


@pytest.mark.asyncio
async def test_simulation_coverage_matrix(async_client: AsyncClient):
    """Verify simulation coverage endpoint returns all 4 scenarios with correct status categories."""
    admin_headers = {"X-Admin-Key": settings.ADMIN_API_KEY}

    resp = await async_client.get("/api/v1/simulations/coverage", headers=admin_headers)
    assert resp.status_code == 200
    data = resp.json()

    assert "total_runs" in data
    assert "passed_runs" in data
    assert "failed_runs" in data
    assert "inconclusive_runs" in data
    assert "scenarios" in data
    assert len(data["scenarios"]) == 4

    scenario_ids = [s["scenario_id"] for s in data["scenarios"]]
    assert set(scenario_ids) == {"brute-force", "web-shell", "port-scan", "priv-esc"}

    for s in data["scenarios"]:
        assert s["positive_status"] in ["VALIDATED", "FAILED", "INCONCLUSIVE", "NOT_TESTED"]
        assert s["negative_status"] in ["VALIDATED", "FAILED", "INCONCLUSIVE", "NOT_TESTED"]
        assert s["mitre_attack_id"] is not None
        assert s["target_rule_id"] is not None


@pytest.mark.asyncio
async def test_simulation_run_history_pagination_and_filtering(async_client: AsyncClient):
    """Test listing simulation runs with pagination and scenario filtering."""
    admin_headers = {"X-Admin-Key": settings.ADMIN_API_KEY}

    # Register two distinct runs
    id1 = f"sim-hist-1-{uuid.uuid4().hex[:6]}"
    id2 = f"sim-hist-2-{uuid.uuid4().hex[:6]}"

    await async_client.post(
        "/api/v1/simulations/runs",
        json={
            "run_id": id1,
            "trace_id": f"trace-{uuid.uuid4().hex[:6]}",
            "scenario_id": "port-scan",
            "scenario_name": "Port Scan",
            "target_rule_id": "RULE-NET-001-PORTSCAN",
        },
        headers=admin_headers,
    )

    await async_client.post(
        "/api/v1/simulations/runs",
        json={
            "run_id": id2,
            "trace_id": f"trace-{uuid.uuid4().hex[:6]}",
            "scenario_id": "priv-esc",
            "scenario_name": "Priv Esc",
            "target_rule_id": "RULE-PROC-001-PRIVILEGE-ESC",
        },
        headers=admin_headers,
    )

    # Query with scenario filter
    resp = await async_client.get("/api/v1/simulations/runs", params={"scenario_id": "port-scan"}, headers=admin_headers)
    assert resp.status_code == 200
    runs = resp.json()
    assert any(r["run_id"] == id1 for r in runs)
    assert not any(r["run_id"] == id2 for r in runs)
