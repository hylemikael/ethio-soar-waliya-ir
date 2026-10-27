"""Integration & Security Verification Suite for Phase B1: Authorization and Privilege Escalation Hardening.

Covers:
1. Least-Privilege Role Separation across all 4 roles (ADMIN, OPERATOR, ANALYST, AUDITOR).
2. Auditor read-only visibility into audit ledger, cryptographic verification, diagnostics, and metrics; strict rejection from all mutations.
3. Analyst read-only visibility into incidents, detection rules, telemetry findings, correlation graph, assets, and threat intel; permission for indicator curation; strict rejection from status transitions, response execution, rule creation, and administration.
4. Operator operational response capabilities (incident status, evidence sealing, graph refresh, response execution, outbox flush); strict rejection from user management, rule authoring, integration secrets, and audit records.
5. Administrator full governance capabilities.
6. Invariant Protection: Rejection of root admin demotion/deactivation and rejection of self-demotion/self-deactivation.
7. Agent Cross-Tenant Isolation & IDOR Protection: Prevention of agent token reuse across distinct agent IDs.
8. Machine Key (X-Admin-Key) Boundary Quarantine: Rejection of machine keys on personal interactive user endpoints.
9. Safe Failure & Unauthenticated Request Rejection: Strict 401 on missing, expired, or revoked credentials.
"""

from datetime import datetime, timezone
import uuid
from typing import Dict, Tuple

import pytest
import pytest_asyncio
from httpx import AsyncClient
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.contracts import IncidentStatusEnum, SeverityEnum
from waliya.core.auth import UserRole
from waliya.core.crypto import hash_agent_token
from waliya.core.password import hash_password
from waliya.core.session import (
    clear_revocations_for_tests,
    create_session_token,
    revoke_session,
)
from waliya.db.models import (
    AgentModel,
    EventModel,
    FindingModel,
    IncidentModel,
    UserModel,
)
from waliya.db.session import async_session_factory


@pytest.fixture(autouse=True)
def clean_security_state():
    """Ensure clean session revocations between test runs."""
    clear_revocations_for_tests()
    yield
    clear_revocations_for_tests()


@pytest_asyncio.fixture
async def rbac_test_users():
    """Provision distinct test accounts for ADMIN, OPERATOR, ANALYST, and AUDITOR."""
    unique_tag = uuid.uuid4().hex[:6]
    pw_hash = hash_password("Waliya#Security#Passphrase#2026!")

    users_to_create = [
        {"username": f"admin_b1_{unique_tag}", "email": f"admin_{unique_tag}@soc.et", "role": UserRole.ADMIN.value},
        {"username": f"operator_b1_{unique_tag}", "email": f"operator_{unique_tag}@soc.et", "role": UserRole.OPERATOR.value},
        {"username": f"analyst_b1_{unique_tag}", "email": f"analyst_{unique_tag}@soc.et", "role": UserRole.ANALYST.value},
        {"username": f"auditor_b1_{unique_tag}", "email": f"auditor_{unique_tag}@soc.et", "role": UserRole.AUDITOR.value},
    ]

    created_users = {}

    async with async_session_factory() as session:
        for u_data in users_to_create:
            user_obj = UserModel(
                id=uuid.uuid4(),
                username=u_data["username"],
                email=u_data["email"],
                full_name=f"Test {u_data['role']}",
                role=u_data["role"],
                password_hash=pw_hash,
                is_active=True,
                is_mfa_enabled=False,
            )
            session.add(user_obj)
            created_users[u_data["role"]] = user_obj
        await session.commit()

        for u in created_users.values():
            await session.refresh(u)

    # Generate session tokens and CSRF headers for each role
    role_sessions = {}
    for role, user in created_users.items():
        session_token, csrf_token = create_session_token(
            secret_key=settings.SECRET_KEY,
            actor=user.username,
            role=role,
            mfa_authenticated=True,
            user_id=str(user.id),
        )
        role_sessions[role] = {
            "user_id": user.id,
            "username": user.username,
            "cookies": {
                settings.SESSION_COOKIE_NAME: session_token,
                settings.CSRF_COOKIE_NAME: csrf_token,
            },
            "headers": {"X-CSRF-Token": csrf_token},
        }

    yield role_sessions

    # Cleanup test users
    async with async_session_factory() as session:
        u_ids = [u.id for u in created_users.values()]
        await session.execute(delete(UserModel).where(UserModel.id.in_(u_ids)))
        await session.commit()


@pytest_asyncio.fixture
async def sample_incident():
    """Seed a test incident, event, and finding for testing status transitions and evidence sealing."""
    inc_id = uuid.uuid4()
    ev_id = uuid.uuid4()
    finding_id = uuid.uuid4()
    now = datetime.now(timezone.utc)
    event = EventModel(
        id=ev_id,
        event_type="AUTH_FAILURE",
        severity="HIGH",
        timestamp=now,
        source="waliya-audit",
        raw_payload={"raw": "payload"},
        normalized_payload={"user": "root", "action": "failed_login"},
    )
    incident = IncidentModel(
        id=inc_id,
        incident_number=999901,
        title="B1 Security Authorization Test Incident",
        description="Testing authorization boundaries on incident mutation endpoints",
        severity=SeverityEnum.HIGH.value,
        status=IncidentStatusEnum.INVESTIGATING.value,
        assigned_to="system:test",
        created_at=now,
        updated_at=now,
    )
    finding = FindingModel(
        id=finding_id,
        event_id=ev_id,
        incident_id=inc_id,
        severity="HIGH",
        confidence=90,
        explanation={"finding_type": "AUTH_ANOMALY", "detail": "Observed brute-force auth attempts"},
        timestamp=now,
        dedup_key=f"dedup-{uuid.uuid4().hex}",
    )
    async with async_session_factory() as session:
        session.add(event)
        session.add(incident)
        session.add(finding)
        await session.commit()

    yield incident

    async with async_session_factory() as session:
        await session.execute(delete(FindingModel).where(FindingModel.incident_id == inc_id))
        await session.execute(delete(IncidentModel).where(IncidentModel.id == inc_id))
        await session.execute(delete(EventModel).where(EventModel.id == ev_id))
        await session.commit()


@pytest_asyncio.fixture
async def two_agents():
    """Register two distinct agents (Agent A and Agent B) to test cross-tenant isolation."""
    agent_a_id = uuid.uuid4()
    agent_b_id = uuid.uuid4()
    raw_token_a = f"agent-a-secret-token-{uuid.uuid4().hex}"
    raw_token_b = f"agent-b-secret-token-{uuid.uuid4().hex}"

    token_hash_a = hash_agent_token(raw_token_a, pepper=settings.AGENT_TOKEN_PEPPER)
    token_hash_b = hash_agent_token(raw_token_b, pepper=settings.AGENT_TOKEN_PEPPER)

    agent_a = AgentModel(
        id=agent_a_id,
        hostname="waliya-agent-alpha",
        os_family="linux",
        os_version="Debian 12",
        primary_ip="10.0.1.10",
        mac_address="02:42:0a:00:01:0a",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash_a,
        secret_key_enc="enc_key_a",
    )
    agent_b = AgentModel(
        id=agent_b_id,
        hostname="waliya-agent-bravo",
        os_family="linux",
        os_version="Ubuntu 24.04",
        primary_ip="10.0.1.20",
        mac_address="02:42:0a:00:01:14",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash_b,
        secret_key_enc="enc_key_b",
    )

    async with async_session_factory() as session:
        session.add(agent_a)
        session.add(agent_b)
        await session.commit()

    yield {
        "agent_a": {"id": agent_a_id, "token": raw_token_a},
        "agent_b": {"id": agent_b_id, "token": raw_token_b},
    }

    async with async_session_factory() as session:
        await session.execute(delete(AgentModel).where(AgentModel.id.in_([agent_a_id, agent_b_id])))
        await session.commit()


# ==============================================================================
# 1. Least Privilege Matrix & Auditor Access Verification
# ==============================================================================

@pytest.mark.asyncio
async def test_auditor_permissions_and_state_change_rejection(
    async_client: AsyncClient,
    rbac_test_users: Dict[str, Dict],
    sample_incident: IncidentModel,
):
    """Verify AUDITOR has read access to audit records, verification, diagnostics, and metrics,

    and is strictly prohibited (403) from executing any state-changing operations.
    """
    auditor = rbac_test_users["AUDITOR"]

    # 1. Permitted Auditor Endpoints -> 200 OK
    res_records = await async_client.get(
        "/api/v1/soar/audit/records",
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_records.status_code == 200
    assert isinstance(res_records.json(), list)

    res_verify = await async_client.get(
        "/api/v1/soar/audit/verify",
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_verify.status_code == 200
    assert "verified" in res_verify.json()

    res_diag = await async_client.get(
        "/api/v1/health/diagnostics",
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_diag.status_code == 200
    assert "status" in res_diag.json()

    res_metrics = await async_client.get(
        "/api/v1/health/metrics",
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_metrics.status_code == 200

    res_incidents = await async_client.get(
        "/api/v1/incidents",
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_incidents.status_code == 200

    # 2. Forbidden Auditor Operations -> 403 Forbidden
    # Mutation 1: Change incident status
    res_status = await async_client.patch(
        f"/api/v1/incidents/{sample_incident.id}/status",
        json={"status": "CONTAINED", "note": "Auditor unauthorized attempt"},
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_status.status_code == 403

    # Mutation 2: Seal incident evidence
    res_seal = await async_client.post(
        f"/api/v1/incidents/{sample_incident.id}/seal-evidence",
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_seal.status_code == 403

    # Mutation 3: Trigger SOAR playbook
    res_pb = await async_client.post(
        "/api/v1/soar/playbooks/execute",
        json={
            "playbook_id": str(uuid.uuid4()),
            "incident_id": str(sample_incident.id),
            "agent_id": str(uuid.uuid4()),
            "dry_run": True,
        },
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_pb.status_code == 403

    # Mutation 4: Create detection rule
    res_rule = await async_client.post(
        "/api/v1/rules",
        json={
            "rule_id": "TEST-RULE-001",
            "name": "Unauthorized Auditor Rule",
            "event_type": "PROCESS_START",
            "severity": "HIGH",
            "condition": {"operator": "EQUALS", "field": "event.action", "value": "exec"},
        },
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_rule.status_code == 403

    # Mutation 5: Create threat indicator
    res_ti = await async_client.post(
        "/api/v1/threat-intel/indicators",
        json={
            "indicator_type": "IPV4",
            "value": "198.51.100.99",
            "source": "Auditor Test",
            "severity": "HIGH",
            "confidence": 85,
        },
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_ti.status_code == 403

    # Mutation 6: Create user
    res_user = await async_client.post(
        "/api/v1/users",
        json={
            "username": "hacker_user",
            "email": "hacker@soc.et",
            "password": "Waliya#Security#Passphrase#2026!",
            "role": "ADMIN",
        },
        cookies=auditor["cookies"],
        headers=auditor["headers"],
    )
    assert res_user.status_code == 403


# ==============================================================================
# 2. Analyst Permissions & Operational State-Change Rejection
# ==============================================================================

@pytest.mark.asyncio
async def test_analyst_permissions_and_operational_rejection(
    async_client: AsyncClient,
    rbac_test_users: Dict[str, Dict],
    sample_incident: IncidentModel,
):
    """Verify ANALYST has read access to operational telemetry, graph, assets, and overview;

    can curate threat indicators; but is strictly prohibited from mutating incidents,
    approving response plans, or performing administration.
    """
    analyst = rbac_test_users["ANALYST"]

    # 1. Permitted Analyst Read Endpoints -> 200 OK
    assert (await async_client.get("/api/v1/incidents", cookies=analyst["cookies"], headers=analyst["headers"])).status_code == 200
    assert (await async_client.get("/api/v1/rules", cookies=analyst["cookies"], headers=analyst["headers"])).status_code == 200
    assert (await async_client.get("/api/v1/rules/findings", cookies=analyst["cookies"], headers=analyst["headers"])).status_code == 200
    assert (await async_client.get("/api/v1/threat-intel/indicators", cookies=analyst["cookies"], headers=analyst["headers"])).status_code == 200
    assert (await async_client.get("/api/v1/correlation/graph", cookies=analyst["cookies"], headers=analyst["headers"])).status_code == 200
    assert (await async_client.get("/api/v1/assets", cookies=analyst["cookies"], headers=analyst["headers"])).status_code == 200
    assert (await async_client.get("/api/v1/overview", cookies=analyst["cookies"], headers=analyst["headers"])).status_code == 200

    # 2. Permitted Analyst Threat Indicator Curation -> 201 Created
    unique_domain = f"c2-{uuid.uuid4().hex[:16]}.threat-sample.org"
    res_ioc = await async_client.post(
        "/api/v1/threat-intel/indicators",
        json={
            "indicator_type": "DOMAIN",
            "value": unique_domain,
            "source": f"SOC Triage Analyst {uuid.uuid4().hex[:8]}",
            "severity": "HIGH",
            "confidence": 90,
            "description": "Analyst verified C2 observable",
        },
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_ioc.status_code == 201
    ioc_id = res_ioc.json()["id"]

    # 3. Forbidden Analyst Actions -> 403 Forbidden
    # Mutation 1: Update incident status
    res_status = await async_client.patch(
        f"/api/v1/incidents/{sample_incident.id}/status",
        json={"status": "CONTAINED", "note": "Analyst attempting unauthorized status transition"},
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_status.status_code == 403

    # Mutation 2: Seal incident evidence
    res_seal = await async_client.post(
        f"/api/v1/incidents/{sample_incident.id}/seal-evidence",
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_seal.status_code == 403

    # Mutation 3: Refresh incident correlation graph
    res_refresh = await async_client.post(
        f"/api/v1/incidents/{sample_incident.id}/graph/refresh",
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_refresh.status_code == 403

    # Mutation 4: Create response plan
    res_plan = await async_client.post(
        "/api/v1/soar/plans",
        json={
            "title": "Analyst Rogue Plan",
            "description": "Unauthorized response plan",
            "incident_id": str(sample_incident.id),
            "risk_level": "HIGH",
            "actions": [],
        },
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_plan.status_code == 403

    # Mutation 5: Access audit ledger records
    res_audit = await async_client.get(
        "/api/v1/soar/audit/records",
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_audit.status_code == 403

    # Mutation 6: Access system diagnostics
    res_diag = await async_client.get(
        "/api/v1/health/diagnostics",
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_diag.status_code == 403

    # Mutation 7: Author detection rules
    res_rule = await async_client.post(
        "/api/v1/rules",
        json={
            "rule_id": "TEST-RULE-002",
            "name": "Analyst Rule Author Attempt",
            "event_type": "FILE_MODIFICATION",
            "severity": "MEDIUM",
            "condition": {"operator": "EQUALS", "field": "file.path", "value": "/etc/shadow"},
        },
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_rule.status_code == 403

    # Mutation 8: User management
    res_user = await async_client.post(
        "/api/v1/users",
        json={
            "username": "analyst_created_user",
            "email": "user@soc.et",
            "password": "Waliya#Security#Passphrase#2026!",
            "role": "ANALYST",
        },
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_user.status_code == 403


# ==============================================================================
# 3. Operator Permissions & Administration Isolation
# ==============================================================================

@pytest.mark.asyncio
async def test_operator_permissions_and_admin_isolation(
    async_client: AsyncClient,
    rbac_test_users: Dict[str, Dict],
    sample_incident: IncidentModel,
):
    """Verify OPERATOR can perform operational incident response, status transitions,

    evidence sealing, and outbox operations, but is strictly prohibited from user management,
    detection rule authoring, modifying integration destinations, or viewing the audit ledger.
    """
    operator = rbac_test_users["OPERATOR"]

    # 1. Permitted Operator Operations -> 200 OK
    # Operation 1: Update incident status
    res_status = await async_client.patch(
        f"/api/v1/incidents/{sample_incident.id}/status",
        json={"status": "CONTAINED", "note": "Operator triage: containment verified"},
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_status.status_code == 200
    assert res_status.json()["current_status"] == "CONTAINED"

    # Operation 2: Seal incident evidence
    res_seal = await async_client.post(
        f"/api/v1/incidents/{sample_incident.id}/seal-evidence",
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_seal.status_code == 200
    assert res_seal.json()["status"] == "VERIFIED"
    assert "manifest_hash" in res_seal.json()

    # Operation 3: Refresh incident correlation graph
    res_graph = await async_client.post(
        f"/api/v1/incidents/{sample_incident.id}/graph/refresh",
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_graph.status_code == 200

    # Operation 4: Flush telemetry outbox
    res_flush = await async_client.post(
        "/api/v1/telemetry/outbox/flush",
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_flush.status_code == 200
    assert res_flush.json()["status"] == "COMPLETED"

    # Operation 5: Correlation graph prune
    res_prune = await async_client.post(
        "/api/v1/correlation/prune",
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_prune.status_code == 200
    assert res_prune.json()["status"] == "COMPLETED"

    # 2. Forbidden Operator Operations -> 403 Forbidden
    # Prohibited 1: User management
    res_user = await async_client.post(
        "/api/v1/users",
        json={
            "username": "operator_created_user",
            "email": "user2@soc.et",
            "password": "Waliya#Security#Passphrase#2026!",
            "role": "ANALYST",
        },
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_user.status_code == 403

    # Prohibited 2: Rule authoring
    res_rule = await async_client.post(
        "/api/v1/rules",
        json={
            "rule_id": "TEST-RULE-003",
            "name": "Operator Rule Author Attempt",
            "event_type": "NETWORK_CONNECT",
            "severity": "HIGH",
            "condition": {"operator": "EQUALS", "field": "dest.port", "value": 4444},
        },
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_rule.status_code == 403

    # Prohibited 3: Outbound integration destination creation
    res_dest = await async_client.post(
        "/api/v1/integrations/destinations",
        json={
            "name": "Rogue Webhook",
            "destination_url": "https://alerts.soc.et/webhook",
            "is_enabled": True,
            "subscribed_events": ["*"],
        },
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_dest.status_code == 403

    # Prohibited 4: Threat feed configuration update
    res_feed = await async_client.patch(
        "/api/v1/threat-intel/feeds/alienvault-otx",
        json={"is_enabled": False},
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_feed.status_code == 403

    # Prohibited 5: Audit ledger viewing (Auditor/Admin only)
    res_audit = await async_client.get(
        "/api/v1/soar/audit/records",
        cookies=operator["cookies"],
        headers=operator["headers"],
    )
    assert res_audit.status_code == 403


# ==============================================================================
# 4. Privilege Escalation & Self-Protection Invariants
# ==============================================================================

@pytest.mark.asyncio
async def test_root_admin_and_self_protection_invariants(
    async_client: AsyncClient,
    rbac_test_users: Dict[str, Dict],
):
    """Verify that:

    1. Root administrator account ('admin') cannot be demoted or deactivated by any administrator.
    2. Active interactive administrators cannot demote their own account.
    3. Active interactive administrators cannot deactivate their own account.
    4. Non-administrators cannot call user modification endpoints (403).
    """
    admin = rbac_test_users["ADMIN"]
    analyst = rbac_test_users["ANALYST"]

    # 1. Fetch or provision root administrator account
    async with async_session_factory() as session:
        root_admin = (await session.execute(
            select(UserModel).where(UserModel.username == "admin")
        )).scalars().first()
        if not root_admin:
            root_admin = UserModel(
                id=uuid.uuid4(),
                username="admin",
                email="admin@soc.et",
                full_name="Root Administrator",
                role=UserRole.ADMIN.value,
                password_hash=hash_password("Root#Admin#Passphrase#2026!"),
                is_active=True,
                is_mfa_enabled=False,
            )
            session.add(root_admin)
            await session.commit()
            await session.refresh(root_admin)

    # Attempt 1: Admin attempts to demote root 'admin' -> 400 Bad Request
    res_demote_root = await async_client.patch(
        f"/api/v1/users/{root_admin.id}",
        json={"role": "ANALYST"},
        cookies=admin["cookies"],
        headers=admin["headers"],
    )
    assert res_demote_root.status_code == 400
    assert "Cannot demote the root administrator account" in res_demote_root.json()["detail"]

    # Attempt 2: Admin attempts to deactivate root 'admin' -> 400 Bad Request
    res_deact_root = await async_client.patch(
        f"/api/v1/users/{root_admin.id}",
        json={"is_active": False},
        cookies=admin["cookies"],
        headers=admin["headers"],
    )
    assert res_deact_root.status_code == 400
    assert "Cannot deactivate the root administrator account" in res_deact_root.json()["detail"]

    # Attempt 3: Admin attempts to self-demote -> 400 Bad Request
    res_self_demote = await async_client.patch(
        f"/api/v1/users/{admin['user_id']}",
        json={"role": "OPERATOR"},
        cookies=admin["cookies"],
        headers=admin["headers"],
    )
    assert res_self_demote.status_code == 400
    assert "Administrators cannot demote their own account" in res_self_demote.json()["detail"]

    # Attempt 4: Admin attempts to self-deactivate -> 400 Bad Request
    res_self_deact = await async_client.patch(
        f"/api/v1/users/{admin['user_id']}",
        json={"is_active": False},
        cookies=admin["cookies"],
        headers=admin["headers"],
    )
    assert res_self_deact.status_code == 400
    assert "Administrators cannot deactivate their own account" in res_self_deact.json()["detail"]

    # Attempt 5: Analyst attempts to patch user -> 403 Forbidden
    res_unauth_patch = await async_client.patch(
        f"/api/v1/users/{analyst['user_id']}",
        json={"role": "ADMIN"},
        cookies=analyst["cookies"],
        headers=analyst["headers"],
    )
    assert res_unauth_patch.status_code == 403


# ==============================================================================
# 5. Agent Cross-Tenant Isolation & IDOR Defense
# ==============================================================================

@pytest.mark.asyncio
async def test_agent_cross_tenant_isolation_and_idor(
    async_client: AsyncClient,
    two_agents: Dict[str, Dict],
):
    """Verify that an agent bearer token cryptographically derived for Agent A cannot

    interact with Agent B's task queue, receipts, heartbeat, or verification endpoints.
    """
    agent_a = two_agents["agent_a"]
    agent_b = two_agents["agent_b"]

    auth_header_a = {"Authorization": f"Bearer {agent_a['token']}"}

    # 1. Agent A successfully heartbeats on own endpoint -> 200 OK
    res_hb_ok = await async_client.post(
        f"/api/v1/agents/{agent_a['id']}/heartbeat",
        headers=auth_header_a,
    )
    assert res_hb_ok.status_code == 200
    assert res_hb_ok.json()["status"] == "ACK"

    # 2. Agent A attempts heartbeat targeting Agent B -> 403 Forbidden
    res_hb_idor = await async_client.post(
        f"/api/v1/agents/{agent_b['id']}/heartbeat",
        headers=auth_header_a,
    )
    assert res_hb_idor.status_code == 403
    assert "does not match agent ID in URL path" in res_hb_idor.json()["detail"]

    # 3. Agent A attempts task poll targeting Agent B -> 403 Forbidden
    res_poll_idor = await async_client.post(
        f"/api/v1/agents/{agent_b['id']}/tasks/poll",
        json={"supported_actions": ["ISOLATE_HOST"]},
        headers=auth_header_a,
    )
    assert res_poll_idor.status_code == 403
    assert "does not match agent ID in URL path" in res_poll_idor.json()["detail"]

    # 4. Agent A attempts receipt submission targeting Agent B -> 403 Forbidden
    res_receipt_idor = await async_client.post(
        f"/api/v1/agents/{agent_b['id']}/receipts",
        json={
            "command_id": str(uuid.uuid4()),
            "status": "EXECUTED",
            "exit_code": 0,
            "output": "Fake output",
        },
        headers=auth_header_a,
    )
    assert res_receipt_idor.status_code == 403
    assert "does not match agent ID in URL path" in res_receipt_idor.json()["detail"]

    # 5. Agent A attempts verification telemetry targeting Agent B -> 403 Forbidden
    res_verif_idor = await async_client.post(
        f"/api/v1/agents/{agent_b['id']}/verification",
        json={
            "command_id": str(uuid.uuid4()),
            "observed_state": {"isolated": True},
            "verified_at": datetime.now(timezone.utc).isoformat(),
        },
        headers=auth_header_a,
    )
    assert res_verif_idor.status_code == 403
    assert "does not match agent ID in URL path" in res_verif_idor.json()["detail"]


# ==============================================================================
# 6. Machine Key Quarantining on Personal Endpoints
# ==============================================================================

@pytest.mark.asyncio
async def test_machine_key_quarantine_on_personal_endpoints(
    async_client: AsyncClient,
):
    """Verify pre-shared administrative machine keys (X-Admin-Key) cannot be used to

    circumvent interactive user sessions on personal MFA and password endpoints.
    """
    machine_headers = {"X-Admin-Key": settings.ADMIN_API_KEY}

    # 1. MFA enrollment via machine key -> 403 Forbidden
    res_mfa_enroll = await async_client.post(
        "/api/v1/auth/mfa/enroll",
        headers=machine_headers,
    )
    assert res_mfa_enroll.status_code == 403
    assert "cannot be performed via API key" in res_mfa_enroll.json()["detail"]

    # 2. MFA verify via machine key -> 403 Forbidden
    res_mfa_verify = await async_client.post(
        "/api/v1/auth/mfa/verify",
        json={"code": "123456"},
        headers=machine_headers,
    )
    assert res_mfa_verify.status_code == 403
    assert "cannot be performed via API key" in res_mfa_verify.json()["detail"]

    # 3. MFA disable via machine key -> 403 Forbidden
    res_mfa_disable = await async_client.post(
        "/api/v1/auth/mfa/disable",
        json={"current_password": "AnyPassword123!"},
        headers=machine_headers,
    )
    assert res_mfa_disable.status_code == 403
    assert "cannot be performed via API key" in res_mfa_disable.json()["detail"]

    # 4. Password change via machine key -> 403 Forbidden
    res_pw_change = await async_client.post(
        "/api/v1/auth/password/change",
        json={
            "current_password": "OldPassword123!",
            "new_password": "NewPassphrase#2026!Waliya",
        },
        headers=machine_headers,
    )
    assert res_pw_change.status_code == 403
    assert "cannot be performed via API key" in res_pw_change.json()["detail"]


# ==============================================================================
# 7. Safe Failure & Unauthenticated Rejection
# ==============================================================================

@pytest.mark.asyncio
async def test_safe_failure_on_unauthenticated_and_revoked_requests(
    async_client: AsyncClient,
):
    """Verify that requests missing credentials, using invalid signatures, or presenting

    revoked sessions consistently fail safe with 401 Unauthorized or 403 Forbidden.
    """
    protected_endpoints = [
        ("GET", "/api/v1/incidents"),
        ("GET", "/api/v1/users"),
        ("GET", "/api/v1/rules"),
        ("GET", "/api/v1/rules/findings"),
        ("GET", "/api/v1/threat-intel/indicators"),
        ("GET", "/api/v1/soar/audit/records"),
        ("GET", "/api/v1/soar/audit/verify"),
        ("GET", "/api/v1/health/diagnostics"),
        ("GET", "/api/v1/health/metrics"),
        ("GET", "/api/v1/correlation/graph"),
        ("GET", "/api/v1/assets"),
    ]

    for method, path in protected_endpoints:
        # 1. Completely unauthenticated -> 401 Unauthorized
        res_unauth = await async_client.request(method, path)
        assert res_unauth.status_code == 401, f"Expected 401 for unauthenticated {method} {path}, got {res_unauth.status_code}"

        # 2. Malformed / forged token -> 401 Unauthorized
        res_forged = await async_client.request(
            method,
            path,
            headers={"Authorization": "Bearer forged-signature-token-12345"},
        )
        assert res_forged.status_code == 401, f"Expected 401 for forged token {method} {path}, got {res_forged.status_code}"

    # 3. Explicitly revoked session token -> 401 Unauthorized
    dummy_user_id = str(uuid.uuid4())
    token, csrf = create_session_token(
        secret_key=settings.SECRET_KEY,
        actor="revoked_analyst",
        role="ANALYST",
        user_id=dummy_user_id,
    )
    s_id = token.split(":")[0]

    # Pre-revocation verification -> 200 OK
    res_before_rev = await async_client.get(
        "/api/v1/incidents",
        cookies={settings.SESSION_COOKIE_NAME: token},
        headers={"X-CSRF-Token": csrf},
    )
    assert res_before_rev.status_code == 200

    # Invalidate session
    revoke_session(session_id=s_id, user_id=dummy_user_id)

    # Post-revocation verification -> 401 Unauthorized
    res_after_rev = await async_client.get(
        "/api/v1/incidents",
        cookies={settings.SESSION_COOKIE_NAME: token},
        headers={"X-CSRF-Token": csrf},
    )
    assert res_after_rev.status_code == 401
    assert "expired or is invalid" in res_after_rev.json()["detail"]

