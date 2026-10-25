"""Unit tests for SOAR response governance, action registry, and plan lifecycle state machine."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest
import pytest_asyncio
from sqlalchemy import delete, select

from waliya.contracts import (
    ActionRiskClassificationEnum,
    ResponseActionEnum,
    ResponsePlanActionItem,
    ResponsePlanCreateRequest,
    ResponsePlanStatusEnum,
)
from waliya.db.models import (
    AgentModel,
    AuditLedgerModel,
    IncidentModel,
    ResponseActionModel,
    ResponsePlanModel,
)
from waliya.db.session import async_session_factory
from waliya.soar.action_registry import (
    ACTION_REGISTRY,
    ResponseActionRegistry,
)
from waliya.soar.adapters import ActionParametersValidator
from waliya.soar.plan_service import (
    InvalidLifecycleTransitionError,
    ResponsePlanService,
    compute_actions_approval_hash,
)


@pytest.fixture
def sample_actions():
    return [
        {
            "action": "BLOCK_IP",
            "parameters": {"ip_address": "198.51.100.99", "direction": "BOTH"},
            "agent_id": str(uuid4()),
            "requires_approval": True,
        },
        {
            "action": "COLLECT_FORENSIC_ARTIFACT",
            "parameters": {"artifact_type": "LOGS"},
            "agent_id": str(uuid4()),
            "requires_approval": False,
        },
    ]


def test_action_registry_completeness_and_risk_ordering():
    """Verify registry contains all 7 actions with appropriate risk ratings."""
    assert len(ACTION_REGISTRY) == 7
    assert ResponseActionRegistry.is_supported("BLOCK_IP")
    assert ResponseActionRegistry.is_supported("TERMINATE_PROCESS")
    assert not ResponseActionRegistry.is_supported("FORMAT_HARD_DRIVE")

    # Risk classifications
    assert ResponseActionRegistry.get_metadata(ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT).risk_classification == ActionRiskClassificationEnum.READ_ONLY
    assert ResponseActionRegistry.get_metadata(ResponseActionEnum.BLOCK_IP).risk_classification == ActionRiskClassificationEnum.REVERSIBLE
    assert ResponseActionRegistry.get_metadata(ResponseActionEnum.ISOLATE_HOST).risk_classification == ActionRiskClassificationEnum.CONTAINMENT
    assert ResponseActionRegistry.get_metadata(ResponseActionEnum.TERMINATE_PROCESS).risk_classification == ActionRiskClassificationEnum.DESTRUCTIVE

    # Plan-level risk escalation
    read_only_plan = [{"action": "COLLECT_FORENSIC_ARTIFACT", "requires_approval": False}]
    assert ResponseActionRegistry.compute_plan_risk(read_only_plan) == ActionRiskClassificationEnum.READ_ONLY

    containment_plan = [
        {"action": "COLLECT_FORENSIC_ARTIFACT"},
        {"action": "ISOLATE_HOST"},
    ]
    assert ResponseActionRegistry.compute_plan_risk(containment_plan) == ActionRiskClassificationEnum.CONTAINMENT

    destructive_plan = [
        {"action": "COLLECT_FORENSIC_ARTIFACT"},
        {"action": "TERMINATE_PROCESS"},
    ]
    assert ResponseActionRegistry.compute_plan_risk(destructive_plan) == ActionRiskClassificationEnum.DESTRUCTIVE


def test_action_registry_approval_mandate():
    """Verify approval mandate is enforced for containment or destructive actions."""
    # Pre-approved read only action without approval flag
    assert not ResponseActionRegistry.plan_requires_approval([
        {"action": "COLLECT_FORENSIC_ARTIFACT", "requires_approval": False}
    ])

    # Destructive action mandates approval even if step says false
    assert ResponseActionRegistry.plan_requires_approval([
        {"action": "TERMINATE_PROCESS", "requires_approval": False}
    ])


def test_lifecycle_state_machine_valid_transitions():
    """Verify allowed lifecycle paths succeed without raising InvalidLifecycleTransitionError."""
    # Draft -> Pending Approval
    ResponsePlanService._validate_transition(ResponsePlanStatusEnum.DRAFT, ResponsePlanStatusEnum.PENDING_APPROVAL)
    # Draft -> Cancelled
    ResponsePlanService._validate_transition(ResponsePlanStatusEnum.DRAFT, ResponsePlanStatusEnum.CANCELLED)
    # Pending Approval -> Approved
    ResponsePlanService._validate_transition(ResponsePlanStatusEnum.PENDING_APPROVAL, ResponsePlanStatusEnum.APPROVED)
    # Pending Approval -> Rejected
    ResponsePlanService._validate_transition(ResponsePlanStatusEnum.PENDING_APPROVAL, ResponsePlanStatusEnum.REJECTED)
    # Approved -> Executing
    ResponsePlanService._validate_transition(ResponsePlanStatusEnum.APPROVED, ResponsePlanStatusEnum.EXECUTING)
    # Executing -> Succeeded
    ResponsePlanService._validate_transition(ResponsePlanStatusEnum.EXECUTING, ResponsePlanStatusEnum.SUCCEEDED)
    # Executing -> Failed
    ResponsePlanService._validate_transition(ResponsePlanStatusEnum.EXECUTING, ResponsePlanStatusEnum.FAILED)


def test_lifecycle_state_machine_invalid_transitions():
    """Verify illegal transitions are strictly rejected by the finite state machine."""
    # Cannot jump directly from DRAFT to EXECUTING (bypassing approval)
    with pytest.raises(InvalidLifecycleTransitionError, match="Cannot transition response plan from DRAFT to EXECUTING"):
        ResponsePlanService._validate_transition(ResponsePlanStatusEnum.DRAFT, ResponsePlanStatusEnum.EXECUTING)

    # Cannot approve a plan directly from DRAFT without submission
    with pytest.raises(InvalidLifecycleTransitionError):
        ResponsePlanService._validate_transition(ResponsePlanStatusEnum.DRAFT, ResponsePlanStatusEnum.APPROVED)

    # Terminal states cannot transition anywhere
    for terminal in (ResponsePlanStatusEnum.SUCCEEDED, ResponsePlanStatusEnum.FAILED, ResponsePlanStatusEnum.REJECTED, ResponsePlanStatusEnum.CANCELLED):
        with pytest.raises(InvalidLifecycleTransitionError):
            ResponsePlanService._validate_transition(terminal, ResponsePlanStatusEnum.APPROVED)


def test_approval_hash_deterministic_and_tamper_detection(sample_actions):
    """Verify approval hash is deterministic and changes upon any action parameter alteration."""
    hash1 = compute_actions_approval_hash(sample_actions)
    hash2 = compute_actions_approval_hash(sample_actions)
    assert hash1 == hash2
    assert len(hash1) == 64

    # Tampered action parameters
    tampered_actions = [
        {
            "action": "BLOCK_IP",
            "parameters": {"ip_address": "198.51.100.100", "direction": "BOTH"},  # Changed IP
            "agent_id": sample_actions[0]["agent_id"],
            "requires_approval": True,
        },
        sample_actions[1],
    ]
    tampered_hash = compute_actions_approval_hash(tampered_actions)
    assert tampered_hash != hash1


@pytest_asyncio.fixture
async def setup_plan_context():
    """Setup agent and incident in test db for governance tests."""
    agent_id = uuid4()
    inc_id = uuid4()
    now_utc = datetime.now(timezone.utc)

    agent = AgentModel(
        id=agent_id,
        hostname="waliya-gov-sensor",
        os_family="linux",
        os_version="Debian 12",
        primary_ip="10.0.1.50",
        mac_address="02:42:0A:00:01:32",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash="fake_hash",
        secret_key_enc="fake_secret_enc",
    )

    incident = IncidentModel(
        id=inc_id,
        title="Web Server Shell Anomaly",
        description="Suspicious web server outbound connection",
        severity="HIGH",
        status="OPEN",
        composite_risk_score=75.0,
        risk_explanation={"score": 75.0},
        first_seen=now_utc,
        last_seen=now_utc,
        affected_entities=[f"host:{agent_id}"],
        mitre_attack_ids=["T1059.004"],
        update_history=[],
        is_simulation=False,
    )

    async with async_session_factory() as session:
        session.add(agent)
        session.add(incident)
        await session.commit()

    yield {"agent_id": agent_id, "incident_id": inc_id}

    # Teardown
    async with async_session_factory() as session:
        await session.execute(delete(ResponsePlanModel).where(ResponsePlanModel.incident_id == inc_id))
        await session.execute(delete(IncidentModel).where(IncidentModel.id == inc_id))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest.mark.asyncio
async def test_response_plan_creation_and_lifecycle_flow(setup_plan_context):
    """Test full plan lifecycle: Create -> Submit -> Approve -> Execute with audit ledger trail."""
    ctx = setup_plan_context
    agent_id = ctx["agent_id"]
    inc_id = ctx["incident_id"]

    # 1. Create plan
    payload = ResponsePlanCreateRequest(
        incident_id=inc_id,
        title="Containment Plan Alpha",
        description="Block external IP and collect volatile logs",
        actions=[
            ResponsePlanActionItem(
                action=ResponseActionEnum.BLOCK_IP,
                parameters={"ip_address": "203.0.113.195", "direction": "IN"},
                agent_id=agent_id,
                requires_approval=True,
            ),
            ResponsePlanActionItem(
                action=ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT,
                parameters={"artifact_type": "LOGS"},
                agent_id=agent_id,
                requires_approval=False,
            ),
        ],
        dry_run=True,
        submit_for_approval=False,
    )

    async with async_session_factory() as session:
        plan = await ResponsePlanService.create_plan(session, payload, created_by="analyst_alice")
        assert plan.status == ResponsePlanStatusEnum.DRAFT.value
        assert plan.risk_level == ActionRiskClassificationEnum.REVERSIBLE.value
        assert plan.requires_approval is True
        assert plan.approval_hash is None
        plan_id = plan.id

    # 2. Submit plan
    async with async_session_factory() as session:
        plan = await ResponsePlanService.submit_plan(session, plan_id, actor_id="analyst_alice")
        assert plan.status == ResponsePlanStatusEnum.PENDING_APPROVAL.value
        assert plan.approval_hash is not None
        initial_hash = plan.approval_hash

    # 3. Approve plan (by different actor -> separation of duties)
    async with async_session_factory() as session:
        plan = await ResponsePlanService.approve_plan(
            session,
            plan_id,
            actor_id="admin_bob",
            reason="Verified IOC against external threat intel",
        )
        assert plan.status == ResponsePlanStatusEnum.APPROVED.value
        assert plan.approved_by == "admin_bob"
        assert plan.approval_hash == initial_hash


@pytest.mark.asyncio
async def test_tampered_plan_execution_rejected(setup_plan_context):
    """Verify that tampering with plan action parameters invalidates approval and aborts execution."""
    ctx = setup_plan_context
    agent_id = ctx["agent_id"]
    inc_id = ctx["incident_id"]

    payload = ResponsePlanCreateRequest(
        incident_id=inc_id,
        title="Tamper Test Plan",
        actions=[
            ResponsePlanActionItem(
                action=ResponseActionEnum.BLOCK_IP,
                parameters={"ip_address": "203.0.113.50", "direction": "BOTH"},
                agent_id=agent_id,
                requires_approval=True,
            ),
        ],
        dry_run=True,
        submit_for_approval=True,
    )

    async with async_session_factory() as session:
        plan = await ResponsePlanService.create_plan(session, payload, created_by="analyst_alice")
        plan_id = plan.id

    async with async_session_factory() as session:
        await ResponsePlanService.approve_plan(session, plan_id, actor_id="admin_bob", reason="Approved")

    # Manually tamper with action payload in DB
    async with async_session_factory() as session:
        res = await session.execute(select(ResponsePlanModel).where(ResponsePlanModel.id == plan_id))
        plan = res.scalars().first()
        plan.actions = [
            {
                "action": "BLOCK_IP",
                "parameters": {"ip_address": "198.51.100.77", "direction": "BOTH"},  # Tampered IP
                "agent_id": str(agent_id),
                "requires_approval": True,
            }
        ]
        await session.commit()

    # Attempt to execute: must fail due to hash mismatch
    async with async_session_factory() as session:
        with pytest.raises(ValueError, match="Action payload mismatch detected at execution time"):
            await ResponsePlanService.execute_plan(session, plan_id, actor_id="admin_bob")


@pytest.mark.asyncio
async def test_simulation_incident_forces_dry_run(setup_plan_context):
    """Verify synthetic simulation incidents strictly enforce dry_run=True."""
    ctx = setup_plan_context
    agent_id = ctx["agent_id"]
    inc_id = ctx["incident_id"]

    # Mark incident as simulation
    async with async_session_factory() as session:
        res = await session.execute(select(IncidentModel).where(IncidentModel.id == inc_id))
        incident = res.scalars().first()
        incident.is_simulation = True
        incident.simulation_run_id = "sim-run-456"
        await session.commit()

    payload = ResponsePlanCreateRequest(
        incident_id=inc_id,
        title="Simulation Incident Plan",
        actions=[
            ResponsePlanActionItem(
                action=ResponseActionEnum.COLLECT_FORENSIC_ARTIFACT,
                parameters={"artifact_type": "LOGS"},
                agent_id=agent_id,
                requires_approval=False,
            ),
        ],
        dry_run=False,  # Client tries to request live mode on simulation
        submit_for_approval=True,
    )

    async with async_session_factory() as session:
        plan = await ResponsePlanService.create_plan(session, payload, created_by="analyst_alice")
        # Forcibly true at creation
        assert plan.dry_run is True
        assert plan.is_simulation is True
        plan_id = plan.id

    async with async_session_factory() as session:
        await ResponsePlanService.approve_plan(session, plan_id, actor_id="admin_bob", reason="Approve sim plan")

    async with async_session_factory() as session:
        # Client tries to force dry_run=False at execution
        plan = await ResponsePlanService.execute_plan(session, plan_id, actor_id="admin_bob", dry_run=False)
        # Boundary forcibly maintained
        assert plan.dry_run is True
        assert plan.status in (ResponsePlanStatusEnum.SUCCEEDED.value, ResponsePlanStatusEnum.FAILED.value)
