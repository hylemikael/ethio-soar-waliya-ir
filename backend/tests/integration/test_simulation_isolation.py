"""Integration regression tests for simulation-to-real isolation and hardening invariants."""

from datetime import datetime, timezone
import pytest
from sqlalchemy import select
from uuid import uuid4

from waliya.api.routes.simulations import REGISTERED_SCENARIOS, get_simulation_coverage
from waliya.correlation.graph_engine import EntityGraphManager
from waliya.db.models import (
    AgentModel,
    EventModel,
    FindingModel,
    IncidentModel,
    PlaybookModel,
    PlaybookRunModel,
    RuleModel,
    SimulationRunModel,
)
from waliya.db.session import async_session_factory
from waliya.detection.rule_engine import RuleEngine
from waliya.incidents.correlation_service import IncidentCorrelationService
from waliya.soar.playbook_engine import PlaybookEngine
from redis.asyncio import Redis
from waliya.config import settings


async def _create_test_event(session, event_id=None, is_simulation=False, simulation_run_id=None) -> EventModel:
    eid = event_id or uuid4()
    ev = EventModel(
        id=eid,
        event_type="AUTHENTICATION",
        severity="HIGH",
        timestamp=datetime.now(timezone.utc),
        source="auditd",
        raw_payload={"sim": is_simulation},
        normalized_payload={
            "is_simulation": is_simulation,
            "simulation_run_id": simulation_run_id,
        },
    )
    session.add(ev)
    await session.commit()
    return ev


@pytest.mark.asyncio
async def test_simulation_finding_does_not_merge_into_real_incident():
    """Core Invariant: A synthetic finding MUST NEVER merge into an existing real security incident,

    even if they share non-host entities (e.g. identical IP or user).
    """
    async with async_session_factory() as db_session:
        service = IncidentCorrelationService()
        graph_manager = EntityGraphManager()
        shared_ip = "198.51.100.99"
        shared_user = "sec-admin"

        # 1. Create an existing real production incident
        real_inc = IncidentModel(
            id=uuid4(),
            title="Excessive Authentication Failures on sec-admin",
            description="Real brute force attempt from unauthorized actor",
            severity="HIGH",
            status="OPEN",
            composite_risk_score=75.0,
            affected_entities=[f"ip:{shared_ip}", f"user:{shared_user}"],
            is_simulation=False,
            simulation_run_id=None,
        )
        db_session.add(real_inc)
        await db_session.commit()

        # 2. Simulate synthetic finding with shared IP and user
        sim_run_id = f"sim-{uuid4().hex[:8]}"
        ev = await _create_test_event(db_session, is_simulation=True, simulation_run_id=sim_run_id)
        sim_finding = FindingModel(
            id=uuid4(),
            event_id=ev.id,
            severity="HIGH",
            confidence=1.0,
            explanation={
                "rule_id": "RULE-AUTH-001-BRUTEFORCE",
                "rule_name": "Excessive Authentication Failures",
                "is_simulation": True,
                "simulation_run_id": sim_run_id,
                "trace_id": f"trace-{uuid4().hex[:8]}",
            },
            dedup_key=f"sim:{sim_run_id}:RULE-AUTH-001-BRUTEFORCE:{shared_ip}",
            is_simulation=True,
            simulation_run_id=sim_run_id,
        )
        db_session.add(sim_finding)
        await db_session.commit()

        # 3. Correlate finding
        event_data = {
            "event_id": str(sim_finding.event_id),
            "is_simulation": True,
            "simulation_run_id": sim_run_id,
            "attributes": {"src_ip": shared_ip, "user": shared_user},
        }
        modified_incidents = await service.correlate_findings(
            session=db_session,
            findings=[sim_finding],
            event_data=event_data,
            graph_manager=graph_manager,
        )
        await db_session.commit()

        # 4. Verify that real incident was NOT modified and did NOT absorb synthetic finding
        await db_session.refresh(real_inc)
        assert real_inc.is_simulation is False
        assert not real_inc.title.startswith("[SIMULATION]")
        assert sim_finding.incident_id != real_inc.id

        # 5. Verify that a separate simulation incident was created
        assert len(modified_incidents) == 1
        sim_inc = modified_incidents[0]
        assert sim_inc.id != real_inc.id
        assert sim_inc.is_simulation is True
        assert sim_inc.simulation_run_id == sim_run_id
        assert sim_inc.title.startswith("[SIMULATION]")


@pytest.mark.asyncio
async def test_real_finding_does_not_merge_into_simulation_incident():
    """Core Invariant: A real endpoint finding MUST NEVER merge into an existing simulation incident."""
    async with async_session_factory() as db_session:
        service = IncidentCorrelationService()
        graph_manager = EntityGraphManager()
        shared_user = "deploy-bot"

        # 1. Existing simulation incident
        sim_run_id = f"sim-{uuid4().hex[:8]}"
        sim_inc = IncidentModel(
            id=uuid4(),
            title="[SIMULATION] Suspicious Privilege Escalation Execution",
            description="Synthetic purple team validation",
            severity="HIGH",
            status="OPEN",
            composite_risk_score=60.0,
            affected_entities=[f"user:{shared_user}"],
            is_simulation=True,
            simulation_run_id=sim_run_id,
        )
        db_session.add(sim_inc)
        await db_session.commit()

        # 2. Real finding arriving with the same user
        real_ev = await _create_test_event(db_session, is_simulation=False)
        real_finding = FindingModel(
            id=uuid4(),
            event_id=real_ev.id,
            severity="HIGH",
            confidence=1.0,
            explanation={
                "rule_id": "RULE-PROC-001-PRIVILEGE-ESC",
                "rule_name": "Suspicious Privilege Escalation Execution",
            },
            dedup_key=f"RULE-PROC-001-PRIVILEGE-ESC:{shared_user}",
            is_simulation=False,
            simulation_run_id=None,
        )
        db_session.add(real_finding)
        await db_session.commit()

        # 3. Correlate real finding
        event_data = {
            "event_id": str(real_finding.event_id),
            "is_simulation": False,
            "attributes": {"username": shared_user},
        }
        modified_incidents = await service.correlate_findings(
            session=db_session,
            findings=[real_finding],
            event_data=event_data,
            graph_manager=graph_manager,
        )
        await db_session.commit()

        # 4. Verify separation
        await db_session.refresh(sim_inc)
        assert real_finding.incident_id != sim_inc.id
        assert len(modified_incidents) == 1
        real_inc = modified_incidents[0]
        assert real_inc.id != sim_inc.id
        assert real_inc.is_simulation is False
        assert not real_inc.title.startswith("[SIMULATION]")


@pytest.mark.asyncio
async def test_cross_run_simulation_isolation():
    """Core Invariant: Two different simulation runs with shared entities MUST NOT merge together."""
    async with async_session_factory() as db_session:
        service = IncidentCorrelationService()
        graph_manager = EntityGraphManager()
        shared_ip = "198.51.100.77"

        run_a_id = f"sim-{uuid4().hex[:8]}"
        run_b_id = f"sim-{uuid4().hex[:8]}"

        # Run A incident
        inc_a = IncidentModel(
            id=uuid4(),
            title="[SIMULATION] Network Port-Scan Behavior on Run A",
            description="Run A simulation",
            severity="MEDIUM",
            status="OPEN",
            composite_risk_score=50.0,
            affected_entities=[f"ip:{shared_ip}"],
            is_simulation=True,
            simulation_run_id=run_a_id,
        )
        db_session.add(inc_a)
        await db_session.commit()

        # Run B finding
        ev_b = await _create_test_event(db_session, is_simulation=True, simulation_run_id=run_b_id)
        finding_b = FindingModel(
            id=uuid4(),
            event_id=ev_b.id,
            severity="MEDIUM",
            confidence=1.0,
            explanation={
                "rule_id": "RULE-NET-001-PORTSCAN",
                "is_simulation": True,
                "simulation_run_id": run_b_id,
            },
            dedup_key=f"sim:{run_b_id}:RULE-NET-001-PORTSCAN:{shared_ip}",
            is_simulation=True,
            simulation_run_id=run_b_id,
        )
        db_session.add(finding_b)
        await db_session.commit()

        event_data = {
            "event_id": str(finding_b.event_id),
            "is_simulation": True,
            "simulation_run_id": run_b_id,
            "attributes": {"src_ip": shared_ip},
        }
        modified_incidents = await service.correlate_findings(
            session=db_session,
            findings=[finding_b],
            event_data=event_data,
            graph_manager=graph_manager,
        )
        await db_session.commit()

        # Finding B must NOT merge into Inc A
        assert finding_b.incident_id != inc_a.id
        assert len(modified_incidents) == 1
        inc_b = modified_incidents[0]
        assert inc_b.id != inc_a.id
        assert inc_b.simulation_run_id == run_b_id


@pytest.mark.asyncio
async def test_stateful_sliding_window_cross_run_isolation():
    """Verify that sliding-window state in Redis is isolated by simulation_run_id,

    so multiple runs below threshold do not combine to falsely trigger rules.
    """
    redis_client = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    try:
        rule = RuleModel(
            id=uuid4(),
            rule_id="RULE-AUTH-001-BRUTEFORCE",
            version=1,
            name="Excessive Auth Failures",
            description="Threshold >= 5",
            severity="HIGH",
            event_type="AUTHENTICATION",
            conditions=[{"field": "attributes.status", "operator": "EQUALS", "value": "FAILURE"}],
            dedup_window_seconds=300,
            is_active=True,
        )

        shared_src_ip = "198.51.100.88"
        run_1 = f"sim-{uuid4().hex[:8]}"
        run_2 = f"sim-{uuid4().hex[:8]}"

        # Submit 3 events under run_1 (threshold is 5)
        for _ in range(3):
            res = await RuleEngine.evaluate_rule(
                rule=rule,
                event_data={
                    "event_id": str(uuid4()),
                    "simulation_run_id": run_1,
                    "is_simulation": True,
                    "attributes": {"status": "FAILURE", "src_ip": shared_src_ip},
                },
                redis_client=redis_client,
            )
            assert res.matched is False

        # Submit 3 events under run_2 (threshold is 5)
        # If keys were NOT isolated, 3 + 3 = 6 >= 5 would falsely match on run_2!
        for _ in range(3):
            res = await RuleEngine.evaluate_rule(
                rule=rule,
                event_data={
                    "event_id": str(uuid4()),
                    "simulation_run_id": run_2,
                    "is_simulation": True,
                    "attributes": {"status": "FAILURE", "src_ip": shared_src_ip},
                },
                redis_client=redis_client,
            )
            assert res.matched is False, "Cross-run sliding window pollution detected: run_2 incorrectly matched!"
    finally:
        await redis_client.aclose()


@pytest.mark.asyncio
async def test_playbook_safety_forces_dry_run_on_simulated_incidents():
    """Core Safety Invariant: Any playbook execution against a simulation incident MUST force dry_run=True."""
    async with async_session_factory() as db_session:
        # Create test agent
        now_ts = datetime.now(timezone.utc)
        agent = AgentModel(
            id=uuid4(),
            hostname=f"test-target-host-{uuid4().hex[:6]}",
            os_family="linux",
            os_version="Ubuntu 24.04 LTS",
            primary_ip="192.168.1.50",
            mac_address="00:1C:42:AA:BB:CC",
            agent_version="2.0.0",
            status="ONLINE",
            api_token_hash=f"mock-token-hash-{uuid4().hex}",
            secret_key_enc="mock-secret",
            last_heartbeat=now_ts,
            registered_at=now_ts,
        )
        # Create test playbook
        playbook = PlaybookModel(
            id=uuid4(),
            name=f"Safety Dry Run Isolation Playbook {uuid4().hex[:8]}",
            description="Isolates infected host",
            action_steps=[
                {
                    "step_id": "step-1",
                    "action": "ISOLATE_HOST",
                    "parameters": {"reason": "test"},
                    "requires_approval": False,
                }
            ],
            requires_approval=False,
            is_active=True,
        )
        # Simulated incident
        sim_inc = IncidentModel(
            id=uuid4(),
            title="[SIMULATION] Web Shell Detected",
            description="Synthetic event",
            severity="CRITICAL",
            status="OPEN",
            composite_risk_score=90.0,
            affected_entities=["host:test-target-host"],
            is_simulation=True,
            simulation_run_id=f"sim-{uuid4().hex[:8]}",
        )
        db_session.add_all([agent, playbook, sim_inc])
        await db_session.commit()

        # Attempt to execute playbook with dry_run=False
        run = await PlaybookEngine.execute_playbook(
            session=db_session,
            playbook=playbook,
            incident=sim_inc,
            agent=agent,
            executed_by="analyst@example.com",
            dry_run=False,  # Explicitly requesting live containment
        )

        # Invariant: dry_run MUST be forced to True
        assert run.dry_run is True, "Security Invariant Violated: dry_run=False was permitted on a simulated incident!"


@pytest.mark.asyncio
async def test_coverage_matrix_rejects_rule_validation_if_negative_boundary_fails():
    """Verify that a detection rule is NOT marked as VALIDATED if its negative boundary test failed,

    even if its positive test passed (preventing false-positive prone rules from claiming validation).
    """
    async with async_session_factory() as db_session:
        sc_id = "brute-force"
        target_rule = "RULE-AUTH-001-BRUTEFORCE"

        now = datetime.now(timezone.utc)

        # 1. Positive run passed
        pos_run = SimulationRunModel(
            run_id=f"sim-pos-{uuid4().hex[:8]}",
            trace_id=f"trace-{uuid4().hex[:8]}",
            scenario_id=sc_id,
            scenario_name="Authentication Brute Force",
            target_rule_id=target_rule,
            is_negative_test=False,
            expected_detection=True,
            observed_detection=True,
            status="PASS",
            start_time=now,
        )
        # 2. Negative boundary run FAILED (e.g. false positive alert on benign traffic)
        neg_run = SimulationRunModel(
            run_id=f"sim-neg-{uuid4().hex[:8]}",
            trace_id=f"trace-{uuid4().hex[:8]}",
            scenario_id=sc_id,
            scenario_name="Authentication Brute Force",
            target_rule_id=target_rule,
            is_negative_test=True,
            expected_detection=False,
            observed_detection=True,  # Violated boundary!
            status="FAIL",
            start_time=now,
        )
        db_session.add_all([pos_run, neg_run])
        await db_session.commit()

        coverage = await get_simulation_coverage(_admin="test-key", session=db_session)

        # Find the scenario item
        sc_item = next(s for s in coverage.scenarios if s.scenario_id == sc_id)
        assert sc_item.positive_status == "VALIDATED"
        assert sc_item.negative_status == "FAILED"

        # Rule must NOT be in validated rules count because boundary failed
        assert coverage.validated_rules_count == 0
