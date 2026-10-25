"""End-to-end integration tests validating closed-loop detection against the real backend pipeline."""

import asyncio
from pathlib import Path
from uuid import UUID, uuid4
import pytest
import pytest_asyncio
from httpx import ASGITransport
from sqlalchemy import delete, select

from waliya.config import settings
from waliya.core.crypto import hash_agent_token
from waliya.db.models import AgentModel, EventModel, EventOutboxModel, FindingModel, IncidentModel
from waliya.db.session import async_session_factory
from waliya.main import create_app
from waliya.telemetry.consumer_worker import TelemetryConsumerWorker

from waliya_sim.client import SimClient
from waliya_sim.config import SimConfig
from waliya_sim.engine import SimulationEngine
from waliya_sim.models import ScenarioOutcome
from waliya_sim.scenarios.brute_force import BruteForceScenario
from waliya_sim.scenarios.port_scan import PortScanScenario
from waliya_sim.scenarios.priv_esc import PrivilegeEscalationScenario
from waliya_sim.scenarios.web_shell import WebShellScenario


@pytest_asyncio.fixture
async def registered_sim_agent():
    """Register a verified endpoint agent in PostgreSQL for live telemetry testing."""
    agent_id = uuid4()
    raw_token = f"sim-agent-token-{uuid4().hex}"
    token_hash = hash_agent_token(raw_token, pepper=settings.AGENT_TOKEN_PEPPER)

    agent = AgentModel(
        id=agent_id,
        hostname=f"sim-sensor-{uuid4().hex[:6]}",
        os_family="linux",
        os_version="Ubuntu 24.04 LTS",
        primary_ip="192.168.1.199",
        mac_address=f"52:54:00:{uuid4().hex[:2]}:{uuid4().hex[:2]}:{uuid4().hex[:2]}",
        agent_version="2.0.0",
        status="ONLINE",
        api_token_hash=token_hash,
        secret_key_enc="enc_secret_placeholder",
    )

    async with async_session_factory() as session:
        session.add(agent)
        await session.commit()

    yield {
        "id": agent_id,
        "token": raw_token,
        "admin_key": settings.ADMIN_API_KEY,
    }

    # Teardown: purge test artifacts
    async with async_session_factory() as session:
        await session.execute(delete(FindingModel).where(FindingModel.agent_id == agent_id))
        await session.execute(delete(EventOutboxModel).where(
            EventOutboxModel.event_id.in_(
                select(EventModel.id).where(EventModel.agent_id == agent_id)
            )
        ))
        await session.execute(delete(EventModel).where(EventModel.agent_id == agent_id))
        await session.execute(delete(AgentModel).where(AgentModel.id == agent_id))
        await session.commit()


@pytest_asyncio.fixture
async def live_consumer_worker():
    """Run an active background TelemetryConsumerWorker loop during the test."""
    worker = TelemetryConsumerWorker(consumer_name=f"sim_worker_{uuid4().hex[:6]}")
    await worker.init_consumer_group()

    stop_event = asyncio.Event()

    async def _worker_loop():
        while not stop_event.is_set():
            try:
                await worker.process_batch(count=20, block_ms=100)
            except Exception:
                pass
            await asyncio.sleep(0.05)

    worker_task = asyncio.create_task(_worker_loop())

    yield worker

    stop_event.set()
    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass
    await worker.close()


@pytest.mark.asyncio
async def test_e2e_web_shell_positive_and_negative(
    registered_sim_agent,
    live_consumer_worker,
    tmp_path: Path,
):
    """End-to-end validation of Scenario B (Web Shell) positive trigger and negative boundary."""
    app = create_app()
    transport = ASGITransport(app=app)

    config = SimConfig(
        backend_url="http://testserver",
        agent_id=registered_sim_agent["id"],
        agent_token=registered_sim_agent["token"],
        admin_key=registered_sim_agent["admin_key"],
        timeout_seconds=5.0,
        poll_interval_seconds=0.1,
        reports_dir=tmp_path,
    )
    client = SimClient(
        base_url=config.backend_url,
        agent_id=config.agent_id,
        agent_token=config.agent_token,
        admin_key=config.admin_key,
        transport=transport,
    )
    engine = SimulationEngine(config, client=client)
    scenario = WebShellScenario()

    # 1. Execute Negative Boundary Run (.png file in web directory)
    neg_record = await engine.execute_scenario(scenario, is_negative=True)
    assert neg_record.status == ScenarioOutcome.PASS
    assert neg_record.observed_detection is False
    assert len(neg_record.matching_finding_ids) == 0

    # 2. Execute Positive Detection Run (.php file in web directory)
    pos_record = await engine.execute_scenario(scenario, is_negative=False)
    assert pos_record.status == ScenarioOutcome.PASS
    assert pos_record.observed_detection is True
    assert len(pos_record.matching_finding_ids) >= 1
    assert pos_record.latency_metrics.measurement_established is True
    assert pos_record.latency_metrics.latency_seconds is not None
    assert pos_record.latency_metrics.latency_seconds >= 0.0


@pytest.mark.asyncio
async def test_e2e_brute_force_positive_and_negative(
    registered_sim_agent,
    live_consumer_worker,
    tmp_path: Path,
):
    """End-to-end validation of Scenario A (Brute Force) positive trigger and negative boundary."""
    app = create_app()
    transport = ASGITransport(app=app)

    config = SimConfig(
        backend_url="http://testserver",
        agent_id=registered_sim_agent["id"],
        agent_token=registered_sim_agent["token"],
        admin_key=registered_sim_agent["admin_key"],
        timeout_seconds=6.0,
        poll_interval_seconds=0.1,
        reports_dir=tmp_path,
    )
    client = SimClient(
        base_url=config.backend_url,
        agent_id=config.agent_id,
        agent_token=config.agent_token,
        admin_key=config.admin_key,
        transport=transport,
    )
    engine = SimulationEngine(config, client=client)
    scenario = BruteForceScenario()

    # 1. Execute Negative Boundary Run (4 failures - below threshold of 5)
    neg_record = await engine.execute_scenario(scenario, is_negative=True)
    assert neg_record.status == ScenarioOutcome.PASS
    assert neg_record.observed_detection is False
    assert len(neg_record.matching_finding_ids) == 0

    # 2. Execute Positive Detection Run (5 failures - meets threshold)
    pos_record = await engine.execute_scenario(scenario, is_negative=False)
    assert pos_record.status == ScenarioOutcome.PASS
    assert pos_record.observed_detection is True
    assert len(pos_record.matching_finding_ids) >= 1


@pytest.mark.asyncio
async def test_e2e_port_scan_positive_and_negative(
    registered_sim_agent,
    live_consumer_worker,
    tmp_path: Path,
):
    """End-to-end validation of Scenario C (Port Scan) positive trigger and negative boundary."""
    app = create_app()
    transport = ASGITransport(app=app)

    config = SimConfig(
        backend_url="http://testserver",
        agent_id=registered_sim_agent["id"],
        agent_token=registered_sim_agent["token"],
        admin_key=registered_sim_agent["admin_key"],
        timeout_seconds=6.0,
        poll_interval_seconds=0.1,
        reports_dir=tmp_path,
    )
    client = SimClient(
        base_url=config.backend_url,
        agent_id=config.agent_id,
        agent_token=config.agent_token,
        admin_key=config.admin_key,
        transport=transport,
    )
    engine = SimulationEngine(config, client=client)
    scenario = PortScanScenario()

    # 1. Execute Negative Boundary Run (5 distinct ports - below threshold of 10)
    neg_record = await engine.execute_scenario(scenario, is_negative=True)
    assert neg_record.status == ScenarioOutcome.PASS
    assert neg_record.observed_detection is False
    assert len(neg_record.matching_finding_ids) == 0

    # 2. Execute Positive Detection Run (10 distinct ports - meets threshold)
    pos_record = await engine.execute_scenario(scenario, is_negative=False)
    assert pos_record.status == ScenarioOutcome.PASS
    assert pos_record.observed_detection is True
    assert len(pos_record.matching_finding_ids) >= 1


@pytest.mark.asyncio
async def test_e2e_privilege_escalation_positive_and_negative(
    registered_sim_agent,
    live_consumer_worker,
    tmp_path: Path,
):
    """End-to-end validation of Scenario D (Privilege Escalation) positive trigger and negative boundary."""
    app = create_app()
    transport = ASGITransport(app=app)

    config = SimConfig(
        backend_url="http://testserver",
        agent_id=registered_sim_agent["id"],
        agent_token=registered_sim_agent["token"],
        admin_key=registered_sim_agent["admin_key"],
        timeout_seconds=5.0,
        poll_interval_seconds=0.1,
        reports_dir=tmp_path,
    )
    client = SimClient(
        base_url=config.backend_url,
        agent_id=config.agent_id,
        agent_token=config.agent_token,
        admin_key=config.admin_key,
        transport=transport,
    )
    engine = SimulationEngine(config, client=client)
    scenario = PrivilegeEscalationScenario()

    # 1. Negative boundary (root executing sudo is benign)
    neg_record = await engine.execute_scenario(scenario, is_negative=True)
    assert neg_record.status == ScenarioOutcome.PASS
    assert neg_record.observed_detection is False
    assert len(neg_record.matching_finding_ids) == 0

    # 2. Positive detection (non-root operator executing sudo)
    pos_record = await engine.execute_scenario(scenario, is_negative=False)
    assert pos_record.status == ScenarioOutcome.PASS
    assert pos_record.observed_detection is True
    assert len(pos_record.matching_finding_ids) >= 1


@pytest.mark.asyncio
async def test_e2e_coverage_matrix_and_db_persistence_verification(
    registered_sim_agent,
    live_consumer_worker,
    tmp_path: Path,
):
    """End-to-end verification that completed simulation runs update the coverage matrix

    and persist valid isolated records in PostgreSQL.
    """
    app = create_app()
    transport = ASGITransport(app=app)

    config = SimConfig(
        backend_url="http://testserver",
        agent_id=registered_sim_agent["id"],
        agent_token=registered_sim_agent["token"],
        admin_key=registered_sim_agent["admin_key"],
        timeout_seconds=5.0,
        poll_interval_seconds=0.1,
        reports_dir=tmp_path,
    )
    client = SimClient(
        base_url=config.backend_url,
        agent_id=config.agent_id,
        agent_token=config.agent_token,
        admin_key=config.admin_key,
        transport=transport,
    )
    engine = SimulationEngine(config, client=client)
    scenario = WebShellScenario()

    # 1. Run negative boundary
    neg_res = await engine.execute_scenario(scenario, is_negative=True)
    assert neg_res.status == ScenarioOutcome.PASS

    # 2. Run positive detection
    pos_res = await engine.execute_scenario(scenario, is_negative=False)
    assert pos_res.status == ScenarioOutcome.PASS

    # 3. Query coverage matrix from API
    coverage = await client.fetch_simulation_coverage()
    assert "scenarios" in coverage
    ws_sc = next(s for s in coverage["scenarios"] if s["scenario_id"] == "web-shell")
    assert ws_sc["positive_status"] == "VALIDATED"
    assert ws_sc["negative_status"] == "VALIDATED"
    assert coverage.get("validated_rules_count", 0) >= 1

    # 4. Verify DB persistence and isolation flags
    async with async_session_factory() as db:
        # Check positive finding in DB
        res_finding = await db.execute(
            select(FindingModel).where(FindingModel.simulation_run_id == pos_res.run_id)
        )
        db_findings = res_finding.scalars().all()
        assert len(db_findings) >= 1
        for f in db_findings:
            assert f.is_simulation is True
            assert f.simulation_run_id == pos_res.run_id

        # Check positive incident in DB
        res_inc = await db.execute(
            select(IncidentModel).where(IncidentModel.simulation_run_id == pos_res.run_id)
        )
        db_incidents = res_inc.scalars().all()
        assert len(db_incidents) >= 1
        for inc in db_incidents:
            assert inc.is_simulation is True
            assert inc.simulation_run_id == pos_res.run_id
            assert inc.title.startswith("[SIMULATION]")
