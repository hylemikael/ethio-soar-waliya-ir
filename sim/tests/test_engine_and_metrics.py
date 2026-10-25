"""Tests for SimulationEngine, latency calculations, error handling, and storage."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
import pytest

from waliya_sim.client import SimClient
from waliya_sim.config import SimConfig
from waliya_sim.engine import SimulationEngine
from waliya_sim.models import DetectionLatencyMetrics, ScenarioOutcome, SimulationRunRecord
from waliya_sim.scenarios.web_shell import WebShellScenario
from waliya_sim.storage import ReportStorage


def test_storage_save_load_delete(tmp_path: Path):
    storage = ReportStorage(reports_dir=tmp_path)
    run_id = f"sim-{uuid4().hex[:10]}"

    record = SimulationRunRecord(
        run_id=run_id,
        trace_id=f"trace-{uuid4().hex[:10]}",
        scenario_id="web-shell",
        scenario_name="Suspicious Web File",
        mitre_attack_id="T1505.003",
        target_rule_id="RULE-FIM-004-WEBSHELL",
        is_negative_test=False,
        start_time="2026-10-22T20:00:00Z",
        end_time="2026-10-22T20:00:02Z",
        duration_seconds=2.0,
        events_generated_count=1,
        events_submitted_count=1,
        events_accepted_count=1,
        events_processed_count=1,
        expected_detection=True,
        observed_detection=True,
        status=ScenarioOutcome.PASS,
        matching_finding_ids=["finding-uuid-1"],
        matching_incident_ids=["incident-uuid-1"],
        summary="Test PASS",
    )

    path = storage.save_report(record)
    assert path.exists()

    loaded = storage.load_report(run_id)
    assert loaded is not None
    assert loaded.run_id == run_id
    assert loaded.status == ScenarioOutcome.PASS

    deleted = storage.delete_report(run_id)
    assert deleted is True
    assert storage.load_report(run_id) is None


@pytest.mark.asyncio
async def test_engine_backend_unreachable(tmp_path: Path):
    """When target backend is down, engine must report INCONCLUSIVE with clear error."""
    config = SimConfig(
        backend_url="http://127.0.0.1:59999",  # unreachable port
        agent_id=uuid4(),
        agent_token="token",
        admin_key="key",
        reports_dir=tmp_path,
        timeout_seconds=1.0,
    )
    engine = SimulationEngine(config)
    scenario = WebShellScenario()

    record = await engine.execute_scenario(scenario)
    assert record.status == ScenarioOutcome.INCONCLUSIVE
    assert "backend unreachable" in record.summary.lower()


@pytest.mark.asyncio
async def test_engine_registration_failure_aborts_telemetry(tmp_path: Path):
    """When registration fails, engine must NOT submit telemetry and must report INCONCLUSIVE."""
    config = SimConfig(
        backend_url="http://mock-backend",
        agent_id=uuid4(),
        agent_token="token",
        admin_key="key",
        reports_dir=tmp_path,
    )
    mock_client = MagicMock(spec=SimClient)
    mock_client.check_health = AsyncMock(return_value=(True, "OK"))
    mock_client.register_simulation_run = AsyncMock(side_effect=RuntimeError("HTTP 409 Conflict"))
    mock_client.ingest_batch = AsyncMock()

    engine = SimulationEngine(config, client=mock_client)
    scenario = WebShellScenario()

    record = await engine.execute_scenario(scenario)
    assert record.status == ScenarioOutcome.INCONCLUSIVE
    assert "registration rejected" in record.summary.lower()
    mock_client.ingest_batch.assert_not_called()


@pytest.mark.asyncio
async def test_engine_submission_failure_inconclusive(tmp_path: Path):
    """When submission is rejected (e.g. 401 unauthorized), report INCONCLUSIVE."""
    config = SimConfig(
        backend_url="http://mock-backend",
        agent_id=uuid4(),
        agent_token="bad-token",
        admin_key="adm-key",
        reports_dir=tmp_path,
    )
    mock_client = MagicMock(spec=SimClient)
    mock_client.check_health = AsyncMock(return_value=(True, "OK"))
    mock_client.register_simulation_run = AsyncMock(return_value={"status": "RUNNING"})
    mock_client.ingest_batch = AsyncMock(side_effect=RuntimeError("HTTP 401 Unauthorized"))

    engine = SimulationEngine(config, client=mock_client)
    scenario = WebShellScenario()

    record = await engine.execute_scenario(scenario)
    assert record.status == ScenarioOutcome.INCONCLUSIVE
    assert "submission rejected" in record.summary.lower()


@pytest.mark.asyncio
async def test_engine_positive_timeout_fail(tmp_path: Path):
    """When expected finding is not found before deadline, positive test must FAIL."""
    config = SimConfig(
        backend_url="http://mock-backend",
        agent_id=uuid4(),
        agent_token="token",
        admin_key="key",
        timeout_seconds=0.2,
        poll_interval_seconds=0.05,
        reports_dir=tmp_path,
    )
    mock_client = MagicMock(spec=SimClient)
    mock_client.check_health = AsyncMock(return_value=(True, "OK"))
    mock_client.register_simulation_run = AsyncMock(return_value={"status": "RUNNING"})
    mock_client.ingest_batch = AsyncMock(return_value={"processed_count": 1})
    mock_client.flush_outbox = AsyncMock(return_value=1)
    mock_client.fetch_findings = AsyncMock(return_value=[])  # no findings
    mock_client.finalize_simulation_run = AsyncMock(return_value={"status": "FAIL"})

    engine = SimulationEngine(config, client=mock_client)
    scenario = WebShellScenario()

    record = await engine.execute_scenario(scenario, is_negative=False)
    assert record.status == ScenarioOutcome.FAIL
    assert record.observed_detection is False
    assert "did not trigger" in record.summary.lower()


@pytest.mark.asyncio
async def test_engine_negative_boundary_pass(tmp_path: Path):
    """When sub-threshold events yield zero findings, boundary test must PASS."""
    config = SimConfig(
        backend_url="http://mock-backend",
        agent_id=uuid4(),
        agent_token="token",
        admin_key="key",
        timeout_seconds=0.2,
        poll_interval_seconds=0.05,
        reports_dir=tmp_path,
    )
    mock_client = MagicMock(spec=SimClient)
    mock_client.check_health = AsyncMock(return_value=(True, "OK"))
    mock_client.register_simulation_run = AsyncMock(return_value={"status": "RUNNING"})
    mock_client.ingest_batch = AsyncMock(return_value={"processed_count": 1})
    mock_client.flush_outbox = AsyncMock(return_value=1)
    mock_client.fetch_findings = AsyncMock(return_value=[])  # no findings
    mock_client.finalize_simulation_run = AsyncMock(return_value={"status": "PASS"})

    engine = SimulationEngine(config, client=mock_client)
    scenario = WebShellScenario()

    record = await engine.execute_scenario(scenario, is_negative=True)
    assert record.status == ScenarioOutcome.PASS
    assert record.observed_detection is False
    assert "correctly rejected" in record.summary.lower()


@pytest.mark.asyncio
async def test_latency_calculation_accuracy(tmp_path: Path):
    """Verify real latency computation between first event timestamp and finding timestamp."""
    config = SimConfig(
        backend_url="http://mock-backend",
        agent_id=uuid4(),
        agent_token="token",
        admin_key="key",
        timeout_seconds=1.0,
        reports_dir=tmp_path,
    )
    scenario = WebShellScenario()

    t0 = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)
    tf = datetime(2026, 10, 22, 12, 0, 1, 350000, tzinfo=timezone.utc)

    mock_client = MagicMock(spec=SimClient)
    mock_client.check_health = AsyncMock(return_value=(True, "OK"))
    mock_client.register_simulation_run = AsyncMock(return_value={"status": "RUNNING"})
    mock_client.ingest_batch = AsyncMock(return_value={"processed_count": 1})
    mock_client.flush_outbox = AsyncMock(return_value=1)
    mock_client.fetch_findings = AsyncMock(return_value=[
        {
            "id": "mock-finding-id",
            "timestamp": tf.isoformat(),
            "explanation": {"rule_id": scenario.target_rule_id},
        }
    ])
    mock_client.fetch_incidents = AsyncMock(return_value=[])
    mock_client.finalize_simulation_run = AsyncMock(return_value={"status": "PASS"})

    engine = SimulationEngine(config, client=mock_client)

    # Monkeypatch generate_events to use deterministic t0
    orig_generate = scenario.generate_events

    def fixed_generate(*args, **kwargs):
        events = orig_generate(*args, **kwargs)
        events[0]["timestamp"] = t0.isoformat()
        return events

    scenario.generate_events = fixed_generate

    record = await engine.execute_scenario(scenario, is_negative=False)
    assert record.status == ScenarioOutcome.PASS
    assert record.latency_metrics.measurement_established is True
    assert record.latency_metrics.latency_seconds == pytest.approx(1.35, 0.01)
