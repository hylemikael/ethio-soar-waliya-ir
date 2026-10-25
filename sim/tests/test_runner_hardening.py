"""Hardening and resilience tests for the simulation runner and detection pipeline.

Tests event generation resilience, sliding-window boundary conditions, duplicate event ID
idempotency, interleaved runs, and out-of-window timestamp behavior.
"""

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import AsyncMock, patch
from uuid import uuid4
import pytest
from redis.asyncio import Redis

from waliya.config import settings
from waliya.detection.builtin_rules import BUILTIN_RULES
from waliya.detection.rule_engine import RuleEngine
from waliya_sim.config import SimConfig
from waliya_sim.engine import SimulationEngine
from waliya_sim.models import ExpectedOutcome, ScenarioOutcome, SimulationRunRecord
from waliya_sim.scenarios.base import BaseScenario


def _get_rule(rule_id: str):
    for r in BUILTIN_RULES:
        if r.rule_id == rule_id:
            return r
    raise ValueError(f"Rule {rule_id} not found in BUILTIN_RULES")


@pytest.mark.asyncio
async def test_duplicate_event_id_idempotence_in_sliding_window():
    """Verify that duplicate submissions of identical event IDs do not inflate

    the sliding window count or cause false-positive threshold alerts.
    """
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    rule = _get_rule("RULE-AUTH-001-BRUTEFORCE")
    sim_run_id = f"sim-{uuid4().hex[:8]}"
    src_ip = "198.51.100.44"
    duplicate_event_id = str(uuid4())

    try:
        # Submit the same event ID 10 times
        for _ in range(10):
            event_dict = {
                "event_id": duplicate_event_id,
                "event_type": "AUTHENTICATION",
                "is_simulation": True,
                "simulation_run_id": sim_run_id,
                "attributes": {
                    "status": "FAILURE",
                    "src_ip": src_ip,
                    "user": "victim-user",
                },
            }
            res = await RuleEngine.evaluate_rule(rule, event_dict, redis_client=redis)
            # Threshold is 5. Because event_id is identical, count must remain 1 and NOT match!
            assert res.matched is False, "Duplicate event_id inflated window count and caused false match!"

        # Now submit 4 NEW distinct event IDs (total distinct: 1 + 4 = 5)
        for i in range(4):
            event_dict = {
                "event_id": str(uuid4()),
                "event_type": "AUTHENTICATION",
                "is_simulation": True,
                "simulation_run_id": sim_run_id,
                "attributes": {
                    "status": "FAILURE",
                    "src_ip": src_ip,
                    "user": "victim-user",
                },
            }
            res = await RuleEngine.evaluate_rule(rule, event_dict, redis_client=redis)
            if i < 3:
                assert res.matched is False
            else:
                # 5th distinct event reaches threshold
                assert res.matched is True
    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_repeated_port_access_does_not_inflate_distinct_port_count():
    """Verify that multiple network connections to the SAME port do not inflate

    the port scan distinct port counter.
    """
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    rule = _get_rule("RULE-NET-001-PORTSCAN")
    sim_run_id = f"sim-{uuid4().hex[:8]}"
    src_ip = "198.51.100.55"

    try:
        # Submit 15 events targeting ONLY port 80 and 443
        for i in range(15):
            port = 80 if i % 2 == 0 else 443
            event_dict = {
                "event_id": str(uuid4()),
                "event_type": "NETWORK_CONNECTION",
                "is_simulation": True,
                "simulation_run_id": sim_run_id,
                "attributes": {
                    "src_ip": src_ip,
                    "dst_port": port,
                    "dst_ip": "198.51.100.1",
                    "direction": "OUTBOUND",
                },
            }
            res = await RuleEngine.evaluate_rule(rule, event_dict, redis_client=redis)
            # Distinct ports is at most 2, threshold is 10
            assert res.matched is False, f"Repeated port {port} inflated distinct port count!"
    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_interleaved_concurrent_simulation_runs():
    """Verify that two simulation runs interleaving events with the same target entity

    maintain completely isolated sliding windows.
    """
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    rule = _get_rule("RULE-AUTH-001-BRUTEFORCE")

    run_a = f"sim-run-a-{uuid4().hex[:6]}"
    run_b = f"sim-run-b-{uuid4().hex[:6]}"
    shared_src_ip = "198.51.100.66"

    try:
        # Interleave 4 events for run_a and 4 events for run_b (total 8 events)
        # Threshold is 5. Neither run should trigger!
        for _ in range(4):
            # Run A event
            res_a = await RuleEngine.evaluate_rule(
                rule,
                {
                    "event_id": str(uuid4()),
                    "event_type": "AUTHENTICATION",
                    "is_simulation": True,
                    "simulation_run_id": run_a,
                    "attributes": {"status": "FAILURE", "src_ip": shared_src_ip},
                },
                redis_client=redis,
            )
            assert res_a.matched is False, "Run A triggered prematurely!"

            # Run B event
            res_b = await RuleEngine.evaluate_rule(
                rule,
                {
                    "event_id": str(uuid4()),
                    "event_type": "AUTHENTICATION",
                    "is_simulation": True,
                    "simulation_run_id": run_b,
                    "attributes": {"status": "FAILURE", "src_ip": shared_src_ip},
                },
                redis_client=redis,
            )
            assert res_b.matched is False, "Run B triggered prematurely!"

        # Now send 5th event ONLY to Run A -> Run A matches, Run B remains unmatched
        res_a_final = await RuleEngine.evaluate_rule(
            rule,
            {
                "event_id": str(uuid4()),
                "event_type": "AUTHENTICATION",
                "is_simulation": True,
                "simulation_run_id": run_a,
                "attributes": {"status": "FAILURE", "src_ip": shared_src_ip},
            },
            redis_client=redis,
        )
        assert res_a_final.matched is True, "Run A failed to match on 5th event!"

        # Check Run B with another event (now 5 for B) -> Run B matches independently
        res_b_final = await RuleEngine.evaluate_rule(
            rule,
            {
                "event_id": str(uuid4()),
                "event_type": "AUTHENTICATION",
                "is_simulation": True,
                "simulation_run_id": run_b,
                "attributes": {"status": "FAILURE", "src_ip": shared_src_ip},
            },
            redis_client=redis,
        )
        assert res_b_final.matched is True, "Run B failed to match on 5th event!"
    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_out_of_window_timestamp_eviction():
    """Verify that events older than the sliding window (300s) are evicted from Redis

    and do not count toward threshold satisfaction.
    """
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)
    rule = _get_rule("RULE-AUTH-001-BRUTEFORCE")
    sim_run_id = f"sim-{uuid4().hex[:8]}"
    src_ip = "198.51.100.77"
    key = f"waliya:win:sim:{sim_run_id}:auth_fail:{src_ip}"

    try:
        now_ts = datetime.now(timezone.utc).timestamp()
        # Seed 4 events that happened 400 seconds ago (outside 300s window)
        old_events = {f"old-ev-{i}": now_ts - 400 for i in range(4)}
        await redis.zadd(key, old_events)

        # Submit 1 new event now
        res = await RuleEngine.evaluate_rule(
            rule,
            {
                "event_id": str(uuid4()),
                "event_type": "AUTHENTICATION",
                "is_simulation": True,
                "simulation_run_id": sim_run_id,
                "attributes": {"status": "FAILURE", "src_ip": src_ip},
            },
            redis_client=redis,
        )

        # Invariant: Old events were evicted by zremrangebyscore; failure count is 1, not 5!
        assert res.matched is False, "Expired events were counted in sliding window!"

        remaining_count = await redis.zcard(key)
        assert remaining_count == 1
    finally:
        await redis.aclose()


class EmptyScenario(BaseScenario):
    """Scenario that produces zero events for failure testing."""
    @property
    def scenario_id(self) -> str:
        return "empty-scenario"

    @property
    def name(self) -> str:
        return "Empty Scenario"

    @property
    def description(self) -> str:
        return "Test scenario producing no events"

    @property
    def mitre_attack_id(self) -> str:
        return "T0000"

    @property
    def target_rule_id(self) -> str:
        return "RULE-AUTH-001-BRUTEFORCE"

    @property
    def target_event_type(self) -> str:
        return "AUTHENTICATION"

    @property
    def threshold_description(self) -> str:
        return "None"

    @property
    def boundary_description(self) -> str:
        return "None"

    def generate_events(self, run_id, trace_id, agent_id, is_negative=False):
        return []

    def expected_outcome(self, is_negative: bool = False) -> ExpectedOutcome:
        return ExpectedOutcome(
            should_detect=True,
            expected_rule_id=self.target_rule_id,
            expected_mitre_id=self.mitre_attack_id,
            expected_severity="HIGH",
        )


@pytest.mark.asyncio
async def test_zero_event_submission_rejected_by_engine(tmp_path: Path):
    """Verify that a simulation run generating zero events cannot pass."""
    config = SimConfig(
        backend_url="http://testserver",
        agent_id=uuid4(),
        agent_token="mock-token",
        admin_key="mock-key",
        reports_dir=tmp_path,
    )
    mock_client = AsyncMock()
    mock_client.check_health.return_value = (True, "OK")
    mock_client.register_run.return_value = {
        "run_id": "sim-empty-001",
        "trace_id": "trace-empty-001",
    }
    mock_client.submit_telemetry.return_value = {
        "status": "ACCEPTED",
        "accepted_count": 0,
        "rejected_count": 0,
    }
    mock_client.finalize_run.return_value = {"status": "SUCCESS"}

    engine = SimulationEngine(config, client=mock_client)
    record = await engine.execute_scenario(EmptyScenario())

    assert record.status == ScenarioOutcome.FAIL
    assert record.events_generated_count == 0
    assert "No events generated" in record.summary
