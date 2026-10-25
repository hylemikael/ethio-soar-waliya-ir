"""Tests ensuring all simulated telemetry events strictly satisfy backend normalizer contracts."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import pytest

from waliya.contracts import EventTypeEnum, SecurityEventEnvelope, SeverityEnum
from waliya.telemetry.normalizer import normalize_event
from waliya_sim.scenarios import list_scenarios


@pytest.mark.parametrize("scenario", list_scenarios())
@pytest.mark.parametrize("is_negative", [False, True])
def test_all_scenarios_pass_backend_normalizer(scenario, is_negative, sample_run_ids):
    """Verify every event in every scenario normalizes cleanly without validation errors."""
    agent_id = sample_run_ids["agent_id"]
    events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=agent_id,
        is_negative=is_negative,
    )

    assert len(events) >= 1

    for ev_dict in events:
        envelope = SecurityEventEnvelope(
            event_id=UUID(ev_dict["event_id"]),
            event_type=EventTypeEnum(ev_dict["event_type"]),
            severity=SeverityEnum(ev_dict["severity"]),
            timestamp=datetime.fromisoformat(ev_dict["timestamp"]),
            source=ev_dict["source"],
            agent_id=agent_id,
            payload=ev_dict["payload"],
        )

        normalized = normalize_event(envelope, agent_id=agent_id)

        # Check normalization structure
        assert normalized["event_id"] == str(envelope.event_id)
        assert normalized["agent_id"] == str(agent_id)
        assert normalized["event_type"] == envelope.event_type.value
        assert "attributes" in normalized

        # Verify simulation markers are safely preserved
        assert normalized.get("is_simulation") is True
        assert normalized.get("simulation_run_id") == sample_run_ids["run_id"]
        assert normalized.get("trace_id") == sample_run_ids["trace_id"]
        assert normalized["attributes"].get("is_simulation") is True
        assert normalized["attributes"].get("simulation_run_id") == sample_run_ids["run_id"]
        assert normalized["attributes"].get("trace_id") == sample_run_ids["trace_id"]
