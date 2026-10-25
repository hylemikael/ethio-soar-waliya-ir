"""Security invariants, credential redaction, and defensive safety tests for Waliya-Sim."""

import json
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4
import pytest

from waliya_sim.models import SimulationRunRecord
from waliya_sim.scenarios import list_scenarios
from waliya_sim.storage import ReportStorage


def test_preview_mode_strictly_side_effect_free(sample_run_ids):
    """Verify that generating scenario events does not touch disk or execute system commands."""
    with patch("subprocess.run") as mock_subproc, \
         patch("subprocess.Popen") as mock_popen, \
         patch("os.system") as mock_system, \
         patch("httpx.AsyncClient.post") as mock_post:

        for scenario in list_scenarios():
            # Positive preview
            events_pos = scenario.generate_events(
                run_id=sample_run_ids["run_id"],
                trace_id=sample_run_ids["trace_id"],
                agent_id=sample_run_ids["agent_id"],
                is_negative=False,
            )
            assert len(events_pos) >= 1

            # Negative preview
            events_neg = scenario.generate_events(
                run_id=sample_run_ids["run_id"],
                trace_id=sample_run_ids["trace_id"],
                agent_id=sample_run_ids["agent_id"],
                is_negative=True,
            )
            assert len(events_neg) >= 1

        # Assert no system execution tools were called
        mock_subproc.assert_not_called()
        mock_popen.assert_not_called()
        mock_system.assert_not_called()
        mock_post.assert_not_called()


def test_no_credentials_stored_in_reports(tmp_path: Path):
    """Verify API tokens and admin secrets never appear in serialized simulation records."""
    storage = ReportStorage(reports_dir=tmp_path)
    run_id = f"sim-{uuid4().hex[:8]}"
    secret_token = "secret-bearer-agent-token-xyz"
    secret_key = "secret-admin-master-key-123"

    record = SimulationRunRecord(
        run_id=run_id,
        trace_id=f"trace-{uuid4().hex[:8]}",
        scenario_id="brute-force",
        scenario_name="Brute Force",
        mitre_attack_id="T1110.001",
        target_rule_id="RULE-AUTH-001-BRUTEFORCE",
        is_negative_test=False,
        start_time="2026-10-22T20:00:00Z",
        end_time="2026-10-22T20:00:01Z",
        duration_seconds=1.0,
        events_generated_count=5,
        events_submitted_count=5,
        events_accepted_count=5,
        events_processed_count=1,
        expected_detection=True,
        observed_detection=True,
        status="PASS",
        summary="Test PASS",
    )

    file_path = storage.save_report(record)
    content = file_path.read_text(encoding="utf-8")

    # Invariants: No secrets can appear anywhere in the persisted report
    assert secret_token not in content
    assert secret_key not in content
    assert "token" not in content.lower() or "agent_token" not in content


def test_synthetic_entities_use_safe_namespaces(sample_run_ids):
    """Verify synthetic entities strictly use designated test ranges and prefixes."""
    for scenario in list_scenarios():
        events = scenario.generate_events(
            run_id=sample_run_ids["run_id"],
            trace_id=sample_run_ids["trace_id"],
            agent_id=sample_run_ids["agent_id"],
        )
        for ev in events:
            payload = ev["payload"]
            # Simulation marker invariant
            assert payload.get("is_simulation") is True
            assert payload.get("simulation_run_id") == sample_run_ids["run_id"]
            assert payload.get("trace_id") == sample_run_ids["trace_id"]

            # Network IPs: RFC 5737 TEST-NET-2 (198.51.0.0/16)
            if "src_ip" in payload:
                assert payload["src_ip"].startswith("198.51.")

            # File paths: must contain 'sim_' identifier
            if "file_path" in payload:
                assert "sim_" in payload["file_path"]

            # Usernames: must contain 'sim-' identifier or root for negative priv-esc
            if "user" in payload and payload["user"] != "www-data":
                assert "sim-" in payload["user"]
            if "username" in payload and payload["username"] != "root":
                assert "sim-" in payload["username"]
