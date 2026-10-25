"""Tests for Waliya-Sim CLI commands, formatting, and exit codes."""

import json
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4
import pytest

from waliya_sim.cli import cmd_clean, cmd_list, cmd_matrix, cmd_preview, cmd_report, main
from waliya_sim.models import ScenarioOutcome, SimulationRunRecord
from waliya_sim.storage import ReportStorage


class DummyArgs:
    def __init__(self, **kwargs):
        for k, v in kwargs.items():
            setattr(self, k, v)


def test_cli_list_command(capsys):
    # Plain text table
    args = DummyArgs(json=False)
    ret = cmd_list(args)
    assert ret == 0
    capsys.readouterr()  # Flush stdout buffer

    # JSON output
    args_json = DummyArgs(json=True)
    ret_json = cmd_list(args_json)
    assert ret_json == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert len(data) == 4
    assert any(d["scenario_id"] == "brute-force" for d in data)


def test_cli_preview_command(capsys):
    # Positive preview
    args = DummyArgs(scenario="web-shell", negative=False, json=False)
    ret = cmd_preview(args)
    assert ret == 0
    capsys.readouterr()  # Flush stdout buffer

    # Negative preview JSON
    args_json = DummyArgs(scenario="brute-force", negative=True, json=True)
    ret_json = cmd_preview(args_json)
    assert ret_json == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["is_negative"] is True
    assert len(data["events"]) == 4

    # Unknown scenario
    args_bad = DummyArgs(scenario="unknown-technique", negative=False, json=False)
    ret_bad = cmd_preview(args_bad)
    assert ret_bad == 1


def test_cli_report_command(tmp_path: Path, capsys):
    storage = ReportStorage(reports_dir=tmp_path)
    run_id = f"sim-{uuid4().hex[:8]}"
    record = SimulationRunRecord(
        run_id=run_id,
        trace_id=f"trace-{uuid4().hex[:8]}",
        scenario_id="port-scan",
        scenario_name="Network Port-Scan",
        mitre_attack_id="T1046",
        target_rule_id="RULE-NET-001-PORTSCAN",
        is_negative_test=False,
        start_time="2026-10-22T20:00:00Z",
        end_time="2026-10-22T20:00:03Z",
        duration_seconds=3.0,
        events_generated_count=10,
        events_submitted_count=10,
        events_accepted_count=10,
        events_processed_count=1,
        expected_detection=True,
        observed_detection=True,
        status=ScenarioOutcome.PASS,
        summary="Test Port Scan PASS",
    )
    storage.save_report(record)

    # Valid report lookup
    args = DummyArgs(run_id=run_id, reports_dir=tmp_path, json=False)
    assert cmd_report(args) == 0
    capsys.readouterr()  # Flush stdout buffer

    # Valid report lookup JSON
    args_json = DummyArgs(run_id=run_id, reports_dir=tmp_path, json=True)
    assert cmd_report(args_json) == 0
    captured = capsys.readouterr()
    loaded_data = json.loads(captured.out)
    assert loaded_data["run_id"] == run_id

    # Not found report
    args_bad = DummyArgs(run_id="non-existent-run", reports_dir=tmp_path, json=False)
    assert cmd_report(args_bad) == 1


def test_cli_clean_command(tmp_path: Path):
    storage = ReportStorage(reports_dir=tmp_path)
    run_id = f"sim-{uuid4().hex[:8]}"
    record = SimulationRunRecord(
        run_id=run_id,
        trace_id=f"trace-{uuid4().hex[:8]}",
        scenario_id="priv-esc",
        scenario_name="Priv Esc",
        mitre_attack_id="T1548.003",
        target_rule_id="RULE-PROC-001-PRIVILEGE-ESC",
        is_negative_test=False,
        start_time="2026-10-22T20:00:00Z",
        end_time="2026-10-22T20:00:01Z",
        duration_seconds=1.0,
        events_generated_count=1,
        events_submitted_count=1,
        events_accepted_count=1,
        events_processed_count=1,
        expected_detection=True,
        observed_detection=True,
        status=ScenarioOutcome.PASS,
        summary="Test Clean",
    )
    storage.save_report(record)
    assert len(storage.list_reports()) == 1

    # Clean single report
    args_single = DummyArgs(run_id=run_id, reports_dir=tmp_path)
    assert cmd_clean(args_single) == 0
    assert len(storage.list_reports()) == 0

    # Clean all reports
    storage.save_report(record)
    args_all = DummyArgs(run_id=None, reports_dir=tmp_path)
    assert cmd_clean(args_all) == 0
    assert len(storage.list_reports()) == 0


def test_cli_matrix_command(capsys):
    mock_coverage = {
        "total_rules_count": 4,
        "validated_rules_count": 2,
        "scenarios": [
            {
                "scenario_id": "brute-force",
                "scenario_name": "Authentication Brute Force",
                "mitre_attack_id": "T1110.001",
                "target_rule_id": "RULE-AUTH-001-BRUTEFORCE",
                "positive_status": "VALIDATED",
                "negative_status": "VALIDATED",
            },
            {
                "scenario_id": "web-shell",
                "scenario_name": "Suspicious Web File",
                "mitre_attack_id": "T1505.003",
                "target_rule_id": "RULE-FIM-001-WEBSHELL",
                "positive_status": "VALIDATED",
                "negative_status": "NOT_TESTED",
            },
        ],
    }

    with patch("waliya_sim.client.SimClient.fetch_simulation_coverage", return_value=mock_coverage):
        # Table output
        args = DummyArgs(url=None, admin_key=None, json=False)
        assert cmd_matrix(args) == 0
        capsys.readouterr()

        # JSON output
        args_json = DummyArgs(url=None, admin_key=None, json=True)
        assert cmd_matrix(args_json) == 0
        captured = capsys.readouterr()
        data = json.loads(captured.out)
        assert data["validated_rules_count"] == 2
        assert len(data["scenarios"]) == 2
