"""Unit tests for deterministic purple-team scenario definitions."""

from datetime import datetime
from uuid import uuid4
import pytest

from waliya_sim.scenarios import get_scenario, list_scenarios
from waliya_sim.scenarios.brute_force import BruteForceScenario
from waliya_sim.scenarios.port_scan import PortScanScenario
from waliya_sim.scenarios.priv_esc import PrivilegeEscalationScenario
from waliya_sim.scenarios.web_shell import WebShellScenario


def test_scenario_registry_and_aliases():
    """Verify all 4 required scenarios are registered and accessible by aliases."""
    scenarios = list_scenarios()
    assert len(scenarios) == 4

    ids = {s.scenario_id for s in scenarios}
    assert ids == {"brute-force", "web-shell", "port-scan", "priv-esc"}

    # Test aliases
    assert isinstance(get_scenario("brute-force"), BruteForceScenario)
    assert isinstance(get_scenario("t1110"), BruteForceScenario)
    assert isinstance(get_scenario("auth"), BruteForceScenario)

    assert isinstance(get_scenario("web-shell"), WebShellScenario)
    assert isinstance(get_scenario("t1505"), WebShellScenario)
    assert isinstance(get_scenario("fim"), WebShellScenario)

    assert isinstance(get_scenario("port-scan"), PortScanScenario)
    assert isinstance(get_scenario("t1046"), PortScanScenario)
    assert isinstance(get_scenario("net"), PortScanScenario)

    assert isinstance(get_scenario("priv-esc"), PrivilegeEscalationScenario)
    assert isinstance(get_scenario("t1548"), PrivilegeEscalationScenario)
    assert isinstance(get_scenario("proc"), PrivilegeEscalationScenario)

    assert get_scenario("non-existent-scenario") is None


def test_brute_force_scenario_events(sample_run_ids):
    scenario = BruteForceScenario()
    assert scenario.mitre_attack_id == "T1110.001"
    assert scenario.target_rule_id == "RULE-AUTH-001-BRUTEFORCE"

    # Positive generation
    pos_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=False,
    )
    assert len(pos_events) == 5
    for ev in pos_events:
        assert ev["event_type"] == "AUTHENTICATION"
        assert ev["payload"]["is_simulation"] is True
        assert ev["payload"]["simulation_run_id"] == sample_run_ids["run_id"]
        assert ev["payload"]["trace_id"] == sample_run_ids["trace_id"]
        assert ev["payload"]["status"] == "FAILURE"

    # Negative generation (threshold boundary)
    neg_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=True,
    )
    assert len(neg_events) == 4

    # Timestamp ordering check
    timestamps = [datetime.fromisoformat(ev["timestamp"]) for ev in pos_events]
    for i in range(len(timestamps) - 1):
        assert timestamps[i] <= timestamps[i + 1]

    assert scenario.expected_outcome(is_negative=False).should_detect is True
    assert scenario.expected_outcome(is_negative=True).should_detect is False


def test_web_shell_scenario_events(sample_run_ids):
    scenario = WebShellScenario()
    assert scenario.mitre_attack_id == "T1505.003"
    assert scenario.target_rule_id == "RULE-FIM-004-WEBSHELL"

    pos_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=False,
    )
    assert len(pos_events) == 1
    ev = pos_events[0]
    assert ev["event_type"] == "FILE_INTEGRITY"
    assert ev["payload"]["file_path"].endswith(".php")
    assert "/var/www" in ev["payload"]["file_path"]
    assert ev["payload"]["action"] == "CREATED"
    assert ev["payload"]["is_simulation"] is True

    neg_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=True,
    )
    assert len(neg_events) == 1
    assert neg_events[0]["payload"]["file_path"].endswith(".png")

    assert scenario.expected_outcome(is_negative=False).should_detect is True
    assert scenario.expected_outcome(is_negative=True).should_detect is False


def test_port_scan_scenario_events(sample_run_ids):
    scenario = PortScanScenario()
    assert scenario.mitre_attack_id == "T1046"
    assert scenario.target_rule_id == "RULE-NET-001-PORTSCAN"

    pos_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=False,
    )
    assert len(pos_events) == 10
    ports = [e["payload"]["dst_port"] for e in pos_events]
    assert len(set(ports)) == 10
    for ev in pos_events:
        assert ev["event_type"] == "NETWORK_CONNECTION"
        assert ev["payload"]["is_simulation"] is True

    neg_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=True,
    )
    assert len(neg_events) == 5
    neg_ports = [e["payload"]["dst_port"] for e in neg_events]
    assert len(set(neg_ports)) == 5

    assert scenario.expected_outcome(is_negative=False).should_detect is True
    assert scenario.expected_outcome(is_negative=True).should_detect is False


def test_privilege_escalation_scenario_events(sample_run_ids):
    scenario = PrivilegeEscalationScenario()
    assert scenario.mitre_attack_id == "T1548.003"
    assert scenario.target_rule_id == "RULE-PROC-001-PRIVILEGE-ESC"

    pos_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=False,
    )
    assert len(pos_events) == 1
    ev = pos_events[0]
    assert ev["event_type"] == "PROCESS_EXECUTION"
    assert ev["payload"]["exe"] == "/usr/bin/sudo"
    assert ev["payload"]["username"] != "root"
    assert ev["payload"]["is_simulation"] is True

    neg_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=True,
    )
    assert len(neg_events) == 1
    assert neg_events[0]["payload"]["username"] == "root"

    assert scenario.expected_outcome(is_negative=False).should_detect is True
    assert scenario.expected_outcome(is_negative=True).should_detect is False
