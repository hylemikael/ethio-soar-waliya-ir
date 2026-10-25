"""Scenario D: Suspicious Privilege Escalation (MITRE T1548.003)."""

from datetime import datetime, timezone
from typing import Any, Dict, List
from uuid import UUID, uuid4

from waliya_sim.models import ExpectedOutcome
from waliya_sim.scenarios.base import BaseScenario


class PrivilegeEscalationScenario(BaseScenario):
    """Deterministic simulation of privilege escalation attempts via system elevation binaries."""

    @property
    def scenario_id(self) -> str:
        return "priv-esc"

    @property
    def name(self) -> str:
        return "Suspicious Privilege Escalation"

    @property
    def description(self) -> str:
        return (
            "Generates process execution telemetry representing a non-root user executing "
            "privilege elevation binaries (sudo, su, pkexec, doas) to acquire elevated privileges."
        )

    @property
    def mitre_attack_id(self) -> str:
        return "T1548.003"

    @property
    def target_rule_id(self) -> str:
        return "RULE-PROC-001-PRIVILEGE-ESC"

    @property
    def target_event_type(self) -> str:
        return "PROCESS_EXECUTION"

    @property
    def threshold_description(self) -> str:
        return "Process execution of /usr/bin/sudo, su, pkexec, or doas by any user other than root"

    @property
    def boundary_description(self) -> str:
        return "Execution of privilege binary by 'root' user, which is treated as legitimate administrative activity"

    def generate_events(
        self,
        run_id: str,
        trace_id: str,
        agent_id: UUID,
        is_negative: bool = False,
    ) -> List[Dict[str, Any]]:
        now = datetime.now(timezone.utc)
        event_id = uuid4()

        if is_negative:
            # Benign boundary: binary is executed directly by root user
            username = "root"
            cmdline = "sudo systemctl status nginx"
            severity = "INFORMATIONAL"
        else:
            # Elevation attempt by standard non-root user
            username = f"sim-operator-{run_id[:8]}"
            cmdline = "sudo -l"
            severity = "HIGH"

        return [
            {
                "event_id": str(event_id),
                "agent_id": str(agent_id),
                "event_type": self.target_event_type,
                "severity": severity,
                "timestamp": now.isoformat(),
                "source": "waliya-sim:proc_collector",
                "payload": {
                    "pid": 88001,
                    "ppid": 1000,
                    "exe": "/usr/bin/sudo",
                    "cmdline": cmdline,
                    "username": username,
                    "is_simulation": True,
                    "simulation_run_id": run_id,
                    "trace_id": trace_id,
                },
            }
        ]

    def expected_outcome(self, is_negative: bool = False) -> ExpectedOutcome:
        if is_negative:
            return ExpectedOutcome(
                should_detect=False,
                expected_rule_id=self.target_rule_id,
                expected_mitre_id=self.mitre_attack_id,
                expected_severity="HIGH",
                min_events_for_trigger=1,
                description="Root user executing sudo does not trigger privilege escalation rule",
            )
        return ExpectedOutcome(
            should_detect=True,
            expected_rule_id=self.target_rule_id,
            expected_mitre_id=self.mitre_attack_id,
            expected_severity="HIGH",
            min_events_for_trigger=1,
            description="Non-root user executing sudo matches privilege escalation rule conditions",
        )
