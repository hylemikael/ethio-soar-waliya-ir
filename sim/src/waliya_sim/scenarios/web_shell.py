"""Scenario B: Suspicious Web File (MITRE T1505.003)."""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List
from uuid import UUID, uuid4

from waliya_sim.models import ExpectedOutcome
from waliya_sim.scenarios.base import BaseScenario


class WebShellScenario(BaseScenario):
    """Deterministic simulation of suspicious web script deployment in monitored web directories."""

    @property
    def scenario_id(self) -> str:
        return "web-shell"

    @property
    def name(self) -> str:
        return "Suspicious Web File (Web Shell)"

    @property
    def description(self) -> str:
        return (
            "Generates synthetic file-integrity telemetry representing the creation or "
            "modification of an executable script file within a protected web server directory."
        )

    @property
    def mitre_attack_id(self) -> str:
        return "T1505.003"

    @property
    def target_rule_id(self) -> str:
        return "RULE-FIM-004-WEBSHELL"

    @property
    def target_event_type(self) -> str:
        return "FILE_INTEGRITY"

    @property
    def threshold_description(self) -> str:
        return "Single file-integrity CREATED or MODIFIED event with executable script extension in web root"

    @property
    def boundary_description(self) -> str:
        return "Creation of non-executable image file (.png) in web directory, expecting no detection"

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
            # Benign file extension (.png) does not match script regex
            file_path = f"/var/www/html/sim_asset_{run_id[:8]}.png"
            is_executable = False
            severity = "INFORMATIONAL"
        else:
            # Suspicious .php script inside standard web root
            file_path = f"/var/www/html/sim_shell_{run_id[:8]}.php"
            is_executable = True
            severity = "HIGH"

        # Deterministic synthetic content hash
        synthetic_hash = hashlib.sha256(f"{run_id}:{file_path}".encode("utf-8")).hexdigest()

        return [
            {
                "event_id": str(event_id),
                "agent_id": str(agent_id),
                "event_type": self.target_event_type,
                "severity": severity,
                "timestamp": now.isoformat(),
                "source": "waliya-sim:fim_collector",
                "payload": {
                    "file_path": file_path,
                    "action": "CREATED",
                    "sha256": synthetic_hash,
                    "size_bytes": 2048,
                    "is_executable": is_executable,
                    "user": "www-data",
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
                description="Image file (.png) does not match script extensions; rule should not trigger",
            )
        return ExpectedOutcome(
            should_detect=True,
            expected_rule_id=self.target_rule_id,
            expected_mitre_id=self.mitre_attack_id,
            expected_severity="HIGH",
            min_events_for_trigger=1,
            description="PHP script creation in web directory matches web shell rule conditions",
        )
