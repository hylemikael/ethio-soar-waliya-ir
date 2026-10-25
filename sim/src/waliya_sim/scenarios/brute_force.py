"""Scenario A: Authentication Brute Force (MITRE T1110 / T1110.001)."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from uuid import UUID, uuid4

from waliya_sim.models import ExpectedOutcome
from waliya_sim.scenarios.base import BaseScenario


class BruteForceScenario(BaseScenario):
    """Deterministic simulation of credential brute-force attacks via authentication failure streams."""

    @property
    def scenario_id(self) -> str:
        return "brute-force"

    @property
    def name(self) -> str:
        return "Authentication Brute Force"

    @property
    def description(self) -> str:
        return (
            "Generates sequential failed authentication attempts against a target service "
            "from a synthetic source IP to trigger sliding-window rate threshold rules."
        )

    @property
    def mitre_attack_id(self) -> str:
        return "T1110.001"

    @property
    def target_rule_id(self) -> str:
        return "RULE-AUTH-001-BRUTEFORCE"

    @property
    def target_event_type(self) -> str:
        return "AUTHENTICATION"

    @property
    def threshold_description(self) -> str:
        return "5 or more authentication failures within a 300-second sliding window"

    @property
    def boundary_description(self) -> str:
        return "4 authentication failures (below threshold of 5), expecting no detection"

    def generate_events(
        self,
        run_id: str,
        trace_id: str,
        agent_id: UUID,
        is_negative: bool = False,
    ) -> List[Dict[str, Any]]:
        # Threshold for RULE-AUTH-001-BRUTEFORCE is >= 5 failures
        event_count = 4 if is_negative else 5

        # Deterministic synthetic IP in RFC 5737 documentation block (TEST-NET-2)
        import hashlib
        run_hash = hashlib.md5(run_id.encode("utf-8")).hexdigest()
        octet3 = (int(run_hash[:4], 16) % 250) + 1
        octet4 = (int(run_hash[4:8], 16) % 250) + 1
        synthetic_src_ip = f"198.51.{octet3}.{octet4}"
        target_user = f"sim-admin-{run_id[:8]}"

        now = datetime.now(timezone.utc)
        events: List[Dict[str, Any]] = []

        for i in range(event_count):
            # Timestamps spaced 2 seconds apart, all within recent window
            event_ts = now - timedelta(seconds=(event_count - i) * 2)
            event_id = uuid4()

            events.append({
                "event_id": str(event_id),
                "agent_id": str(agent_id),
                "event_type": self.target_event_type,
                "severity": "MEDIUM" if i < 4 else "HIGH",
                "timestamp": event_ts.isoformat(),
                "source": "waliya-sim:auth_collector",
                "payload": {
                    "service": "sshd",
                    "user": target_user,
                    "src_ip": synthetic_src_ip,
                    "status": "FAILURE",
                    "is_simulation": True,
                    "simulation_run_id": run_id,
                    "trace_id": trace_id,
                },
            })

        return events

    def expected_outcome(self, is_negative: bool = False) -> ExpectedOutcome:
        if is_negative:
            return ExpectedOutcome(
                should_detect=False,
                expected_rule_id=self.target_rule_id,
                expected_mitre_id=self.mitre_attack_id,
                expected_severity="HIGH",
                min_events_for_trigger=5,
                description="4 authentication failures remain below threshold; rule should not trigger",
            )
        return ExpectedOutcome(
            should_detect=True,
            expected_rule_id=self.target_rule_id,
            expected_mitre_id=self.mitre_attack_id,
            expected_severity="HIGH",
            min_events_for_trigger=5,
            description="5 authentication failures meet threshold; rule should trigger finding and incident",
        )
