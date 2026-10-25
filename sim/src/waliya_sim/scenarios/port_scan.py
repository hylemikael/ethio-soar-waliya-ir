"""Scenario C: Network Port-Scan Behavior (MITRE T1046)."""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from uuid import UUID, uuid4

from waliya_sim.models import ExpectedOutcome
from waliya_sim.scenarios.base import BaseScenario


class PortScanScenario(BaseScenario):
    """Deterministic simulation of network reconnaissance and port scanning behavior."""

    @property
    def scenario_id(self) -> str:
        return "port-scan"

    @property
    def name(self) -> str:
        return "Network Port-Scan Behavior"

    @property
    def description(self) -> str:
        return (
            "Generates sequential network-connection observations showing one synthetic source IP "
            "contacting multiple distinct destination ports to trigger sliding-window port-scan rules."
        )

    @property
    def mitre_attack_id(self) -> str:
        return "T1046"

    @property
    def target_rule_id(self) -> str:
        return "RULE-NET-001-PORTSCAN"

    @property
    def target_event_type(self) -> str:
        return "NETWORK_CONNECTION"

    @property
    def threshold_description(self) -> str:
        return "10 or more distinct destination ports contacted within a 60-second sliding window"

    @property
    def boundary_description(self) -> str:
        return "5 distinct destination ports (below threshold of 10), expecting no detection"

    def generate_events(
        self,
        run_id: str,
        trace_id: str,
        agent_id: UUID,
        is_negative: bool = False,
    ) -> List[Dict[str, Any]]:
        # Threshold for RULE-NET-001-PORTSCAN is >= 10 distinct destination ports
        distinct_ports = [21, 22, 23, 25, 80] if is_negative else [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443]

        import hashlib
        run_hash = hashlib.md5(run_id.encode("utf-8")).hexdigest()
        octet3 = (int(run_hash[:4], 16) % 250) + 1
        octet4 = (int(run_hash[4:8], 16) % 250) + 1
        synthetic_src_ip = f"198.51.{octet3}.{octet4}"
        target_dst_ip = "192.168.1.100"

        now = datetime.now(timezone.utc)
        events: List[Dict[str, Any]] = []

        for i, port in enumerate(distinct_ports):
            event_ts = now - timedelta(seconds=(len(distinct_ports) - i))
            event_id = uuid4()

            events.append({
                "event_id": str(event_id),
                "agent_id": str(agent_id),
                "event_type": self.target_event_type,
                "severity": "LOW" if i < 9 else "MEDIUM",
                "timestamp": event_ts.isoformat(),
                "source": "waliya-sim:net_collector",
                "payload": {
                    "src_ip": synthetic_src_ip,
                    "src_port": 40000 + i,
                    "dst_ip": target_dst_ip,
                    "dst_port": port,
                    "protocol": "TCP",
                    "direction": "OUTBOUND",
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
                expected_severity="MEDIUM",
                min_events_for_trigger=10,
                description="5 distinct ports remain below threshold of 10; rule should not trigger",
            )
        return ExpectedOutcome(
            should_detect=True,
            expected_rule_id=self.target_rule_id,
            expected_mitre_id=self.mitre_attack_id,
            expected_severity="MEDIUM",
            min_events_for_trigger=10,
            description="10 distinct ports satisfy sliding-window threshold; rule should trigger finding",
        )
