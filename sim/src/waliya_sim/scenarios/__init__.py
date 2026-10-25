"""Scenario registry and factory functions for Waliya-Sim."""

from typing import Dict, List, Optional

from waliya_sim.scenarios.base import BaseScenario
from waliya_sim.scenarios.brute_force import BruteForceScenario
from waliya_sim.scenarios.port_scan import PortScanScenario
from waliya_sim.scenarios.priv_esc import PrivilegeEscalationScenario
from waliya_sim.scenarios.web_shell import WebShellScenario

_SCENARIOS: List[BaseScenario] = [
    BruteForceScenario(),
    WebShellScenario(),
    PortScanScenario(),
    PrivilegeEscalationScenario(),
]

_ALIASES: Dict[str, str] = {
    "brute-force": "brute-force",
    "bruteforce": "brute-force",
    "auth": "brute-force",
    "t1110": "brute-force",
    "t1110.001": "brute-force",
    "web-shell": "web-shell",
    "webshell": "web-shell",
    "fim": "web-shell",
    "t1505": "web-shell",
    "t1505.003": "web-shell",
    "port-scan": "port-scan",
    "portscan": "port-scan",
    "net": "port-scan",
    "t1046": "port-scan",
    "priv-esc": "priv-esc",
    "privesc": "priv-esc",
    "privilege-escalation": "priv-esc",
    "proc": "priv-esc",
    "t1548": "priv-esc",
    "t1548.003": "priv-esc",
}


def list_scenarios() -> List[BaseScenario]:
    """Return all available deterministic purple-team simulation scenarios."""
    return list(_SCENARIOS)


def get_scenario(identifier: str) -> Optional[BaseScenario]:
    """Retrieve scenario by ID or alias, case-insensitively."""
    canonical = _ALIASES.get(identifier.strip().lower())
    if not canonical:
        return None
    for s in _SCENARIOS:
        if s.scenario_id == canonical:
            return s
    return None
