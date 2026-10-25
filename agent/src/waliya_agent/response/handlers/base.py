"""Base handler classes for agent defensive response actions."""

import abc
from dataclasses import dataclass, field
from typing import Any, Dict


@dataclass
class ExecutionResult:
    """Outcome of an action execution step."""
    status: str  # "EXECUTED" or "FAILED"
    exit_code: int
    output: str
    observed_state: Dict[str, Any] = field(default_factory=dict)
    dry_run: bool = False


class BaseActionHandler(abc.ABC):
    """Abstract base class for executing and verifying an individual response action."""

    def __init__(self, action_name: str):
        self.action_name = action_name

    @abc.abstractmethod
    async def execute(self, parameters: Dict[str, Any], dry_run: bool) -> ExecutionResult:
        """Execute the defensive action safely. If dry_run is True, must not modify system state."""
        pass

    @abc.abstractmethod
    async def verify_state(self, parameters: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
        """Inspect the operating system to collect independent evidence for containment verification."""
        pass
