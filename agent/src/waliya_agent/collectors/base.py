"""Base collector abstraction for security telemetry gatherers."""

import abc
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

logger = logging.getLogger("waliya_agent.collectors.base")


class BaseCollector(abc.ABC):
    """Abstract base class for periodic endpoint security telemetry collectors."""

    def __init__(self, agent_id: UUID, collector_name: str):
        self.agent_id = agent_id
        self.collector_name = collector_name

    @abc.abstractmethod
    async def collect(self) -> List[Dict[str, Any]]:
        """Collect and return a list of normalized security event dictionaries.

        Guarantees:
        - Must never raise unhandled exceptions; return empty list on failure.
        - Must never execute code or interpret data as shell commands.
        """
        pass

    def create_envelope(
        self,
        event_type: str,
        payload: Dict[str, Any],
        severity: str = "INFORMATIONAL",
        timestamp: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """Wrap payload in a standard SecurityEventEnvelope matching backend contracts."""
        ts = timestamp or datetime.now(timezone.utc)
        return {
            "event_id": str(uuid4()),
            "event_type": event_type,
            "severity": severity,
            "timestamp": ts.astimezone(timezone.utc).isoformat(),
            "source": f"agent:{self.collector_name}",
            "agent_id": str(self.agent_id),
            "payload": payload,
        }
