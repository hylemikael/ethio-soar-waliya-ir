"""Configuration management for Waliya-Sim."""

import os
from pathlib import Path
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, Field


class SimConfig(BaseModel):
    """Runtime configuration for simulation execution and verification."""
    backend_url: str = Field(
        default="http://127.0.0.1:8000",
        description="Base URL of Waliya-IR backend server",
    )
    agent_id: Optional[UUID] = Field(
        default=None,
        description="UUID of authenticated sensor agent submitting telemetry",
    )
    agent_token: Optional[str] = Field(
        default=None,
        description="Bearer authentication token for agent",
    )
    admin_key: Optional[str] = Field(
        default=None,
        description="Admin API key for outbox flush and verification queries",
    )
    timeout_seconds: float = Field(
        default=15.0,
        description="Maximum seconds to wait for backend detection processing",
    )
    poll_interval_seconds: float = Field(
        default=0.5,
        description="Polling interval in seconds when checking findings/incidents",
    )
    reports_dir: Path = Field(
        default=Path("./sim_reports"),
        description="Directory for saving simulation run reports",
    )


def load_config(
    backend_url: Optional[str] = None,
    agent_id: Optional[str] = None,
    agent_token: Optional[str] = None,
    admin_key: Optional[str] = None,
    timeout_seconds: Optional[float] = None,
    reports_dir: Optional[str] = None,
) -> SimConfig:
    """Load configuration with precedence: CLI arguments > Environment variables > Defaults."""
    url = (
        backend_url
        or os.environ.get("WALIYA_URL")
        or os.environ.get("WALIYA_BACKEND_URL")
        or "http://127.0.0.1:8000"
    ).rstrip("/")

    # Agent ID
    aid_str = agent_id or os.environ.get("WALIYA_AGENT_ID")
    aid = UUID(aid_str) if aid_str else None

    # Agent Token
    token = agent_token or os.environ.get("WALIYA_AGENT_TOKEN")

    # Admin Key
    adm = admin_key or os.environ.get("WALIYA_ADMIN_KEY") or os.environ.get("WALIYA_ADMIN_API_KEY")

    # Timeout
    to_val = float(timeout_seconds) if timeout_seconds else float(os.environ.get("WALIYA_SIM_TIMEOUT", "15.0"))

    # Reports Directory
    rep_dir = Path(reports_dir or os.environ.get("WALIYA_SIM_REPORTS_DIR", "./sim_reports"))

    return SimConfig(
        backend_url=url,
        agent_id=aid,
        agent_token=token,
        admin_key=adm,
        timeout_seconds=to_val,
        reports_dir=rep_dir,
    )
