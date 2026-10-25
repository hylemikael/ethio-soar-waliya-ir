"""Configuration model and loader for Waliya-IR Linux Endpoint Agent."""

import os
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
from uuid import UUID

import yaml
from pydantic import BaseModel, Field, field_validator, model_validator


class ServerConfig(BaseModel):
    """Server connection and TLS settings."""
    url: str = Field(default="http://127.0.0.1:8000", description="Waliya-IR management server URL")
    tls_verify: bool = Field(default=True, description="Enforce TLS certificate verification")
    ca_cert_path: Optional[str] = Field(default=None, description="Path to custom CA certificate")
    request_timeout_seconds: float = Field(default=15.0, ge=1.0, le=120.0)
    max_retries: int = Field(default=3, ge=0, le=10)
    retry_backoff_factor: float = Field(default=1.5, ge=1.0, le=10.0)

    @field_validator("url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if not (v.startswith("http://") or v.startswith("https://")):
            raise ValueError("Server URL must begin with 'http://' or 'https://'")
        return v


class AgentIdentityConfig(BaseModel):
    """Agent authentication and cryptographic credentials."""
    id: UUID = Field(..., description="Registered agent UUID")
    api_token: str = Field(..., min_length=8, description="Bearer API token")
    signing_secret: str = Field(..., min_length=16, description="HMAC-SHA256 signing secret")
    state_dir: Path = Field(default=Path("./data/agent_state"), description="Directory for persistent state and queues")

    @field_validator("state_dir", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Path:
        return Path(v).expanduser().resolve()


class TelemetryConfig(BaseModel):
    """Collection cadences and monitoring paths."""
    upload_interval_seconds: float = Field(default=5.0, ge=0.5, le=300.0)
    upload_batch_size: int = Field(default=100, ge=1, le=1000)
    buffer_capacity: int = Field(default=5000, ge=100, le=100000)

    # File Integrity Monitoring (FIM)
    fim_enabled: bool = Field(default=True)
    fim_paths: List[str] = Field(default_factory=lambda: ["/etc/passwd", "/tmp"])
    fim_poll_interval_seconds: float = Field(default=10.0, ge=1.0, le=3600.0)
    fim_debounce_seconds: float = Field(default=2.0, ge=0.1, le=60.0)
    fim_max_file_size_mb: float = Field(default=25.0, ge=0.1, le=1024.0)

    # Process Monitoring
    process_enabled: bool = Field(default=True)
    process_poll_interval_seconds: float = Field(default=5.0, ge=0.5, le=600.0)

    # Authentication Monitoring
    auth_enabled: bool = Field(default=True)
    auth_log_path: str = Field(default="/var/log/auth.log")
    auth_poll_interval_seconds: float = Field(default=5.0, ge=0.5, le=600.0)

    # Network Monitoring
    network_enabled: bool = Field(default=True)
    network_poll_interval_seconds: float = Field(default=10.0, ge=1.0, le=600.0)


class C2Config(BaseModel):
    """Command & Control polling intervals."""
    heartbeat_interval_seconds: float = Field(default=15.0, ge=2.0, le=300.0)
    task_poll_interval_seconds: float = Field(default=5.0, ge=1.0, le=120.0)


class LoggingConfig(BaseModel):
    """Agent logging format and severity."""
    level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    format: Literal["json", "text"] = Field(default="json")


class ResponseConfig(BaseModel):
    """Defensive response actions and containment execution settings."""
    enable_response_actions: bool = Field(
        default=False,
        description="Explicit opt-in to allow real OS containment actions. Default false (dry-run only).",
    )
    clock_skew_tolerance_seconds: float = Field(
        default=30.0,
        ge=0.0,
        le=300.0,
        description="Permissible clock skew tolerance when validating command issue and expiry timestamps.",
    )
    allowed_actions: List[str] = Field(
        default_factory=lambda: [
            "BLOCK_IP",
            "UNBLOCK_IP",
            "TERMINATE_PROCESS",
            "COLLECT_FORENSIC_ARTIFACT",
        ],
        description="Strictly allowlisted response action names.",
    )
    forensic_artifact_dir: Path = Field(
        default=Path("./data/forensics"),
        description="Safe directory for storing forensic artifact collections.",
    )
    max_forensic_size_mb: float = Field(
        default=10.0,
        ge=0.1,
        le=100.0,
        description="Maximum artifact size in megabytes.",
    )

    @field_validator("forensic_artifact_dir", mode="before")
    @classmethod
    def parse_path(cls, v: Any) -> Path:
        return Path(v).expanduser().resolve()


class AgentConfig(BaseModel):
    """Top-level agent configuration envelope."""
    server: ServerConfig = Field(default_factory=ServerConfig)
    agent: AgentIdentityConfig
    telemetry: TelemetryConfig = Field(default_factory=TelemetryConfig)
    c2: C2Config = Field(default_factory=C2Config)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)

    def sanitized_dict(self) -> Dict[str, Any]:
        """Return a copy of configuration safe for logging without secrets."""
        data = self.model_dump(mode="json")
        if "agent" in data:
            if "api_token" in data["agent"]:
                data["agent"]["api_token"] = "***MASKED***"
            if "signing_secret" in data["agent"]:
                data["agent"]["signing_secret"] = "***MASKED***"
        return data


def load_config_from_file_or_env(config_path: Optional[str | Path] = None) -> AgentConfig:
    """Load configuration from a YAML file, merging with environment variable overrides.

    Environment variables use the prefix `WALIYA_AGENT_`:
      - WALIYA_AGENT_SERVER_URL
      - WALIYA_AGENT_SERVER_TLS_VERIFY
      - WALIYA_AGENT_ID
      - WALIYA_AGENT_API_TOKEN
      - WALIYA_AGENT_SIGNING_SECRET
      - WALIYA_AGENT_STATE_DIR
      - WALIYA_AGENT_LOG_LEVEL
    """
    raw_dict: Dict[str, Any] = {}

    # 1. Load from file if supplied or if default exists
    if config_path:
        path = Path(config_path).expanduser().resolve()
        if not path.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path}")
        with open(path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            if isinstance(loaded, dict):
                raw_dict = loaded
    else:
        # Check standard default locations
        defaults = [
            Path("/etc/waliya/waliya-agent.yaml"),
            Path("waliya-agent.yaml"),
            Path("./data/waliya-agent.yaml"),
        ]
        for candidate in defaults:
            if candidate.is_file():
                with open(candidate, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        raw_dict = loaded
                        break

    # Ensure structure sections exist
    raw_dict.setdefault("server", {})
    raw_dict.setdefault("agent", {})
    raw_dict.setdefault("telemetry", {})
    raw_dict.setdefault("c2", {})
    raw_dict.setdefault("response", {})
    raw_dict.setdefault("logging", {})

    # 2. Apply Environment Variable Overrides
    if "WALIYA_AGENT_SERVER_URL" in os.environ:
        raw_dict["server"]["url"] = os.environ["WALIYA_AGENT_SERVER_URL"]
    if "WALIYA_AGENT_SERVER_TLS_VERIFY" in os.environ:
        raw_dict["server"]["tls_verify"] = os.environ["WALIYA_AGENT_SERVER_TLS_VERIFY"].lower() in ("true", "1", "yes")
    if "WALIYA_AGENT_CA_CERT_PATH" in os.environ:
        raw_dict["server"]["ca_cert_path"] = os.environ["WALIYA_AGENT_CA_CERT_PATH"]

    if "WALIYA_AGENT_ID" in os.environ:
        raw_dict["agent"]["id"] = os.environ["WALIYA_AGENT_ID"]
    if "WALIYA_AGENT_API_TOKEN" in os.environ:
        raw_dict["agent"]["api_token"] = os.environ["WALIYA_AGENT_API_TOKEN"]
    if "WALIYA_AGENT_SIGNING_SECRET" in os.environ:
        raw_dict["agent"]["signing_secret"] = os.environ["WALIYA_AGENT_SIGNING_SECRET"]
    if "WALIYA_AGENT_STATE_DIR" in os.environ:
        raw_dict["agent"]["state_dir"] = os.environ["WALIYA_AGENT_STATE_DIR"]

    if "WALIYA_AGENT_ENABLE_RESPONSE_ACTIONS" in os.environ:
        raw_dict["response"]["enable_response_actions"] = os.environ["WALIYA_AGENT_ENABLE_RESPONSE_ACTIONS"].lower() in ("true", "1", "yes")
    if "WALIYA_AGENT_CLOCK_SKEW_TOLERANCE" in os.environ:
        raw_dict["response"]["clock_skew_tolerance_seconds"] = float(os.environ["WALIYA_AGENT_CLOCK_SKEW_TOLERANCE"])

    if "WALIYA_AGENT_LOG_LEVEL" in os.environ:
        raw_dict["logging"]["level"] = os.environ["WALIYA_AGENT_LOG_LEVEL"].upper()

    return AgentConfig.model_validate(raw_dict)
