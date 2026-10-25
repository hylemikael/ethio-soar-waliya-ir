"""Application configuration settings for Waliya-IR."""

from typing import List, Optional
from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Platform configuration settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_prefix="WALIYA_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    ENV: str = Field(default="development", description="Runtime environment (development, staging, production)")
    LOG_LEVEL: str = Field(default="INFO", description="Log verbosity level")
    SECRET_KEY: str = Field(default="insecure-dev-secret-key-change-in-production-32chars", description="Master secret key")

    # Storage
    DATABASE_URL: str = Field(
        default="postgresql+asyncpg://waliya_user:waliya_dev_password@127.0.0.1:5432/waliya_ir",
        description="Async PostgreSQL connection URL",
    )
    REDIS_URL: str = Field(
        default="redis://:waliya_redis_dev_secret@127.0.0.1:6380/0",
        description="Redis connection URL for streams and cache",
    )

    # Security & CORS
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:5173", "http://127.0.0.1:5173"],
        description="Allowed frontend CORS origins",
    )
    AGENT_TOKEN_PEPPER: str = Field(
        default="waliya-agent-pepper-dev-value",
        description="Server pepper for hashing agent tokens",
    )
    ADMIN_API_KEY: str = Field(
        default="waliya-admin-supersecret-api-key-2026",
        description="Pre-shared administrative API key for operational and rule management endpoints",
    )
    ENABLE_PUBLIC_DOCS: bool = Field(
        default=False,
        description="Explicitly allow Swagger /docs and OpenAPI schema in production environments",
    )

    # Browser Session & Cookie Auth
    SESSION_COOKIE_NAME: str = Field(default="waliya_session", description="Name of HttpOnly session cookie")
    CSRF_COOKIE_NAME: str = Field(default="waliya_csrf", description="Name of CSRF token cookie")
    SESSION_TTL_SECONDS: int = Field(default=28800, description="Session expiration TTL in seconds (8 hours)")
    SESSION_COOKIE_SECURE: bool = Field(default=False, description="Enforce Secure flag on cookies (set True in HTTPS/production)")
    SESSION_COOKIE_SAMESITE: str = Field(default="lax", description="SameSite policy for session cookies")
    LOGIN_RATE_LIMIT_ATTEMPTS: int = Field(default=5, description="Max failed login attempts before lockout")
    LOGIN_RATE_LIMIT_WINDOW_SECONDS: int = Field(default=60, description="Lockout evaluation window in seconds")

    # SOAR Engine & Timeouts
    COMMAND_TTL_SECONDS: int = Field(default=60, description="Expiration time for queued agent commands")
    VERIFICATION_WINDOW_SECONDS: int = Field(default=10, description="Observation window before post-action verification")

    # Threat Intelligence Feed Ingestion
    TI_THREATFOX_API_KEY: Optional[str] = Field(default=None, description="ThreatFox API key (abuse.ch Auth-Key)")
    TI_URLHAUS_API_KEY: Optional[str] = Field(default=None, description="URLhaus API key (abuse.ch Auth-Key)")
    TI_HTTP_TIMEOUT_SECONDS: int = Field(default=30, description="HTTP timeout for threat intel feed queries")
    TI_MAX_RECORDS_PER_SYNC: int = Field(default=1000, description="Upper bound for indicator records parsed per feed sync run")
    TI_MIN_SYNC_INTERVAL_MINUTES: int = Field(default=15, description="Enforced minimum interval between sync runs to respect provider limits")
    TI_DEFAULT_EXPIRY_DAYS: int = Field(default=30, description="Default indicator expiry TTL in days when not provided by feed")

    @model_validator(mode="after")
    def validate_production_configuration(self) -> "Settings":
        """Fail fast if mandatory production security settings are missing or insecure."""
        if self.ENV.lower() in ("production", "prod"):
            insecure_secret_defaults = {
                "insecure-dev-secret-key-change-in-production-32chars",
                "change-me-to-a-secure-random-key-in-production",
                "default",
                "secret",
            }
            if self.SECRET_KEY in insecure_secret_defaults or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    "Production configuration error: WALIYA_SECRET_KEY must be a cryptographically secure random string with at least 32 characters."
                )

            insecure_admin_defaults = {
                "waliya-admin-supersecret-api-key-2026",
                "admin",
                "change-me",
            }
            if self.ADMIN_API_KEY in insecure_admin_defaults or len(self.ADMIN_API_KEY) < 16:
                raise ValueError(
                    "Production configuration error: WALIYA_ADMIN_API_KEY must be set to a secure pre-shared administrative key (minimum 16 characters)."
                )

            insecure_pepper_defaults = {
                "waliya-agent-pepper-dev-value",
                "change-me-to-a-random-pepper-in-production",
                "pepper",
            }
            if self.AGENT_TOKEN_PEPPER in insecure_pepper_defaults or len(self.AGENT_TOKEN_PEPPER) < 16:
                raise ValueError(
                    "Production configuration error: WALIYA_AGENT_TOKEN_PEPPER must be set to a secure random value (minimum 16 characters)."
                )

            for origin in self.CORS_ORIGINS:
                if origin == "*" or origin.endswith("/*"):
                    raise ValueError(
                        "Production configuration error: Wildcard CORS origins are forbidden in production. Explicit origins required."
                    )

            if not self.DATABASE_URL.startswith(("postgresql://", "postgresql+asyncpg://")):
                raise ValueError(
                    "Production configuration error: WALIYA_DATABASE_URL must be a valid PostgreSQL async connection URL."
                )

            if not self.REDIS_URL.startswith(("redis://", "rediss://")):
                raise ValueError(
                    "Production configuration error: WALIYA_REDIS_URL must be a valid Redis connection URL."
                )

        return self


settings = Settings()
