"""Tests for deployment configuration management, fail-fast validation, and secret hygiene."""

import pytest
from pydantic import ValidationError

from waliya.config import Settings


def test_dev_settings_defaults() -> None:
    """Verify that development defaults load without error for local testing."""
    s = Settings(ENV="development")
    assert s.ENV == "development"
    assert s.LOG_LEVEL == "INFO"
    assert "postgresql+asyncpg://" in s.DATABASE_URL
    assert "redis://" in s.REDIS_URL
    assert s.SESSION_COOKIE_SECURE is False


def test_prod_settings_rejects_insecure_secret_key() -> None:
    """Verify that production mode rejects default or insecure SECRET_KEY."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            SECRET_KEY="insecure-dev-secret-key-change-in-production-32chars",
            ADMIN_API_KEY="valid-admin-api-key-12345",
            AGENT_TOKEN_PEPPER="valid-agent-pepper-12345",
            CORS_ORIGINS=["https://soar.waliya.local"],
        )
    assert "WALIYA_SECRET_KEY must be a cryptographically secure random string" in str(exc_info.value)


def test_prod_settings_rejects_short_secret_key() -> None:
    """Verify that production mode rejects SECRET_KEY shorter than 32 characters."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            SECRET_KEY="too-short-secret-key",
            ADMIN_API_KEY="valid-admin-api-key-12345",
            AGENT_TOKEN_PEPPER="valid-agent-pepper-12345",
            CORS_ORIGINS=["https://soar.waliya.local"],
        )
    assert "WALIYA_SECRET_KEY must be a cryptographically secure random string" in str(exc_info.value)


def test_prod_settings_rejects_insecure_admin_api_key() -> None:
    """Verify that production mode rejects default or insecure ADMIN_API_KEY."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            SECRET_KEY="a" * 32,
            ADMIN_API_KEY="waliya-admin-supersecret-api-key-2026",
            AGENT_TOKEN_PEPPER="valid-agent-pepper-12345",
            CORS_ORIGINS=["https://soar.waliya.local"],
        )
    assert "WALIYA_ADMIN_API_KEY must be set to a secure pre-shared administrative key" in str(exc_info.value)


def test_prod_settings_rejects_short_admin_api_key() -> None:
    """Verify that production mode rejects ADMIN_API_KEY shorter than 16 characters."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            SECRET_KEY="a" * 32,
            ADMIN_API_KEY="short-key",
            AGENT_TOKEN_PEPPER="valid-agent-pepper-12345",
            CORS_ORIGINS=["https://soar.waliya.local"],
        )
    assert "WALIYA_ADMIN_API_KEY must be set to a secure pre-shared administrative key" in str(exc_info.value)


def test_prod_settings_rejects_insecure_agent_token_pepper() -> None:
    """Verify that production mode rejects default or insecure AGENT_TOKEN_PEPPER."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            SECRET_KEY="a" * 32,
            ADMIN_API_KEY="b" * 16,
            AGENT_TOKEN_PEPPER="waliya-agent-pepper-dev-value",
            CORS_ORIGINS=["https://soar.waliya.local"],
        )
    assert "WALIYA_AGENT_TOKEN_PEPPER must be set to a secure random value" in str(exc_info.value)


def test_prod_settings_rejects_wildcard_cors() -> None:
    """Verify that production mode forbids wildcard '*' in CORS_ORIGINS."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            SECRET_KEY="a" * 32,
            ADMIN_API_KEY="b" * 16,
            AGENT_TOKEN_PEPPER="c" * 16,
            CORS_ORIGINS=["*"],
        )
    assert "Wildcard CORS origins are forbidden in production" in str(exc_info.value)


def test_prod_settings_rejects_invalid_database_url() -> None:
    """Verify that production mode rejects non-PostgreSQL database schemes."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            SECRET_KEY="a" * 32,
            ADMIN_API_KEY="b" * 16,
            AGENT_TOKEN_PEPPER="c" * 16,
            CORS_ORIGINS=["https://soar.waliya.local"],
            DATABASE_URL="sqlite:///test.db",
        )
    assert "WALIYA_DATABASE_URL must be a valid PostgreSQL async connection URL" in str(exc_info.value)


def test_prod_settings_rejects_invalid_redis_url() -> None:
    """Verify that production mode rejects non-Redis stream schemes."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENV="production",
            SECRET_KEY="a" * 32,
            ADMIN_API_KEY="b" * 16,
            AGENT_TOKEN_PEPPER="c" * 16,
            CORS_ORIGINS=["https://soar.waliya.local"],
            REDIS_URL="http://localhost:6379",
        )
    assert "WALIYA_REDIS_URL must be a valid Redis connection URL" in str(exc_info.value)


def test_prod_settings_accepts_valid_configuration() -> None:
    """Verify that a properly specified production configuration initializes successfully."""
    s = Settings(
        ENV="production",
        SECRET_KEY="0123456789abcdef0123456789abcdef",
        ADMIN_API_KEY="admin-secret-key-16-chars",
        AGENT_TOKEN_PEPPER="agent-pepper-key-16-chars",
        DATABASE_URL="postgresql+asyncpg://app_user:app_pass@postgres:5432/app_db",
        REDIS_URL="redis://:redis_pass@redis:6379/0",
        CORS_ORIGINS=["https://soar.waliya.local", "https://waliya.internal"],
        SESSION_COOKIE_SECURE=True,
    )
    assert s.ENV == "production"
    assert s.SESSION_COOKIE_SECURE is True
    assert len(s.CORS_ORIGINS) == 2
    assert s.ENABLE_PUBLIC_DOCS is False


def test_prod_settings_enable_public_docs_flag() -> None:
    """Verify that ENABLE_PUBLIC_DOCS can be toggled explicitly."""
    s = Settings(
        ENV="production",
        SECRET_KEY="0123456789abcdef0123456789abcdef",
        ADMIN_API_KEY="admin-secret-key-16-chars",
        AGENT_TOKEN_PEPPER="agent-pepper-key-16-chars",
        DATABASE_URL="postgresql+asyncpg://app_user:app_pass@postgres:5432/app_db",
        REDIS_URL="redis://:redis_pass@redis:6379/0",
        CORS_ORIGINS=["https://soar.waliya.local"],
        ENABLE_PUBLIC_DOCS=True,
    )
    assert s.ENABLE_PUBLIC_DOCS is True
