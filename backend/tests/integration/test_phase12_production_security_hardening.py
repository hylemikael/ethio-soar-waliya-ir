"""Production Security Hardening, Boundary Defense, and Operational Readiness tests for Phase 12."""

import logging
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

from waliya.config import Settings, settings
from waliya.main import create_app
from waliya.observability.correlation import SensitiveDataFilter

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
VALIDATE_SCRIPT = REPO_ROOT / "scripts" / "validate_config.py"


@pytest.mark.asyncio
async def test_security_headers_present_on_api_responses(async_client: AsyncClient):
    """Verify that every API response includes defense-in-depth HTTP security headers."""
    res = await async_client.get("/api/v1/health/liveness")
    assert res.status_code == 200

    headers = res.headers
    assert headers.get("X-Content-Type-Options") == "nosniff"
    assert headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"
    assert "geolocation=()" in headers.get("Permissions-Policy", "")
    assert "X-Request-ID" in headers


@pytest.mark.asyncio
async def test_correlation_id_propagation_and_custom_header(async_client: AsyncClient):
    """Verify incoming correlation IDs are preserved and returned in response headers."""
    custom_id = "req_audit_test_12345"
    res = await async_client.get(
        "/api/v1/health/liveness",
        headers={"X-Request-ID": custom_id},
    )
    assert res.status_code == 200
    assert res.headers.get("X-Request-ID") == custom_id


@pytest.mark.asyncio
async def test_production_docs_disabled_by_default():
    """Verify that public Swagger and OpenAPI docs are disabled in production mode."""
    with patch("waliya.main.settings", Settings(
        ENV="production",
        SECRET_KEY="0123456789abcdef0123456789abcdef",
        ADMIN_API_KEY="admin-secret-key-16-chars",
        AGENT_TOKEN_PEPPER="agent-pepper-key-16-chars",
        DATABASE_URL="postgresql+asyncpg://user:pass@127.0.0.1:5432/db",
        REDIS_URL="redis://:pass@127.0.0.1:6379/0",
        CORS_ORIGINS=["https://soar.waliya.local"],
        ENABLE_PUBLIC_DOCS=False,
    )):
        prod_app = create_app()
        transport = ASGITransport(app=prod_app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            docs_res = await client.get("/docs")
            assert docs_res.status_code == 404

            openapi_res = await client.get("/api/v1/openapi.json")
            assert openapi_res.status_code == 404


@pytest.mark.asyncio
async def test_production_docs_accessible_when_explicitly_enabled():
    """Verify that public Swagger docs can be opted into via ENABLE_PUBLIC_DOCS."""
    with patch("waliya.main.settings", Settings(
        ENV="production",
        SECRET_KEY="0123456789abcdef0123456789abcdef",
        ADMIN_API_KEY="admin-secret-key-16-chars",
        AGENT_TOKEN_PEPPER="agent-pepper-key-16-chars",
        DATABASE_URL="postgresql+asyncpg://user:pass@127.0.0.1:5432/db",
        REDIS_URL="redis://:pass@127.0.0.1:6379/0",
        CORS_ORIGINS=["https://soar.waliya.local"],
        ENABLE_PUBLIC_DOCS=True,
    )):
        prod_app = create_app()
        transport = ASGITransport(app=prod_app)
        async with AsyncClient(transport=transport, base_url="http://testserver") as client:
            docs_res = await client.get("/docs")
            assert docs_res.status_code == 200

            openapi_res = await client.get("/api/v1/openapi.json")
            assert openapi_res.status_code == 200


@pytest.mark.asyncio
async def test_global_unhandled_exception_sanitization():
    """Verify that unexpected internal exceptions do not leak stack traces or internal secrets."""
    app = create_app()

    # Add a temporary test endpoint that raises an unhandled internal exception with sensitive data
    @app.get("/api/v1/test-fault-injection")
    async def faulty_route():
        raise RuntimeError("Database connection string postgresql://admin:secret_pass_123@db failed")

    transport = ASGITransport(app=app, raise_app_exceptions=False)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        res = await client.get("/api/v1/test-fault-injection")
        assert res.status_code == 500
        data = res.json()

        # Must not leak the secret or stack trace
        assert "secret_pass_123" not in res.text
        assert "Traceback" not in res.text
        assert data["error"] == "Internal server error"
        assert "correlation_id" in data
        assert "X-Request-ID" in res.headers
        assert res.headers["X-Request-ID"] == data["correlation_id"]


def test_sensitive_data_filter_redacts_credentials():
    """Verify that SensitiveDataFilter scrubs credentials from log records."""
    filt = SensitiveDataFilter()

    # 1. Double quoted
    r1 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg='Failed authentication with password="super_secret_password" and token="jwt.token.val"',
        args=(),
        exc_info=None,
    )
    filt.filter(r1)
    assert "super_secret_password" not in r1.msg
    assert "jwt.token.val" not in r1.msg
    assert '[REDACTED]' in r1.msg

    # 2. Single quoted and unquoted key=values
    r2 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=11,
        msg="Invalid login password='single_secret_val' and api_key=unquoted_secret_key",
        args=(),
        exc_info=None,
    )
    filt.filter(r2)
    assert "single_secret_val" not in r2.msg
    assert "unquoted_secret_key" not in r2.msg

    # 3. Connection URLs with embedded passwords
    r3 = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=12,
        msg="Failed connecting to postgresql+asyncpg://app_user:db_secret_pass@127.0.0.1:5432/db and redis://:redis_secret_val@127.0.0.1:6380/0",
        args=(),
        exc_info=None,
    )
    filt.filter(r3)
    assert "db_secret_pass" not in r3.msg
    assert "redis_secret_val" not in r3.msg
    assert "app_user:[REDACTED]@" in r3.msg
    assert ":[REDACTED]@" in r3.msg


def test_validate_config_cli_tool_passes_on_valid_example():
    """Verify that validate_config.py exits code 0 on .env.example."""
    res = subprocess.run(
        [sys.executable, str(VALIDATE_SCRIPT), "--env-file", ".env.example"],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=str(REPO_ROOT),
    )
    assert res.returncode == 0
    assert "[SUCCESS] All configuration parameters validated successfully!" in res.stdout


def test_validate_config_cli_tool_fails_on_missing_file(tmp_path):
    """Verify that validate_config.py exits code 1 when .env is absent."""
    missing = tmp_path / "nonexistent.env"
    res = subprocess.run(
        [sys.executable, str(VALIDATE_SCRIPT), "--env-file", str(missing)],
        capture_output=True,
        text=True,
        timeout=15,
        cwd=str(REPO_ROOT),
    )
    assert res.returncode == 1
    assert "not found" in res.stdout
