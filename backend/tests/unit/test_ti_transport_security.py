"""Unit tests for threat intelligence transport security safeguards."""

from unittest.mock import AsyncMock, MagicMock, patch
import httpx
import pytest

from waliya.threat_intel.connectors.base import (
    BaseFeedConnector,
    FeedAuthenticationError,
    FeedFetchResult,
    FeedRateLimitError,
    FeedSecurityError,
)


class DummyTestConnector(BaseFeedConnector):
    feed_id = "test_feed"
    provider = "TestProvider"
    allowed_hosts = {"api.trusted-provider.example.com", "backup.trusted-provider.example.com"}

    async def fetch_indicators(self, config_options, api_key=None):
        return FeedFetchResult()


@pytest.fixture
def dummy_connector():
    return DummyTestConnector(timeout_seconds=5.0)


def test_reject_insecure_http_scheme(dummy_connector):
    """Enforce that plain HTTP URLs are rejected immediately."""
    with pytest.raises(FeedSecurityError, match="Insecure scheme 'http'"):
        dummy_connector.validate_url("http://api.trusted-provider.example.com/feed")


def test_reject_untrusted_host(dummy_connector):
    """Enforce that arbitrary or untrusted hosts are rejected by allowlist."""
    with pytest.raises(FeedSecurityError, match="not in the explicit allowlist"):
        dummy_connector.validate_url("https://malicious-redirect.attacker.com/steal")


def test_credential_redaction(dummy_connector):
    """Enforce that secrets and API keys are redacted from logs and errors."""
    secret = "secret-super-key-12345"
    raw_error = f"Failed to connect using Auth-Key: {secret} to https://api.trusted.com"
    sanitized = dummy_connector.sanitize_string(raw_error, secret)
    assert secret not in sanitized
    assert "[REDACTED" in sanitized


@pytest.mark.asyncio
async def test_unsafe_redirect_rejection(dummy_connector):
    """Enforce that redirects to hosts outside the allowlist are rejected."""
    redirect_resp = MagicMock()
    redirect_resp.status_code = 302
    redirect_resp.headers = {"location": "https://evil.external.com/leak"}

    with patch("httpx.AsyncClient.request", AsyncMock(return_value=redirect_resp)):
        with pytest.raises(FeedSecurityError, match="not in the explicit allowlist"):
            await dummy_connector.execute_request(
                method="GET",
                url="https://api.trusted-provider.example.com/data",
                headers={},
            )


@pytest.mark.asyncio
async def test_oversized_response_rejection(dummy_connector):
    """Enforce that responses exceeding max_response_bytes (10MB) are aborted."""
    dummy_connector.max_response_bytes = 1000  # Set low limit for testing

    oversized_resp = MagicMock()
    oversized_resp.status_code = 200
    oversized_resp.headers = {"content-length": "5000"}
    oversized_resp.content = b"X" * 5000

    with patch("httpx.AsyncClient.request", AsyncMock(return_value=oversized_resp)):
        with pytest.raises(FeedSecurityError, match="exceeds maximum allowed limit"):
            await dummy_connector.execute_request(
                method="GET",
                url="https://api.trusted-provider.example.com/data",
                headers={},
            )
