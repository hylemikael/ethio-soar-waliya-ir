"""Unit tests for browser session tokens, CSRF protection, and login rate limiting."""

import time
import pytest

from waliya.core.rate_limit import SlidingWindowRateLimiter
from waliya.core.session import (
    create_session_token,
    verify_csrf_token,
    verify_session_token,
)

TEST_SECRET = "supersecret-master-encryption-key-for-testing"


def test_session_token_creation_and_verification():
    """Verify session token HMAC generation and valid verification."""
    token, csrf_token = create_session_token(TEST_SECRET, actor="admin")
    assert token is not None
    assert len(csrf_token) >= 32

    # Valid token verification
    data = verify_session_token(token, TEST_SECRET, ttl_seconds=3600)
    assert data is not None
    assert data["actor"] == "admin"
    assert data["csrf_token"] == csrf_token


def test_session_token_tampering_detected():
    """Verify tampering with payload or signature invalidates the session token."""
    token, _ = create_session_token(TEST_SECRET, actor="admin")
    parts = token.split(":")
    # Tamper with actor field (admin -> superadmin)
    tampered_parts = [parts[0], parts[1], "superadmin", parts[3], parts[4]]
    tampered_token = ":".join(tampered_parts)

    res = verify_session_token(tampered_token, TEST_SECRET, ttl_seconds=3600)
    assert res is None


def test_session_token_expiration():
    """Verify expired session tokens are rejected."""
    token, _ = create_session_token(TEST_SECRET, actor="admin")
    # TTL of 0 seconds simulates expired session
    res = verify_session_token(token, TEST_SECRET, ttl_seconds=0)
    assert res is None


def test_csrf_token_verification():
    """Verify CSRF token matching using constant-time comparison."""
    cookie_csrf = "valid-csrf-token-12345"
    assert verify_csrf_token(cookie_csrf, "valid-csrf-token-12345") is True
    assert verify_csrf_token(cookie_csrf, "wrong-token") is False
    assert verify_csrf_token(cookie_csrf, None) is False
    assert verify_csrf_token(None, "valid-token") is False


def test_login_rate_limiter():
    """Verify sliding-window rate limiter blocks IP after max failures."""
    limiter = SlidingWindowRateLimiter(max_attempts=3, window_seconds=10)
    ip = "192.168.1.55"

    assert limiter.is_rate_limited(ip) is False

    # 2 failures
    limiter.record_failure(ip)
    limiter.record_failure(ip)
    assert limiter.is_rate_limited(ip) is False

    # 3rd failure: reaches limit
    limiter.record_failure(ip)
    assert limiter.is_rate_limited(ip) is True

    # Success resets counter
    limiter.record_success(ip)
    assert limiter.is_rate_limited(ip) is False
