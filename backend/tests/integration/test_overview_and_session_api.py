"""Integration tests for Browser Session Authentication, CSRF Protection, and Overview API."""

import pytest
from httpx import AsyncClient

from waliya.config import settings
from waliya.contracts import SystemOverviewResponse
from waliya.core.rate_limit import login_rate_limiter


@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """Ensure rate limiter is clean before each test."""
    login_rate_limiter.clear()
    yield
    login_rate_limiter.clear()


@pytest.mark.asyncio
async def test_auth_login_lifecycle_and_cookies(async_client: AsyncClient):
    """Test administrative login, cookie generation, session verification, and logout."""
    # 1. Invalid password fails with 401
    res_bad = await async_client.post(
        "/api/v1/auth/login",
        json={"password": "wrong-admin-password"},
    )
    assert res_bad.status_code == 401
    assert "Invalid administrative credentials" in res_bad.json()["detail"]

    # 2. Valid password succeeds with 200 and sets cookies
    res_login = await async_client.post(
        "/api/v1/auth/login",
        json={"password": settings.ADMIN_API_KEY},
    )
    assert res_login.status_code == 200
    data = res_login.json()
    assert data["authenticated"] is True
    assert data["actor"] == "admin"
    csrf_token = data["csrf_token"]
    assert csrf_token is not None

    # Check cookies
    session_cookie = res_login.cookies.get(settings.SESSION_COOKIE_NAME)
    csrf_cookie = res_login.cookies.get(settings.CSRF_COOKIE_NAME)
    assert session_cookie is not None
    assert csrf_cookie == csrf_token

    # 3. Verify session endpoint using the session cookie
    res_session = await async_client.get(
        "/api/v1/auth/session",
        cookies={settings.SESSION_COOKIE_NAME: session_cookie},
    )
    assert res_session.status_code == 200
    session_data = res_session.json()
    assert session_data["authenticated"] is True
    assert session_data["actor"] == "admin"
    assert session_data["csrf_token"] == csrf_token

    # 4. State-changing request (logout) requires CSRF header when using cookie
    # Without CSRF header -> 403 Forbidden
    res_logout_no_csrf = await async_client.post(
        "/api/v1/auth/logout",
        cookies={
            settings.SESSION_COOKIE_NAME: session_cookie,
            settings.CSRF_COOKIE_NAME: csrf_cookie,
        },
    )
    assert res_logout_no_csrf.status_code == 403

    # With invalid CSRF header -> 403 Forbidden
    res_logout_bad_csrf = await async_client.post(
        "/api/v1/auth/logout",
        cookies={
            settings.SESSION_COOKIE_NAME: session_cookie,
            settings.CSRF_COOKIE_NAME: csrf_cookie,
        },
        headers={"X-CSRF-Token": "tampered-token"},
    )
    assert res_logout_bad_csrf.status_code == 403

    # With valid CSRF header -> 200 OK and cleared cookies
    res_logout_ok = await async_client.post(
        "/api/v1/auth/logout",
        cookies={
            settings.SESSION_COOKIE_NAME: session_cookie,
            settings.CSRF_COOKIE_NAME: csrf_cookie,
        },
        headers={"X-CSRF-Token": csrf_token},
    )
    assert res_logout_ok.status_code == 200
    assert res_logout_ok.json()["status"] == "LOGGED_OUT"


@pytest.mark.asyncio
async def test_auth_login_rate_limiting(async_client: AsyncClient):
    """Test that consecutive invalid login attempts trigger rate limiting (429)."""
    # Allowed attempts: 5
    for attempt in range(settings.LOGIN_RATE_LIMIT_ATTEMPTS):
        res = await async_client.post(
            "/api/v1/auth/login",
            json={"password": f"wrong-pass-{attempt}"},
        )
        assert res.status_code == 401

    # 6th attempt should be blocked by rate limiter
    res_blocked = await async_client.post(
        "/api/v1/auth/login",
        json={"password": "even-valid-or-invalid"},
    )
    assert res_blocked.status_code == 429
    assert "Too many failed authentication attempts" in res_blocked.json()["detail"]


@pytest.mark.asyncio
async def test_session_endpoint_unauthenticated(async_client: AsyncClient):
    """GET /api/v1/auth/session returns authenticated: false when unauthenticated."""
    res = await async_client.get("/api/v1/auth/session")
    assert res.status_code == 200
    assert res.json() == {"authenticated": False, "actor": None, "csrf_token": None}


@pytest.mark.asyncio
async def test_overview_endpoint_authorization(async_client: AsyncClient):
    """Verify overview endpoint authentication via header and session cookie."""
    # 1. Unauthenticated -> 401
    res_no_auth = await async_client.get("/api/v1/overview")
    assert res_no_auth.status_code == 401

    # 2. Invalid API key -> 403
    res_bad_key = await async_client.get(
        "/api/v1/overview",
        headers={"X-Admin-Key": "invalid-admin-key"},
    )
    assert res_bad_key.status_code == 403

    # 3. Valid API key -> 200 OK
    res_key_ok = await async_client.get(
        "/api/v1/overview",
        headers={"X-Admin-Key": settings.ADMIN_API_KEY},
    )
    assert res_key_ok.status_code == 200
    data = res_key_ok.json()
    validated = SystemOverviewResponse.model_validate(data)
    assert validated.security_posture in ["NORMAL", "ELEVATED", "CRITICAL"]
    assert validated.agents is not None
    assert validated.pipeline is not None
    assert validated.events_24h is not None
    assert validated.findings is not None
    assert validated.incidents is not None
    assert validated.rules is not None
    assert validated.responses is not None
    assert isinstance(validated.incidents.recent_activity, list)

    # 4. Valid session cookie -> 200 OK
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"password": settings.ADMIN_API_KEY},
    )
    session_cookie = login_res.cookies.get(settings.SESSION_COOKIE_NAME)
    assert session_cookie is not None

    res_cookie_ok = await async_client.get(
        "/api/v1/overview",
        cookies={settings.SESSION_COOKIE_NAME: session_cookie},
    )
    assert res_cookie_ok.status_code == 200
    validated_cookie = SystemOverviewResponse.model_validate(res_cookie_ok.json())
    assert validated_cookie.security_posture == validated.security_posture
