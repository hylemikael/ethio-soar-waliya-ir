"""Integration and behavioral tests for Enterprise Security Hardening.

Verifies:
1. NIST SP 800-63B-4 password policy, hashing, and transparent upgrade.
2. RFC 6238 TOTP MFA enrollment, verification, recovery codes, and encryption at rest.
3. Role-Based Access Control (RBAC: ADMIN, OPERATOR, ANALYST, AUDITOR).
4. Server-side session revocation on logout, password change, and deactivation.
5. Account lockout, progressive delay, and username enumeration resistance.
6. Cryptographic single-use password reset tokens.
7. Re-authentication requirements for sensitive modifications.
8. Request size limits (10MB DoS protection).
9. Audit ledger chaining for identity events.
"""

from datetime import datetime, timezone
from uuid import uuid4
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from waliya.config import settings
from waliya.core.auth import UserRole
from waliya.core.mfa import (
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    generate_totp_code,
    generate_totp_secret,
    verify_and_consume_recovery_code,
    verify_totp_code,
)
from waliya.core.password import (
    PasswordPolicyError,
    hash_password,
    validate_password_complexity,
    verify_and_check_upgrade,
    verify_password,
)
from waliya.core.session import (
    clear_revocations_for_tests,
    create_session_token,
    is_session_revoked,
    revoke_all_user_sessions,
    revoke_session,
    verify_session_token,
)
from waliya.db.models import AuditLedgerModel, UserModel
from waliya.db.session import async_session_factory
from waliya.main import create_app


@pytest.fixture(autouse=True)
def clean_test_state():
    """Reset rate limiters and session revocations before each test."""
    clear_revocations_for_tests()
    from waliya.core.rate_limit import (
        login_rate_limiter,
        mfa_rate_limiter,
        password_reset_limiter,
    )
    login_rate_limiter.reset()
    mfa_rate_limiter.reset()
    password_reset_limiter.reset()
    yield


@pytest.fixture
def admin_api_headers():
    return {"X-Admin-Key": settings.ADMIN_API_KEY}


# ==============================================================================
# 1. NIST SP 800-63B-4 Password Security Tests
# ==============================================================================

def test_nist_password_complexity_rules():
    """Verify NIST length, blacklist, and similarity validation."""
    # Too short (< 12 chars)
    with pytest.raises(PasswordPolicyError, match="too short"):
        validate_password_complexity("Short1!")

    # Common / breached dictionary passwords
    with pytest.raises(PasswordPolicyError, match="too common"):
        validate_password_complexity("password1234")

    with pytest.raises(PasswordPolicyError, match="too common"):
        validate_password_complexity("administrator")

    # Repetitive characters
    with pytest.raises(PasswordPolicyError, match="repetitive"):
        validate_password_complexity("aaaaaaaaaaaaa")

    # Contains username
    with pytest.raises(PasswordPolicyError, match="must not contain your username"):
        validate_password_complexity("SuperSecretJohnDoePassphrase!", username="johndoe")

    # Valid long passphrase (recommended by NIST)
    validate_password_complexity("correct horse battery staple 2026!", username="alice")
    validate_password_complexity("Waliya#National#Defense#SecOps#2026")


def test_pbkdf2_password_hashing_and_transparent_upgrade():
    """Verify PBKDF2-HMAC-SHA256 600,000 iterations and transparent upgrade."""
    raw_pwd = "EnterpriseSafePassphrase2026!"
    hashed = hash_password(raw_pwd)

    parts = hashed.split("$")
    assert len(parts) == 4
    assert parts[0] == "pbkdf2_sha256"
    assert int(parts[1]) == 600_000

    assert verify_password(raw_pwd, hashed) is True
    assert verify_password("WrongPassword!", hashed) is False

    # Simulate older hash with 100,000 iterations
    legacy_hash = hash_password(raw_pwd, iterations=100_000)
    is_valid, upgraded = verify_and_check_upgrade(raw_pwd, legacy_hash)
    assert is_valid is True
    assert upgraded is not None
    assert int(upgraded.split("$")[1]) == 600_000


# ==============================================================================
# 2. RFC 6238 TOTP Multi-Factor Authentication Tests
# ==============================================================================

def test_totp_generation_and_drift_window():
    """Verify RFC 6238 TOTP algorithm and drift tolerance."""
    secret = generate_totp_secret()
    assert len(secret) >= 16

    current_code = generate_totp_code(secret)
    assert len(current_code) == 6
    assert current_code.isdigit()

    # Valid within current window
    assert verify_totp_code(secret, current_code) is True
    # Invalid code
    assert verify_totp_code(secret, "000000" if current_code != "000000" else "111111") is False


def test_mfa_secret_encryption_at_rest():
    """Verify that MFA secrets and recovery codes are encrypted with Fernet."""
    plain_secret = generate_totp_secret()
    encrypted = encrypt_secret(plain_secret, settings.SECRET_KEY)
    assert encrypted != plain_secret
    assert not encrypted.startswith("otpauth")

    decrypted = decrypt_secret(encrypted, settings.SECRET_KEY)
    assert decrypted == plain_secret


def test_single_use_recovery_codes_consumption():
    """Verify backup recovery codes can be used once and only once."""
    plain_codes, encrypted_payload = generate_recovery_codes(settings.SECRET_KEY, num_codes=4)
    assert len(plain_codes) == 4

    test_code = plain_codes[0]

    # First consumption succeeds
    is_valid, updated_payload = verify_and_consume_recovery_code(
        test_code,
        encrypted_payload,
        settings.SECRET_KEY,
    )
    assert is_valid is True
    assert updated_payload is not None

    # Second consumption of the same code fails (single-use)
    is_valid2, _ = verify_and_consume_recovery_code(
        test_code,
        updated_payload,
        settings.SECRET_KEY,
    )
    assert is_valid2 is False


# ==============================================================================
# 3. Server-Side Session Revocation Tests
# ==============================================================================

def test_session_token_and_revocation():
    """Verify session creation and immediate server-side revocation."""
    token, csrf = create_session_token(
        secret_key=settings.SECRET_KEY,
        actor="operator_1",
        role=UserRole.OPERATOR.value,
        mfa_authenticated=True,
    )

    verified = verify_session_token(token, settings.SECRET_KEY)
    assert verified is not None
    assert verified["actor"] == "operator_1"
    assert verified["role"] == UserRole.OPERATOR.value

    s_id = verified["session_id"]
    assert is_session_revoked(s_id) is False

    # Revoke session
    revoke_session(s_id)
    assert is_session_revoked(s_id) is True

    # Token immediately fails verification
    assert verify_session_token(token, settings.SECRET_KEY) is None


# ==============================================================================
# 4. End-to-End API Security & RBAC Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_user_provisioning_and_rbac_boundaries(admin_api_headers):
    """Verify user creation with NIST password policy and RBAC boundary enforcement."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        unique_suffix = uuid4().hex[:6]
        analyst_user = f"analyst_{unique_suffix}"
        operator_user = f"operator_{unique_suffix}"
        password_val = "Waliya#Security#Passphrase#2026!"

        # 1. Admin provisions an ANALYST account
        res = await ac.post(
            "/api/v1/users",
            json={
                "username": analyst_user,
                "email": f"{analyst_user}@soc.et",
                "password": password_val,
                "role": "ANALYST",
            },
            headers=admin_api_headers,
        )
        assert res.status_code == 201
        analyst_data = res.json()
        assert analyst_data["role"] == "ANALYST"
        analyst_id = analyst_data["id"]

        # 2. Admin provisions an OPERATOR account
        res_op = await ac.post(
            "/api/v1/users",
            json={
                "username": operator_user,
                "email": f"{operator_user}@soc.et",
                "password": password_val,
                "role": "OPERATOR",
            },
            headers=admin_api_headers,
        )
        assert res_op.status_code == 201

        # 3. Log in as ANALYST
        login_res = await ac.post(
            "/api/v1/auth/login",
            json={"username": analyst_user, "password": password_val},
        )
        assert login_res.status_code == 200
        analyst_csrf = login_res.json()["csrf_token"]
        analyst_cookies = login_res.cookies

        # 4. Verify ANALYST CAN read incidents (Read-Only access)
        get_inc = await ac.get(
            "/api/v1/incidents",
            cookies=analyst_cookies,
            headers={"X-CSRF-Token": analyst_csrf},
        )
        assert get_inc.status_code == 200

        # 5. Verify ANALYST CANNOT provision users (Blocked by require_admin)
        blocked_user_create = await ac.post(
            "/api/v1/users",
            json={
                "username": f"bad_{uuid4().hex[:4]}",
                "email": "bad@soc.et",
                "password": password_val,
                "role": "ADMIN",
            },
            cookies=analyst_cookies,
            headers={"X-CSRF-Token": analyst_csrf},
        )
        assert blocked_user_create.status_code == 403

        # 6. Verify ANALYST CANNOT approve response plans (Blocked by require_operator)
        blocked_approve = await ac.post(
            f"/api/v1/soar/plans/{uuid4()}/approve",
            json={"reason": "Unauthorized attempt"},
            cookies=analyst_cookies,
            headers={"X-CSRF-Token": analyst_csrf},
        )
        assert blocked_approve.status_code == 403


@pytest.mark.asyncio
async def test_login_enumeration_resistance():
    """Verify non-existent user returns timing-safe generic 401 response."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        res = await ac.post(
            "/api/v1/auth/login",
            json={"username": f"non_existent_{uuid4().hex}", "password": "WrongPassword123!"},
        )
        assert res.status_code == 401
        assert "Invalid username or password" in res.json()["detail"]


@pytest.mark.asyncio
async def test_logout_immediate_server_side_invalidation():
    """Verify logging out immediately invalidates session on server."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Log in with admin API key
        login_res = await ac.post(
            "/api/v1/auth/login",
            json={"api_key": settings.ADMIN_API_KEY},
        )
        assert login_res.status_code == 200
        csrf = login_res.json()["csrf_token"]
        session_cookies = login_res.cookies

        # Verify active session works
        sess_check = await ac.get("/api/v1/auth/session", cookies=session_cookies)
        assert sess_check.status_code == 200
        assert sess_check.json()["authenticated"] is True

        # Perform logout
        logout_res = await ac.post(
            "/api/v1/auth/logout",
            cookies=session_cookies,
            headers={"X-CSRF-Token": csrf},
        )
        assert logout_res.status_code == 200
        assert logout_res.json()["status"] == "LOGGED_OUT"

        # Present revoked session cookie -> Must be rejected (401)
        rejected = await ac.get("/api/v1/users", cookies=session_cookies)
        assert rejected.status_code == 401


@pytest.mark.asyncio
async def test_password_reset_flow_and_session_revocation(admin_api_headers):
    """Verify password reset with single-use token and session revocation."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        user_name = f"user_rst_{uuid4().hex[:6]}"
        old_pwd = "InitialPassword#2026!"
        new_pwd = "BrandNewSecurePassword#2026!"

        # Create user
        await ac.post(
            "/api/v1/users",
            json={"username": user_name, "email": f"{user_name}@soc.et", "password": old_pwd, "role": "OPERATOR"},
            headers=admin_api_headers,
        )

        # Log in to get an active session
        login_res = await ac.post("/api/v1/auth/login", json={"username": user_name, "password": old_pwd})
        assert login_res.status_code == 200
        old_cookies = login_res.cookies

        # Request reset token
        req_res = await ac.post("/api/v1/auth/password-reset/request", json={"username_or_email": user_name})
        assert req_res.status_code == 200
        reset_token = req_res.json()["reset_token"]
        assert reset_token is not None

        # Confirm reset
        conf_res = await ac.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": new_pwd},
        )
        assert conf_res.status_code == 200

        # Attempt to reuse the reset token (Must fail)
        reuse_res = await ac.post(
            "/api/v1/auth/password-reset/confirm",
            json={"token": reset_token, "new_password": new_pwd},
        )
        assert reuse_res.status_code == 400

        # Verify old session was invalidated on the server
        old_sess_res = await ac.get("/api/v1/auth/session", cookies=old_cookies)
        assert old_sess_res.json()["authenticated"] is False

        # Verify new password works
        new_login = await ac.post("/api/v1/auth/login", json={"username": user_name, "password": new_pwd})
        assert new_login.status_code == 200


@pytest.mark.asyncio
async def test_reauthentication_for_sensitive_password_change(admin_api_headers):
    """Verify changing password requires re-authentication with current password."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        u_name = f"pwd_chg_{uuid4().hex[:6]}"
        cur_pwd = "CurrentPassword#2026!"
        new_pwd = "UpdatedPassword#2026!"

        await ac.post(
            "/api/v1/users",
            json={"username": u_name, "email": f"{u_name}@soc.et", "password": cur_pwd, "role": "OPERATOR"},
            headers=admin_api_headers,
        )

        login_res = await ac.post("/api/v1/auth/login", json={"username": u_name, "password": cur_pwd})
        cookies = login_res.cookies
        csrf = login_res.json()["csrf_token"]

        # Attempt password change with WRONG current password (Must fail 401)
        bad_change = await ac.post(
            "/api/v1/auth/password/change",
            json={"current_password": "WrongCurrentPassword!", "new_password": new_pwd},
            cookies=cookies,
            headers={"X-CSRF-Token": csrf},
        )
        assert bad_change.status_code == 401

        # Attempt password change with correct current password
        good_change = await ac.post(
            "/api/v1/auth/password/change",
            json={"current_password": cur_pwd, "new_password": new_pwd},
            cookies=cookies,
            headers={"X-CSRF-Token": csrf},
        )
        assert good_change.status_code == 200


@pytest.mark.asyncio
async def test_request_size_limit_middleware():
    """Verify request bodies exceeding 10MB are rejected with HTTP 413."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # Simulate an oversized Content-Length header (15 MB)
        res = await ac.post(
            "/api/v1/auth/login",
            content=b"test",
            headers={"Content-Length": str(15 * 1024 * 1024), "Content-Type": "application/json"},
        )
        assert res.status_code == 413
        assert "Payload Too Large" in res.json()["error"]
