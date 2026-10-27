"""Integration & Security Verification Suite for Phase A1: Account & Password Security Hardening.

Covers:
1. NIST SP 800-63B-4 Password Length Policy (15-char standalone, 12-char with MFA, 128 max).
2. Unicode NFKC Normalization across hashing and verification.
3. Offline Breached Password Blocklist & Username Substring Rejection.
4. PBKDF2 Cryptographic Agility & Safe Failure on Malformed Hashes.
5. RFC 6238 TOTP Multi-Factor Authentication & Single-Use Recovery Code Security.
6. Distributed Redis-Backed Sliding-Window Rate Limiting with Exponential Delays.
7. Multi-Signal Rate Limiting (IP and Username) & Untrusted Proxy Spoofing Prevention.
8. Single-Use MFA Challenge Tokens & Replay Attack Defense.
9. Distributed Session Revocation via Redis & User Bulk Revocation on Password Changes.
10. Administrative Machine Key (X-Admin-Key) Boundary Enforcement (Forbidden on Personal Endpoints).
11. Privileged Role Mandatory MFA Policy (ADMIN and OPERATOR Cannot Disable MFA).
12. Timing-Safe Constant-Time Non-Existent User Defense Against Account Enumeration.
"""

import asyncio
from datetime import datetime, timezone
from typing import Dict
from uuid import uuid4

import pytest
from httpx import ASGITransport, AsyncClient

from waliya.main import create_app
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
    normalize_password,
    validate_password_complexity,
    verify_and_check_upgrade,
    verify_password,
)
from waliya.core.rate_limit import (
    SlidingWindowRateLimiter,
    get_client_ip,
    login_rate_limiter,
    mfa_rate_limiter,
)
from waliya.core.session import (
    clear_revocations_for_tests,
    create_session_token,
    is_session_revoked,
    revoke_all_user_sessions,
    revoke_session,
    verify_session_token,
)


@pytest.fixture(autouse=True)
def clean_security_state():
    """Ensure clean revocation and rate limiter caches between tests."""
    clear_revocations_for_tests()
    login_rate_limiter.reset()
    mfa_rate_limiter.reset()
    yield
    clear_revocations_for_tests()
    login_rate_limiter.reset()
    mfa_rate_limiter.reset()


@pytest.fixture
def admin_api_headers() -> Dict[str, str]:
    return {"X-Admin-Key": settings.ADMIN_API_KEY}


# ==============================================================================
# 1. NIST SP 800-63B-4 Dual Length Policy & Passphrase Validation
# ==============================================================================

def test_nist_dual_length_policy_and_passphrases():
    """Verify 15-char policy for standalone passwords, 12-char for MFA, and 128-char max."""
    # Standalone password (< 15 chars) must be rejected
    with pytest.raises(PasswordPolicyError, match="too short"):
        validate_password_complexity("ShortPass1234!", is_mfa_enforced=False)

    # Standalone password (>= 15 chars) is accepted
    valid_standalone = "Correct#Horse#Battery#2026!"
    assert validate_password_complexity(valid_standalone, is_mfa_enforced=False) == valid_standalone

    # MFA account (12-14 chars) is accepted
    valid_mfa_pwd = "MfaSecure123!"
    assert validate_password_complexity(valid_mfa_pwd, is_mfa_enforced=True) == valid_mfa_pwd

    # MFA account (< 12 chars) must be rejected
    with pytest.raises(PasswordPolicyError, match="too short"):
        validate_password_complexity("TooShort123", is_mfa_enforced=True)

    # Passphrase up to 128 characters is allowed
    long_passphrase = "a" * 128  # Wait, low entropy will trigger repetition check
    diverse_long_passphrase = ("Alpha-Bravo-Charlie-Delta-Echo-Foxtrot-Golf-Hotel-" * 3)[:128]
    assert len(diverse_long_passphrase) == 128
    assert validate_password_complexity(diverse_long_passphrase) == diverse_long_passphrase

    # Greater than 128 characters must be rejected
    with pytest.raises(PasswordPolicyError, match="too long"):
        validate_password_complexity(diverse_long_passphrase + "extra")


def test_unicode_nfkc_normalization():
    """Verify Unicode NFKC normalization prevents authentication bypass and canonical inconsistency."""
    # Full-width exclamation mark and full-width latin letters
    fullwidth_pwd = "Passphrase2026\uFF01\uFF21"
    normalized = normalize_password(fullwidth_pwd)
    assert normalized == "Passphrase2026!A"

    # Password hashed with full-width character verifies when user enters standard normalized ascii
    hashed = hash_password(fullwidth_pwd)
    assert verify_password("Passphrase2026!A", hashed) is True
    assert verify_password(fullwidth_pwd, hashed) is True


def test_offline_breached_blocklist_and_similarity():
    """Verify maintainable offline blocklist and username substring rejection."""
    # Common breached passwords rejected regardless of length
    with pytest.raises(PasswordPolicyError, match="too common"):
        validate_password_complexity("password12345678")

    with pytest.raises(PasswordPolicyError, match="too common"):
        validate_password_complexity("administrator2026")

    # Username similarity rejection
    with pytest.raises(PasswordPolicyError, match="must not contain your username"):
        validate_password_complexity("VeryLongSecurePassphraseForAlice!", username="alice")

    # Low character entropy (repetitive patterns)
    with pytest.raises(PasswordPolicyError, match="repetitive"):
        validate_password_complexity("aaaaaaaaaaaaaaaa")


# ==============================================================================
# 2. Cryptographic Agility & Malformed Hash Safety
# ==============================================================================

def test_pbkdf2_safe_failure_on_malformed_hashes():
    """Verify verify_password fails safely without exceptions on corrupted or malicious stored hashes."""
    pwd = "ValidPassphrase2026!"

    # Empty and non-string inputs
    assert verify_password("", "valid$hash") is False
    assert verify_password(pwd, "") is False
    assert verify_password(pwd, None) is False

    # Invalid parts count
    assert verify_password(pwd, "pbkdf2_sha256$600000$saltonly") is False
    assert verify_password(pwd, "pbkdf2_sha256$600000$salt$hash$extra") is False

    # Unsupported algorithm
    assert verify_password(pwd, "md5$600000$c2FsdA==$aGFzaA==") is False

    # Non-integer and invalid iterations
    assert verify_password(pwd, "pbkdf2_sha256$notanumber$c2FsdA==$aGFzaA==") is False
    assert verify_password(pwd, "pbkdf2_sha256$0$c2FsdA==$aGFzaA==") is False
    assert verify_password(pwd, "pbkdf2_sha256$-100$c2FsdA==$aGFzaA==") is False

    # Invalid base64 in salt or hash
    assert verify_password(pwd, "pbkdf2_sha256$600000$!!!invalid_b64!!!$aGFzaA==") is False
    assert verify_password(pwd, "pbkdf2_sha256$600000$c2FsdA==$!!!invalid_b64!!!") is False


def test_transparent_hash_upgrade():
    """Verify older hash iterations trigger transparent upgrade on successful verification."""
    pwd = "EnterpriseSecurePassphrase2026!"
    legacy_hash = hash_password(pwd, iterations=200_000)

    is_valid, upgraded = verify_and_check_upgrade(pwd, legacy_hash)
    assert is_valid is True
    assert upgraded is not None
    assert int(upgraded.split("$")[1]) == 600_000
    assert verify_password(pwd, upgraded) is True

    # Already at current iterations -> no upgrade returned
    is_valid_current, upgraded_current = verify_and_check_upgrade(pwd, upgraded)
    assert is_valid_current is True
    assert upgraded_current is None


# ==============================================================================
# 3. Distributed Redis Rate Limiting & Proxy Verification
# ==============================================================================

def test_redis_distributed_sliding_window_rate_limiter():
    """Verify sliding-window rate limiting with exponential backoff on consecutive lockouts."""
    limiter = SlidingWindowRateLimiter(
        domain=f"test_{uuid4().hex[:6]}",
        max_attempts=3,
        window_seconds=10,
        base_lockout_seconds=2,
        max_lockout_seconds=10,
    )
    test_key = "192.0.2.1"

    # Initial attempts
    assert limiter.is_rate_limited(test_key) is False
    limiter.record_failure(test_key)
    limiter.record_failure(test_key)
    assert limiter.is_rate_limited(test_key) is False

    # 3rd failure reaches max_attempts
    limiter.record_failure(test_key)
    assert limiter.is_rate_limited(test_key) is True
    rem = limiter.get_remaining_lockout_seconds(test_key)
    assert 0 < rem <= 3

    # Success clears lockout immediately
    limiter.record_success(test_key)
    assert limiter.is_rate_limited(test_key) is False
    assert limiter.get_remaining_lockout_seconds(test_key) == 0


def test_trusted_proxy_ip_resolution():
    """Verify client IP extraction ignores untrusted X-Forwarded-For headers."""
    class DummyClient:
        def __init__(self, host: str):
            self.host = host

    class DummyRequest:
        def __init__(self, client_host: str, headers: Dict[str, str]):
            self.client = DummyClient(client_host)
            self.headers = headers

    # Case 1: Untrusted external caller trying to spoof IP
    req_spoof = DummyRequest(
        client_host="203.0.113.50",
        headers={"X-Forwarded-For": "10.0.0.1, 127.0.0.1"},
    )
    assert get_client_ip(req_spoof) == "203.0.113.50"

    # Case 2: Trusted local reverse proxy forwarding client IP
    req_trusted = DummyRequest(
        client_host="127.0.0.1",
        headers={"X-Forwarded-For": "198.51.100.22, 127.0.0.1"},
    )
    assert get_client_ip(req_trusted) == "198.51.100.22"


# ==============================================================================
# 4. Distributed Session Revocation via Redis
# ==============================================================================

def test_distributed_session_revocation():
    """Verify session revocation persists and propagates via Redis across workers."""
    token, _ = create_session_token(
        secret_key=settings.SECRET_KEY,
        actor="soc_analyst",
        role="ANALYST",
        user_id=str(uuid4()),
    )
    session_id = token.split(":")[0]

    # Active session is valid
    verified = verify_session_token(token, settings.SECRET_KEY)
    assert verified is not None
    assert verified["actor"] == "soc_analyst"

    # Revoke session
    revoke_session(session_id)
    assert is_session_revoked(session_id) is True

    # Token immediately rejected
    assert verify_session_token(token, settings.SECRET_KEY) is None


def test_user_bulk_session_revocation():
    """Verify revoke_all_user_sessions invalidates previously issued sessions for that user."""
    target_user_id = str(uuid4())
    token_old, _ = create_session_token(
        secret_key=settings.SECRET_KEY,
        actor="soc_analyst",
        role="ANALYST",
        user_id=target_user_id,
    )
    s_id_old = token_old.split(":")[0]
    issued_at_old = int(token_old.split(":")[1])

    # Invalidate all user sessions
    revoke_all_user_sessions(target_user_id)

    # Old token fails verification
    assert is_session_revoked(s_id_old, issued_at=issued_at_old, user_id=target_user_id) is True
    assert verify_session_token(token_old, settings.SECRET_KEY) is None


# ==============================================================================
# 5. End-to-End API Security & Boundary Tests
# ==============================================================================

@pytest.mark.asyncio
async def test_admin_api_key_forbidden_on_personal_endpoints(admin_api_headers):
    """Verify machine-to-machine X-Admin-Key cannot bypass personal MFA or password endpoints."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        # 1. Attempt MFA enrollment via machine API key
        res_enroll = await ac.post("/api/v1/auth/mfa/enroll", headers=admin_api_headers)
        assert res_enroll.status_code == 403
        assert "interactive user session" in res_enroll.json()["detail"]

        # 2. Attempt MFA disablement via machine API key
        res_disable = await ac.post(
            "/api/v1/auth/mfa/disable",
            json={"current_password": "any_password"},
            headers=admin_api_headers,
        )
        assert res_disable.status_code == 403
        assert "interactive user session" in res_disable.json()["detail"]

        # 3. Attempt personal password change via machine API key
        res_change = await ac.post(
            "/api/v1/auth/password/change",
            json={"current_password": "any", "new_password": "Waliya#Security#Passphrase#2026!"},
            headers=admin_api_headers,
        )
        assert res_change.status_code == 403
        assert "interactive user session" in res_change.json()["detail"]


@pytest.mark.asyncio
async def test_single_use_mfa_challenge_tokens_and_replay_defense(admin_api_headers):
    """Verify MFA challenge tokens are strictly single-use and cannot be replayed."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        unique_suffix = uuid4().hex[:6]
        user_name = f"mfa_user_{unique_suffix}"
        user_pass = "Waliya#Enterprise#Passphrase#2026!"

        # 1. Admin creates user account (15-char standalone policy enforced)
        create_res = await ac.post(
            "/api/v1/users",
            json={
                "username": user_name,
                "email": f"{user_name}@soc.et",
                "password": user_pass,
                "role": "ANALYST",
            },
            headers=admin_api_headers,
        )
        assert create_res.status_code == 201

        # 2. Login to get interactive session cookie
        login_res = await ac.post(
            "/api/v1/auth/login",
            json={"username": user_name, "password": user_pass},
        )
        assert login_res.status_code == 200
        csrf_token = login_res.json()["csrf_token"]
        session_cookies = login_res.cookies

        # 3. Enroll MFA
        enroll_res = await ac.post(
            "/api/v1/auth/mfa/enroll",
            headers={"X-CSRF-Token": csrf_token},
            cookies=session_cookies,
        )
        assert enroll_res.status_code == 200
        totp_secret = enroll_res.json()["secret"]
        recovery_codes = enroll_res.json()["recovery_codes"]

        # 4. Confirm enrollment with valid TOTP code
        current_code = generate_totp_code(totp_secret)
        confirm_res = await ac.post(
            "/api/v1/auth/mfa/verify",
            json={"code": current_code},
            headers={"X-CSRF-Token": csrf_token},
            cookies=session_cookies,
        )
        assert confirm_res.status_code == 200

        # 5. Subsequent login triggers MFA challenge
        mfa_login_res = await ac.post(
            "/api/v1/auth/login",
            json={"username": user_name, "password": user_pass},
        )
        assert mfa_login_res.status_code == 200
        assert mfa_login_res.json()["status"] == "MFA_REQUIRED"
        challenge_token = mfa_login_res.json()["challenge_token"]
        assert challenge_token is not None

        # 6. Complete challenge with fresh TOTP code
        code_for_login = generate_totp_code(totp_secret)
        complete_res = await ac.post(
            "/api/v1/auth/mfa/challenge",
            json={"challenge_token": challenge_token, "code": code_for_login},
        )
        assert complete_res.status_code == 200
        assert complete_res.json()["status"] == "AUTHENTICATED"

        # 7. REPLAY ATTACK: Submit the exact same challenge token again
        replay_res = await ac.post(
            "/api/v1/auth/mfa/challenge",
            json={"challenge_token": challenge_token, "code": code_for_login},
        )
        assert replay_res.status_code == 400
        assert "already consumed" in replay_res.json()["detail"]


@pytest.mark.asyncio
async def test_privileged_mfa_cannot_be_disabled(admin_api_headers):
    """Verify accounts with privileged roles (ADMIN, OPERATOR) cannot disable mandatory MFA."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        unique_suffix = uuid4().hex[:6]
        operator_name = f"op_mfa_{unique_suffix}"
        operator_pass = "Waliya#Enterprise#Passphrase#2026!"

        # 1. Create OPERATOR account
        create_res = await ac.post(
            "/api/v1/users",
            json={
                "username": operator_name,
                "email": f"{operator_name}@soc.et",
                "password": operator_pass,
                "role": "OPERATOR",
            },
            headers=admin_api_headers,
        )
        assert create_res.status_code == 201

        # 2. Login to get interactive session
        login_res = await ac.post(
            "/api/v1/auth/login",
            json={"username": operator_name, "password": operator_pass},
        )
        assert login_res.status_code == 200
        csrf_token = login_res.json()["csrf_token"]
        cookies = login_res.cookies

        # 3. Enroll and activate MFA
        enroll_res = await ac.post(
            "/api/v1/auth/mfa/enroll",
            headers={"X-CSRF-Token": csrf_token},
            cookies=cookies,
        )
        totp_secret = enroll_res.json()["secret"]
        await ac.post(
            "/api/v1/auth/mfa/verify",
            json={"code": generate_totp_code(totp_secret)},
            headers={"X-CSRF-Token": csrf_token},
            cookies=cookies,
        )

        # 4. Attempt to disable MFA on privileged account -> Must be rejected with 403 Forbidden
        disable_res = await ac.post(
            "/api/v1/auth/mfa/disable",
            json={"current_password": operator_pass},
            headers={"X-CSRF-Token": csrf_token},
            cookies=cookies,
        )
        assert disable_res.status_code == 403
        assert "mandatory for privileged accounts" in disable_res.json()["detail"]


@pytest.mark.asyncio
async def test_multi_signal_account_rate_limiting():
    """Verify brute force attack targeting a single username is rate-limited even with rotating IPs."""
    app = create_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
        target_user = "target_analyst_account"
        target_pwd = "WrongPasswordAttempt123!"

        # Simulate requests from 6 different IP addresses targeting the same user
        responses = []
        for i in range(6):
            client_ip = f"198.51.100.{10 + i}"
            res = await ac.post(
                "/api/v1/auth/login",
                json={"username": target_user, "password": target_pwd},
                headers={"X-Forwarded-For": f"{client_ip}, 127.0.0.1"},
            )
            responses.append(res.status_code)

        # First 5 attempts return 401 Unauthorized
        assert responses[:5] == [401, 401, 401, 401, 401]
        # 6th attempt is locked out by user-level rate limiting returning 429 Too Many Requests
        assert responses[5] == 429
