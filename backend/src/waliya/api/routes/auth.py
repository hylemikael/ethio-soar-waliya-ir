"""Enterprise Authentication, Multi-Factor Authentication (MFA), and Session Management.

Specifications:
- NIST SP 800-63B-4 Password Security & Transparent Upgrades (PBKDF2-HMAC-SHA256)
- RFC 6238 TOTP Multi-Factor Authentication & Single-Use Recovery Codes
- Cryptographically Random, Single-Use Password Reset Tokens with Timing Enumeration Resistance
- Server-Side Session Revocation Registry & CSRF Protection
- Progressive Delays & In-Memory Sliding-Window Rate Limiting
- Full Audit Ledger Logging of Identity & Authentication Lifecycle Events
"""

import hmac
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field, model_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.audit.ledger_service import AuditLedgerService
from waliya.config import settings
from waliya.core.auth import AuthenticatedActor, UserRole, get_authenticated_actor
from waliya.core.mfa import (
    decrypt_secret,
    encrypt_secret,
    generate_recovery_codes,
    generate_totp_secret,
    generate_totp_uri,
    verify_and_consume_recovery_code,
    verify_totp_code,
)
from waliya.core.password import (
    PasswordPolicyError,
    generate_secure_reset_token,
    hash_password,
    validate_password_complexity,
    verify_and_check_upgrade,
    verify_password,
    verify_reset_token,
)
import json
import secrets

from waliya.core.rate_limit import (
    get_client_ip,
    login_rate_limiter,
    mfa_rate_limiter,
    password_reset_limiter,
)
from waliya.core.session import (
    create_session_token,
    revoke_all_user_sessions,
    revoke_session,
    verify_session_token,
)
from waliya.db.models import PasswordResetTokenModel, UserModel
from waliya.db.session import get_db_session

logger = logging.getLogger("waliya.api.routes.auth")

router = APIRouter(prefix="/auth", tags=["auth"])

# Temporary in-memory pending MFA challenges (challenge_token -> metadata)
_PENDING_MFA_CHALLENGES: Dict[str, Dict[str, Any]] = {}

# Static dummy hash for constant-time comparison on non-existent accounts
_DUMMY_PBKDF2_HASH = (
    "pbkdf2_sha256$600000$ZHVtbXlzYWx0MTIzNDU2Nw==$ZHVtbXloYXNoMTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY="
)


def _get_redis_client() -> Optional[Any]:
    """Lazy load Redis client for distributed MFA challenge state."""
    try:
        from redis import Redis
        return Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
    except Exception as exc:
        logger.debug("Redis client unavailable in auth routes: %s", exc)
        return None


def _store_mfa_challenge(challenge_token: str, data: Dict[str, Any], ttl_seconds: int = 300) -> None:
    """Store temporary MFA challenge token in distributed Redis with local in-memory fallback."""
    _PENDING_MFA_CHALLENGES[challenge_token] = data
    r = _get_redis_client()
    if r is not None:
        try:
            data_copy = dict(data)
            if "expires_at" in data_copy and isinstance(data_copy["expires_at"], datetime):
                data_copy["expires_at"] = data_copy["expires_at"].isoformat()
            r.set(f"mfa:challenge:{challenge_token}", json.dumps(data_copy), ex=ttl_seconds)
        except Exception as exc:
            logger.debug("Failed storing MFA challenge in Redis: %s", exc)


def _consume_mfa_challenge(challenge_token: str) -> Optional[Dict[str, Any]]:
    """Retrieve and immediately invalidate an MFA challenge token (atomic single-use)."""
    data: Optional[Dict[str, Any]] = None
    r = _get_redis_client()
    if r is not None:
        try:
            raw = r.getdel(f"mfa:challenge:{challenge_token}")
            if raw:
                data = json.loads(raw)
        except Exception as exc:
            logger.debug("Failed consuming MFA challenge from Redis: %s", exc)

    local_data = _PENDING_MFA_CHALLENGES.pop(challenge_token, None)
    if data is None:
        data = local_data

    if not data:
        return None

    # Check expiration
    expires_at = data.get("expires_at")
    if isinstance(expires_at, (int, float)):
        if datetime.now(timezone.utc).timestamp() > expires_at:
            return None
    elif isinstance(expires_at, str):
        try:
            exp_dt = datetime.fromisoformat(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                return None
        except ValueError:
            pass
    elif isinstance(expires_at, datetime):
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > expires_at:
            return None

    return data


# --- Request and Response Schemas ---

class LoginRequest(BaseModel):
    """Payload for user and administrator login."""
    username: Optional[str] = Field(None, min_length=1, max_length=64, description="User account username or email")
    password: Optional[str] = Field(None, min_length=1, max_length=512, description="User password or administrative secret")
    api_key: Optional[str] = Field(None, min_length=1, max_length=512, description="Legacy administrative API key")
    mfa_code: Optional[str] = Field(None, min_length=6, max_length=16, description="Optional 6-digit TOTP or backup recovery code")

    @model_validator(mode="after")
    def validate_credentials_present(self) -> "LoginRequest":
        if not self.username and not self.password and not self.api_key:
            raise ValueError("Credentials (username/password or api_key) are required.")
        return self


class LoginResponse(BaseModel):
    status: str
    authenticated: bool = True
    actor: str
    role: str = "ADMIN"
    user_id: Optional[str] = None
    csrf_token: Optional[str] = None
    expires_in: int
    mfa_required: bool = False
    challenge_token: Optional[str] = None


class MFAChallengeRequest(BaseModel):
    challenge_token: str = Field(..., description="Temporary challenge token issued after primary credential verification")
    code: str = Field(..., min_length=6, max_length=16, description="6-digit TOTP code or backup recovery code")


class MFAEnrollResponse(BaseModel):
    secret: str
    otpauth_uri: str
    recovery_codes: List[str]
    message: str = "Scan the QR code or enter the secret in your authenticator app, then verify with a 6-digit code."


class MFAVerifyRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, description="6-digit TOTP code from authenticator app")


class MFADisableRequest(BaseModel):
    current_password: str = Field(..., min_length=1, description="Current password for sensitive re-authentication")


class PasswordResetRequestPayload(BaseModel):
    username_or_email: str = Field(..., min_length=3, max_length=255, description="Account username or registered email")


class PasswordResetConfirmPayload(BaseModel):
    token: str = Field(..., min_length=16, description="Cryptographic password reset token")
    new_password: str = Field(..., min_length=12, max_length=128, description="New NIST-compliant password")


class PasswordChangePayload(BaseModel):
    current_password: str = Field(..., min_length=1, description="Current password for re-authentication")
    new_password: str = Field(..., min_length=12, max_length=128, description="New NIST-compliant password")


# --- Helper Functions ---

async def ensure_initial_admin_seeded(session: AsyncSession) -> None:
    """Ensure at least one administrator account exists, seeding from configuration if empty."""
    res = await session.execute(select(UserModel).where(UserModel.username == "admin"))
    existing_admin = res.scalars().first()
    if not existing_admin:
        # Check if any user exists
        user_res = await session.execute(select(UserModel).limit(1))
        if not user_res.scalars().first():
            hashed = hash_password(settings.ADMIN_API_KEY)
            initial_admin = UserModel(
                id=uuid4(),
                username="admin",
                email="admin@waliya.local",
                full_name="Default Administrator",
                password_hash=hashed,
                password_algo="pbkdf2_sha256",
                role=UserRole.ADMIN.value,
                is_active=True,
                is_mfa_enabled=False,
            )
            session.add(initial_admin)
            await session.commit()
            logger.info("Seeded initial default administrator account 'admin'")


# --- Authentication Endpoints ---

@router.post(
    "/login",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user or administrator and establish secure session",
)
async def login(
    payload: LoginRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
) -> LoginResponse:
    """Authenticate credentials against user accounts or root administrative key.

    Enforces:
    - IP and Account sliding-window rate limiting.
    - Constant-time verification to prevent timing attacks.
    - NIST SP 800-63B-4 transparent password hash upgrades.
    - Multi-Factor Authentication challenge when enabled.
    - Audit logging of all login successes and failures.
    - HttpOnly, SameSite, and Secure session cookie emission with CSRF token.
    """
    await ensure_initial_admin_seeded(session)
    client_ip = get_client_ip(request)
    username_val = payload.username.strip() if payload.username else None
    user_key = f"user:{username_val.lower()}" if username_val else None

    # 1. Multi-signal Rate Limiting Check (both IP and targeted account)
    if login_rate_limiter.is_rate_limited(client_ip) or (user_key and login_rate_limiter.is_rate_limited(user_key)):
        rem_ip = login_rate_limiter.get_remaining_lockout_seconds(client_ip)
        rem_user = login_rate_limiter.get_remaining_lockout_seconds(user_key) if user_key else 0
        rem = max(rem_ip, rem_user)
        logger.warning("Login rate limit exceeded for client IP %s or user %s (locked for %ds)", client_ip, user_key, rem)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed authentication attempts. Please wait {rem} seconds before retrying.",
        )

    # 2. Case A: Legacy administrative API key or password-only check
    if not payload.username and (payload.api_key or payload.password):
        secret_candidate = (payload.api_key or payload.password).strip()
        if not hmac.compare_digest(secret_candidate, settings.ADMIN_API_KEY):
            login_rate_limiter.record_failure(client_ip)
            logger.warning("Failed administrative key login attempt from IP: %s", client_ip)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid administrative credentials",
            )

        login_rate_limiter.record_success(client_ip)
        session_token, csrf_token = create_session_token(
            secret_key=settings.SECRET_KEY,
            actor="admin",
            role=UserRole.ADMIN.value,
            mfa_authenticated=True,
        )

        _set_session_cookies(response, session_token, csrf_token)
        await AuditLedgerService.record_action(
            session=session,
            actor_id="admin",
            action="USER_LOGIN_SUCCESS",
            target_entity="auth:admin_key",
            payload={"auth_method": "api_key", "client_ip": client_ip},
            actor_role=UserRole.ADMIN.value,
        )
        return LoginResponse(
            status="AUTHENTICATED",
            actor="admin",
            role=UserRole.ADMIN.value,
            csrf_token=csrf_token,
            expires_in=settings.SESSION_TTL_SECONDS,
        )

    # 3. Case B: Multi-User Username & Password Authentication
    password_val = (payload.password or payload.api_key or "").strip()

    # Query user by username or email
    user_res = await session.execute(
        select(UserModel).where(
            (UserModel.username == username_val) | (UserModel.email == username_val)
        )
    )
    user = user_res.scalars().first()

    now_utc = datetime.now(timezone.utc)

    # Timing-safe dummy hash verification if user not found to prevent username enumeration
    if not user:
        verify_password(password_val, _DUMMY_PBKDF2_HASH)
        login_rate_limiter.record_failure(client_ip)
        if user_key:
            login_rate_limiter.record_failure(user_key)
        logger.warning("Failed login for non-existent user '%s' from IP: %s", username_val, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Check account active status
    if not user.is_active:
        verify_password(password_val, _DUMMY_PBKDF2_HASH)
        login_rate_limiter.record_failure(client_ip)
        if user_key:
            login_rate_limiter.record_failure(user_key)
        logger.warning("Login attempt for deactivated user '%s' from IP: %s", username_val, client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Check progressive account lockout
    if user.locked_until and user.locked_until > now_utc:
        rem_lock = int((user.locked_until - now_utc).total_seconds())
        logger.warning("Account '%s' is temporarily locked out until %s", username_val, user.locked_until)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Account temporarily locked due to multiple failed attempts. Please retry in {rem_lock} seconds.",
        )

    # Verify password with transparent parameter upgrade check
    is_valid, upgraded_hash = verify_and_check_upgrade(password_val, user.password_hash)
    if not is_valid:
        login_rate_limiter.record_failure(client_ip)
        if user_key:
            login_rate_limiter.record_failure(user_key)
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= 5:
            user.locked_until = now_utc + timedelta(minutes=5)
            logger.warning("User '%s' locked out for 5 minutes after 5 failed attempts", username_val)
        await session.commit()

        await AuditLedgerService.record_action(
            session=session,
            actor_id=str(user.id),
            action="USER_LOGIN_FAILED",
            target_entity=f"user:{user.id}",
            payload={"username": username_val, "client_ip": client_ip, "reason": "bad_password"},
            actor_role=user.role,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Password verified successfully: clear lockouts and update upgraded hash if needed
    user.failed_login_attempts = 0
    user.locked_until = None
    if upgraded_hash:
        user.password_hash = upgraded_hash
        user.password_algo = "pbkdf2_sha256"
        logger.info("Transparently upgraded password hash for user '%s'", user.username)
    await session.commit()
    login_rate_limiter.record_success(client_ip)
    if user_key:
        login_rate_limiter.record_success(user_key)

    # 4. Check Multi-Factor Authentication (MFA)
    if user.is_mfa_enabled:
        # Check if MFA code was supplied directly in initial payload
        if payload.mfa_code:
            mfa_valid = _verify_user_mfa(user, payload.mfa_code.strip())
            if not mfa_valid:
                mfa_rate_limiter.record_failure(client_ip)
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid multi-factor authentication code or recovery code",
                )
        else:
            # Issue temporary challenge token (5-minute TTL, single-use, Redis backed)
            challenge_token = secrets.token_urlsafe(32)
            challenge_payload = {
                "user_id": str(user.id),
                "username": user.username,
                "role": user.role,
                "expires_at": (now_utc + timedelta(minutes=5)).timestamp(),
            }
            _store_mfa_challenge(challenge_token, challenge_payload, ttl_seconds=300)
            logger.info("MFA challenge issued for user '%s' from IP %s", user.username, client_ip)
            return LoginResponse(
                status="MFA_REQUIRED",
                authenticated=False,
                actor=user.username,
                role=user.role,
                user_id=str(user.id),
                expires_in=300,
                mfa_required=True,
                challenge_token=challenge_token,
            )

    # 5. Establish authenticated session
    session_token, csrf_token = create_session_token(
        secret_key=settings.SECRET_KEY,
        actor=user.username,
        role=user.role,
        mfa_authenticated=True,
        user_id=str(user.id),
    )
    _set_session_cookies(response, session_token, csrf_token)

    await AuditLedgerService.record_action(
        session=session,
        actor_id=str(user.id),
        action="USER_LOGIN_SUCCESS",
        target_entity=f"user:{user.id}",
        payload={"username": user.username, "role": user.role, "client_ip": client_ip},
        actor_role=user.role,
    )

    logger.info("User '%s' (role=%s) authenticated successfully from IP: %s", user.username, user.role, client_ip)
    return LoginResponse(
        status="AUTHENTICATED",
        actor=user.username,
        role=user.role,
        user_id=str(user.id),
        csrf_token=csrf_token,
        expires_in=settings.SESSION_TTL_SECONDS,
    )


@router.post(
    "/mfa/challenge",
    response_model=LoginResponse,
    status_code=status.HTTP_200_OK,
    summary="Complete authentication challenge using MFA TOTP or backup recovery code",
)
async def complete_mfa_challenge(
    payload: MFAChallengeRequest,
    request: Request,
    response: Response,
    session: AsyncSession = Depends(get_db_session),
) -> LoginResponse:
    """Verify MFA TOTP code or single-use recovery code to complete login."""
    client_ip = get_client_ip(request)
    if mfa_rate_limiter.is_rate_limited(client_ip):
        rem = mfa_rate_limiter.get_remaining_lockout_seconds(client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many failed MFA verification attempts. Please retry in {rem} seconds.",
        )

    challenge_data = _consume_mfa_challenge(payload.challenge_token)
    if not challenge_data:
        mfa_rate_limiter.record_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="MFA challenge token is invalid, expired, or already consumed. Please log in again.",
        )

    user_id = UUID(challenge_data["user_id"])
    user = (await session.execute(
        select(UserModel).where(UserModel.id == user_id).with_for_update()
    )).scalars().first()
    if not user or not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is unavailable.",
        )

    mfa_valid = _verify_user_mfa(user, payload.code.strip())
    if not mfa_valid:
        mfa_rate_limiter.record_failure(client_ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid multi-factor authentication code or recovery code.",
        )

    mfa_rate_limiter.record_success(client_ip)
    await session.commit()

    # Issue full authenticated session
    session_token, csrf_token = create_session_token(
        secret_key=settings.SECRET_KEY,
        actor=user.username,
        role=user.role,
        mfa_authenticated=True,
        user_id=str(user.id),
    )
    _set_session_cookies(response, session_token, csrf_token)

    await AuditLedgerService.record_action(
        session=session,
        actor_id=str(user.id),
        action="USER_LOGIN_SUCCESS",
        target_entity=f"user:{user.id}",
        payload={"username": user.username, "mfa_verified": True, "client_ip": client_ip},
        actor_role=user.role,
    )

    return LoginResponse(
        status="AUTHENTICATED",
        actor=user.username,
        role=user.role,
        user_id=str(user.id),
        csrf_token=csrf_token,
        expires_in=settings.SESSION_TTL_SECONDS,
    )


@router.post(
    "/mfa/enroll",
    response_model=MFAEnrollResponse,
    status_code=status.HTTP_200_OK,
    summary="Initiate MFA enrollment generating encrypted secret and backup recovery codes",
)
async def enroll_mfa(
    actor: AuthenticatedActor = Depends(get_authenticated_actor),
    session: AsyncSession = Depends(get_db_session),
) -> MFAEnrollResponse:
    """Generate high-entropy Base32 TOTP secret, QR code URI, and backup recovery codes."""
    if actor.auth_method != "session" or not actor.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA enrollment requires an active interactive user session and cannot be performed via API key.",
        )

    user = (await session.execute(select(UserModel).where(UserModel.id == actor.user_id))).scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    raw_secret = generate_totp_secret()
    plain_recovery_codes, encrypted_codes = generate_recovery_codes()

    # Store encrypted pending secret on user profile
    user.mfa_secret_encrypted = encrypt_secret(raw_secret, settings.SECRET_KEY)
    user.mfa_recovery_codes_encrypted = encrypted_codes
    await session.commit()

    otpauth_uri = generate_totp_uri(secret=raw_secret, username=user.username)
    logger.info("MFA enrollment initiated for user '%s'", user.username)

    return MFAEnrollResponse(
        secret=raw_secret,
        otpauth_uri=otpauth_uri,
        recovery_codes=plain_recovery_codes,
    )


@router.post(
    "/mfa/verify",
    status_code=status.HTTP_200_OK,
    summary="Confirm MFA enrollment by verifying 6-digit TOTP code",
)
async def verify_mfa_enrollment(
    payload: MFAVerifyRequest,
    actor: AuthenticatedActor = Depends(get_authenticated_actor),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Verify candidate TOTP code and activate MFA on the calling account."""
    if actor.auth_method != "session" or not actor.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA verification requires an active interactive user session and cannot be performed via API key.",
        )

    user = (await session.execute(select(UserModel).where(UserModel.id == actor.user_id))).scalars().first()
    if not user or not user.mfa_secret_encrypted:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="MFA enrollment has not been initiated.")

    raw_secret = decrypt_secret(user.mfa_secret_encrypted, settings.SECRET_KEY)
    if not verify_totp_code(raw_secret, payload.code):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification code. Please check your authenticator app time synchronization.",
        )

    user.is_mfa_enabled = True
    await session.commit()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=str(user.id),
        action="USER_MFA_ENROLLED",
        target_entity=f"user:{user.id}",
        payload={"username": user.username},
        actor_role=user.role,
    )
    logger.info("MFA successfully enabled for user '%s'", user.username)
    return {"status": "MFA_ENABLED", "message": "Multi-factor authentication is now active on your account."}


@router.post(
    "/mfa/disable",
    status_code=status.HTTP_200_OK,
    summary="Disable MFA on account with mandatory password re-authentication",
)
async def disable_mfa(
    payload: MFADisableRequest,
    actor: AuthenticatedActor = Depends(get_authenticated_actor),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Disable MFA requiring re-authentication with current password."""
    if actor.auth_method != "session" or not actor.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA disablement requires an active interactive user session and cannot be performed via API key.",
        )

    user = (await session.execute(select(UserModel).where(UserModel.id == actor.user_id))).scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    # Privileged account MFA enforcement policy check
    if getattr(settings, "MFA_ENFORCED_FOR_PRIVILEGED", True) and user.role in ("ADMIN", "OPERATOR"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Multi-factor authentication is mandatory for privileged accounts (ADMIN, OPERATOR) and cannot be disabled.",
        )

    # Re-authentication verification
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Re-authentication failed. Current password is incorrect.",
        )

    user.is_mfa_enabled = False
    user.mfa_secret_encrypted = None
    user.mfa_recovery_codes_encrypted = None
    await session.commit()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=str(user.id),
        action="USER_MFA_REVOKED",
        target_entity=f"user:{user.id}",
        payload={"username": user.username},
        actor_role=user.role,
    )
    logger.info("MFA disabled for user '%s'", user.username)
    return {"status": "MFA_DISABLED", "message": "Multi-factor authentication has been disabled."}


@router.post(
    "/password-reset/request",
    status_code=status.HTTP_200_OK,
    summary="Request a time-limited password reset token (Enumeration Resistant)",
)
async def request_password_reset(
    payload: PasswordResetRequestPayload,
    request: Request,
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Generate unpredictable single-use password reset token with timing enumeration resistance."""
    client_ip = get_client_ip(request)
    if password_reset_limiter.is_rate_limited(client_ip):
        rem = password_reset_limiter.get_remaining_lockout_seconds(client_ip)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many password reset requests. Please retry in {rem} seconds.",
        )

    identifier = payload.username_or_email.strip()
    user_res = await session.execute(
        select(UserModel).where((UserModel.username == identifier) | (UserModel.email == identifier))
    )
    user = user_res.scalars().first()

    reset_token_plain: Optional[str] = None
    if user and user.is_active:
        plain_token, token_hash = generate_secure_reset_token()
        now_utc = datetime.now(timezone.utc)
        reset_record = PasswordResetTokenModel(
            id=uuid4(),
            user_id=user.id,
            token_hash=token_hash,
            expires_at=now_utc + timedelta(minutes=15),
            is_used=False,
        )
        session.add(reset_record)
        await session.commit()
        reset_token_plain = plain_token

        await AuditLedgerService.record_action(
            session=session,
            actor_id=str(user.id),
            action="USER_PASSWORD_RESET_REQUESTED",
            target_entity=f"user:{user.id}",
            payload={"username": user.username, "client_ip": client_ip},
            actor_role=user.role,
        )
        logger.info("Password reset token generated for user '%s'", user.username)

    # In testing/development, expose token in response to allow automated end-to-end verification
    is_dev = settings.ENV.lower() in ("development", "dev", "test")
    return {
        "status": "SUCCESS",
        "message": "If an active account matches the provided identifier, password reset instructions have been generated.",
        "reset_token": reset_token_plain if is_dev else None,
    }


@router.post(
    "/password-reset/confirm",
    status_code=status.HTTP_200_OK,
    summary="Confirm password reset with cryptographic token and NIST password policy",
)
async def confirm_password_reset(
    payload: PasswordResetConfirmPayload,
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Validate token, enforce NIST SP 800-63B-4 password policy, and revoke existing sessions."""
    # Find matching unused token
    now_utc = datetime.now(timezone.utc)
    res = await session.execute(
        select(PasswordResetTokenModel).where(
            (PasswordResetTokenModel.is_used == False) & (PasswordResetTokenModel.expires_at > now_utc)
        )
    )
    candidate_tokens = res.scalars().all()

    matched_token: Optional[PasswordResetTokenModel] = None
    for cand in candidate_tokens:
        if verify_reset_token(payload.token.strip(), cand.token_hash):
            matched_token = cand
            break

    if not matched_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password reset token is invalid, expired, or has already been used.",
        )

    user = (await session.execute(
        select(UserModel).where(UserModel.id == matched_token.user_id).with_for_update()
    )).scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User account not found.")

    # Validate NIST password complexity respecting user's MFA enrollment
    try:
        validate_password_complexity(
            payload.new_password,
            username=user.username,
            is_mfa_enforced=user.is_mfa_enabled,
        )
    except PasswordPolicyError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))

    # Apply new password
    user.password_hash = hash_password(payload.new_password)
    user.password_algo = "pbkdf2_sha256"
    user.password_changed_at = now_utc
    matched_token.is_used = True

    # Revoke all existing sessions for this user
    revoke_all_user_sessions(str(user.id))
    await session.commit()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=str(user.id),
        action="USER_PASSWORD_RESET_COMPLETED",
        target_entity=f"user:{user.id}",
        payload={"username": user.username},
        actor_role=user.role,
    )
    logger.info("Password successfully reset for user '%s'", user.username)
    return {"status": "SUCCESS", "message": "Password successfully updated. Please log in with your new password."}


@router.post(
    "/password/change",
    status_code=status.HTTP_200_OK,
    summary="Change password with re-authentication and session revocation",
)
async def change_password(
    payload: PasswordChangePayload,
    actor: AuthenticatedActor = Depends(get_authenticated_actor),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Change user password, validating current password and revoking active sessions."""
    if actor.auth_method != "session" or not actor.user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Password change requires an active interactive user session and cannot be performed via API key.",
        )

    user = (await session.execute(
        select(UserModel).where(UserModel.id == actor.user_id).with_for_update()
    )).scalars().first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

    # Re-authentication verification
    if not verify_password(payload.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Current password verification failed.",
        )

    # Validate NIST password complexity respecting user's MFA enrollment
    try:
        validate_password_complexity(
            payload.new_password,
            username=user.username,
            is_mfa_enforced=user.is_mfa_enabled,
        )
    except PasswordPolicyError as err:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(err))

    now_utc = datetime.now(timezone.utc)
    user.password_hash = hash_password(payload.new_password)
    user.password_algo = "pbkdf2_sha256"
    user.password_changed_at = now_utc

    # Revoke all existing sessions
    revoke_all_user_sessions(str(user.id))
    await session.commit()

    await AuditLedgerService.record_action(
        session=session,
        actor_id=str(user.id),
        action="USER_PASSWORD_CHANGED",
        target_entity=f"user:{user.id}",
        payload={"username": user.username},
        actor_role=user.role,
    )
    logger.info("Password changed and active sessions revoked for user '%s'", user.username)
    return {"status": "SUCCESS", "message": "Password updated successfully. Active sessions have been invalidated."}


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Terminate session with immediate server-side revocation and cookie clearance",
)
async def logout(
    request: Request,
    response: Response,
    actor: AuthenticatedActor = Depends(get_authenticated_actor),
    session: AsyncSession = Depends(get_db_session),
) -> Dict[str, str]:
    """Invalidate session on the server and clear browser cookies."""
    session_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_token:
        session_data = verify_session_token(
            token=session_token,
            secret_key=settings.SECRET_KEY,
            ttl_seconds=settings.SESSION_TTL_SECONDS,
        )
        if session_data:
            s_id = session_data.get("session_id")
            if s_id:
                revoke_session(session_id=s_id, user_id=actor.actor_id)

    response.delete_cookie(key=settings.SESSION_COOKIE_NAME, path="/api/v1")
    response.delete_cookie(key=settings.CSRF_COOKIE_NAME, path="/")

    await AuditLedgerService.record_action(
        session=session,
        actor_id=actor.actor_id,
        action="USER_LOGOUT",
        target_entity=f"user:{actor.actor_id}",
        payload={"actor": actor.username, "role": actor.role},
        actor_role=actor.role,
    )
    logger.info("Session revoked and logged out for actor '%s'", actor.username)
    return {"status": "LOGGED_OUT"}


@router.get(
    "/session",
    status_code=status.HTTP_200_OK,
    summary="Check active session authentication state and role",
)
async def check_session(request: Request) -> Dict[str, Any]:
    """Non-blocking session state check for UI initialization."""
    # Check session cookie
    session_cookie = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if session_cookie:
        session_data = verify_session_token(
            token=session_cookie,
            secret_key=settings.SECRET_KEY,
            ttl_seconds=settings.SESSION_TTL_SECONDS,
        )
        if session_data:
            return {
                "authenticated": True,
                "actor": session_data.get("actor", "admin"),
                "role": session_data.get("role", "ADMIN"),
                "user_id": session_data.get("user_id"),
                "mfa_authenticated": session_data.get("mfa_authenticated", True),
                "csrf_token": session_data.get("csrf_token"),
            }

    # Check X-Admin-Key or Bearer
    auth_hdr = request.headers.get("Authorization")
    admin_hdr = request.headers.get("X-Admin-Key")
    key = admin_hdr or (auth_hdr.split("Bearer ", 1)[1] if auth_hdr and auth_hdr.startswith("Bearer ") else None)
    if key and hmac.compare_digest(key.strip(), settings.ADMIN_API_KEY):
        return {
            "authenticated": True,
            "actor": "admin_key",
            "role": "ADMIN",
            "user_id": None,
            "mfa_authenticated": True,
            "csrf_token": None,
        }

    return {
        "authenticated": False,
        "actor": None,
        "csrf_token": None,
    }


# --- Internal Helper Methods ---

def _set_session_cookies(response: Response, session_token: str, csrf_token: str) -> None:
    """Configure HttpOnly session cookie and JavaScript-accessible CSRF cookie."""
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        max_age=settings.SESSION_TTL_SECONDS,
        path="/api/v1",
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=settings.SESSION_COOKIE_SECURE,
        samesite=settings.SESSION_COOKIE_SAMESITE,
        max_age=settings.SESSION_TTL_SECONDS,
        path="/",
    )


def _verify_user_mfa(user: UserModel, candidate_code: str) -> bool:
    """Check candidate code against TOTP or single-use recovery codes."""
    if not user.mfa_secret_encrypted:
        return False

    raw_secret = decrypt_secret(user.mfa_secret_encrypted, settings.SECRET_KEY)
    if verify_totp_code(raw_secret, candidate_code):
        return True

    # Check backup recovery codes
    if user.mfa_recovery_codes_encrypted:
        is_rec_valid, updated_payload = verify_and_consume_recovery_code(
            candidate_code,
            user.mfa_recovery_codes_encrypted,
            settings.SECRET_KEY,
        )
        if is_rec_valid:
            user.mfa_recovery_codes_encrypted = updated_payload
            logger.info("Single-use recovery code consumed for user '%s'", user.username)
            return True

    return False
