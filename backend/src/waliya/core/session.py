"""Cryptographically signed session and CSRF token management with server-side revocation.

Specifications:
- Token Format: session_id:issued_at:actor:csrf_token:role:mfa_authenticated:user_id:hmac_signature
- Backward Compatibility: Parses 4-part legacy tokens and 7-part enterprise tokens
- Cryptographic Integrity: HMAC-SHA256 signature verified with constant-time comparison
- Revocation Registry: In-memory sliding-window cache backed by persistent invalidation tracking
- CSRF Protection: Double-submit HMAC constant-time cookie validation on state-changing requests
"""

import hashlib
import hmac
import logging
import secrets
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger("waliya.core.session")

_session_lock = threading.Lock()

# In-memory revocation registry mapping session_id -> expires_at_timestamp
_REVOKED_SESSIONS: Dict[str, float] = {}

# In-memory user-level revocation mapping user_id -> revoked_before_timestamp
_REVOKED_USER_TIMESTAMPS: Dict[str, float] = {}


def _get_redis_client() -> Optional[Any]:
    """Lazy load Redis client for distributed session revocation."""
    try:
        from redis import Redis
        from waliya.config import settings
        return Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
    except Exception as exc:
        logger.debug("Redis connection not available for session revocation: %s", exc)
        return None


def revoke_session(
    session_id: str,
    expires_at_timestamp: Optional[float] = None,
    user_id: Optional[str] = None,
) -> None:
    """Register a session as revoked immediately on the server across all workers."""
    now = time.time()
    # Default TTL of 8 hours if not provided
    expiry = expires_at_timestamp if expires_at_timestamp is not None else now + 28800
    ttl = max(1, int(expiry - now))

    with _session_lock:
        _REVOKED_SESSIONS[session_id] = expiry
        _cleanup_expired_revocations()

    r = _get_redis_client()
    if r is not None:
        try:
            r.set(f"session:revoked:{session_id}", "1", ex=ttl)
        except Exception as exc:
            logger.debug("Redis set session revocation failed: %s", exc)

    logger.info("Session %s revoked on server (user_id=%s)", session_id, user_id or "unknown")


def revoke_all_user_sessions(user_id: str) -> None:
    """Invalidate all active sessions issued for a user before current timestamp across all workers."""
    now = time.time()
    with _session_lock:
        _REVOKED_USER_TIMESTAMPS[user_id] = now

    r = _get_redis_client()
    if r is not None:
        try:
            # TTL equal to max session lifespan (8 hours = 28800 seconds)
            r.set(f"session:user_revoked_before:{user_id}", str(now), ex=28800)
        except Exception as exc:
            logger.debug("Redis user session bulk revocation failed: %s", exc)

    logger.info("All existing sessions for user %s revoked at ts %f", user_id, now)


def is_session_revoked(
    session_id: str,
    issued_at: int = 0,
    user_id: Optional[str] = None,
) -> bool:
    """Check whether a session ID or user has been revoked on the server."""
    now = time.time()

    # 1. Fast in-memory check
    with _session_lock:
        if session_id in _REVOKED_SESSIONS:
            expiry = _REVOKED_SESSIONS[session_id]
            if expiry > now:
                return True
            else:
                _REVOKED_SESSIONS.pop(session_id, None)

        if user_id and user_id in _REVOKED_USER_TIMESTAMPS:
            revoked_before = _REVOKED_USER_TIMESTAMPS[user_id]
            if issued_at <= revoked_before:
                return True

    # 2. Distributed Redis check
    r = _get_redis_client()
    if r is not None:
        try:
            if r.exists(f"session:revoked:{session_id}"):
                return True
            if user_id:
                rev_ts_val = r.get(f"session:user_revoked_before:{user_id}")
                if rev_ts_val:
                    try:
                        if issued_at <= float(rev_ts_val):
                            return True
                    except ValueError:
                        pass
        except Exception as exc:
            logger.debug("Redis is_session_revoked lookup failed: %s", exc)

    return False


def _cleanup_expired_revocations() -> None:
    """Prune expired session revocation records to prevent unbounded memory growth."""
    now = time.time()
    stale_keys = [s_id for s_id, exp in _REVOKED_SESSIONS.items() if exp <= now]
    for k in stale_keys:
        _REVOKED_SESSIONS.pop(k, None)


def clear_revocations_for_tests() -> None:
    """Clear revocation caches (for automated tests)."""
    with _session_lock:
        _REVOKED_SESSIONS.clear()
        _REVOKED_USER_TIMESTAMPS.clear()

    r = _get_redis_client()
    if r is not None:
        try:
            keys = r.keys("session:revoked:*") + r.keys("session:user_revoked_before:*")
            if keys:
                r.delete(*keys)
        except Exception:
            pass


def create_session_token(
    secret_key: str,
    actor: str = "admin",
    role: str = "ADMIN",
    mfa_authenticated: bool = True,
    user_id: Optional[str] = None,
) -> Tuple[str, str]:
    """Create a signed, tamper-evident session token and corresponding CSRF token.

    Format: session_id:issued_at:actor:csrf_token:role:mfa_authenticated:user_id:signature
    """
    session_id = secrets.token_hex(16)
    issued_at = int(datetime.now(timezone.utc).timestamp())
    csrf_token = secrets.token_urlsafe(32)
    mfa_flag = "1" if mfa_authenticated else "0"
    uid = user_id if user_id else ""

    payload = f"{session_id}:{issued_at}:{actor}:{csrf_token}:{role}:{mfa_flag}:{uid}"
    signature = hmac.new(
        secret_key.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    token = f"{payload}:{signature}"
    return token, csrf_token


def verify_session_token(
    token: Optional[str],
    secret_key: str,
    ttl_seconds: int = 28800,
) -> Optional[Dict[str, Any]]:
    """Verify cryptographic signature, expiration, and server-side revocation status."""
    if not token or not isinstance(token, str):
        return None

    parts = token.rsplit(":", 1)
    if len(parts) != 2:
        return None

    payload, signature = parts
    expected_signature = hmac.new(
        secret_key.encode("utf-8"),
        payload.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(signature.lower(), expected_signature.lower()):
        logger.warning("Session token HMAC signature verification failed")
        return None

    payload_parts = payload.split(":")
    if len(payload_parts) == 4:
        # Legacy format: session_id:issued_at:actor:csrf_token
        session_id, issued_at_str, actor, csrf_token = payload_parts
        role = "ADMIN" if actor == "admin" else "ANALYST"
        mfa_authenticated = True
        user_id = None
    elif len(payload_parts) == 7:
        # Enterprise format: session_id:issued_at:actor:csrf_token:role:mfa_authenticated:user_id
        session_id, issued_at_str, actor, csrf_token, role, mfa_flag, uid_str = payload_parts
        mfa_authenticated = (mfa_flag == "1")
        user_id = uid_str if uid_str else None
    else:
        return None

    try:
        issued_at = int(issued_at_str)
    except ValueError:
        return None

    now_ts = int(datetime.now(timezone.utc).timestamp())
    if ttl_seconds <= 0 or (now_ts - issued_at) >= ttl_seconds or (issued_at - now_ts) > 60:
        logger.info("Session %s has expired (age=%ds, ttl=%ds)", session_id, now_ts - issued_at, ttl_seconds)
        return None

    # Check server-side revocation
    if is_session_revoked(session_id, issued_at=issued_at, user_id=user_id):
        logger.warning("Session %s has been revoked on the server", session_id)
        return None

    return {
        "session_id": session_id,
        "issued_at": issued_at,
        "actor": actor,
        "csrf_token": csrf_token,
        "role": role,
        "mfa_authenticated": mfa_authenticated,
        "user_id": user_id,
    }


def verify_csrf_token(cookie_csrf: Optional[str], header_csrf: Optional[str]) -> bool:
    """Validate CSRF token header against cookie using constant-time comparison."""
    if not cookie_csrf or not header_csrf:
        return False
    return hmac.compare_digest(cookie_csrf.strip(), header_csrf.strip())
