"""Distributed Redis-backed sliding window rate limiter with progressive backoff and in-memory fallback.

Specifications & Security Controls:
- Sliding Window Algorithm: Redis Sorted Sets (ZADD, ZREMRANGEBYSCORE, ZCARD)
- Keyspace Isolation: ratelimit:{domain}:{identifier}
- Key Expiry (TTL): Automatic TTL set on sorted sets to prevent memory leaks
- Progressive Lockout: Consecutive failures double the lockout duration (exponential backoff)
- Fallback Resilience: Gracefully falls back to thread-safe local sliding window if Redis is unavailable
- Trusted Proxy Support: get_client_ip resolves client IP through trusted proxies only, preventing X-Forwarded-For spoofing
"""

import logging
import secrets
import threading
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional
from fastapi import Request

logger = logging.getLogger("waliya.core.rate_limit")


def _get_redis_client() -> Optional[Any]:
    """Lazy load Redis client for distributed rate limiting."""
    try:
        from redis import Redis
        from waliya.config import settings
        return Redis.from_url(settings.REDIS_URL, decode_responses=True, socket_timeout=2.0)
    except Exception as exc:
        logger.debug("Redis connection not available for rate limiter: %s", exc)
        return None


def get_client_ip(request: Request) -> str:
    """Extract client IP safely respecting trusted reverse proxies.

    Prevents X-Forwarded-For header spoofing by untrusted external clients.
    """
    if not request.client:
        return "127.0.0.1"

    direct_ip = request.client.host
    from waliya.config import settings
    trusted = set(getattr(settings, "TRUSTED_PROXIES", ["127.0.0.1", "::1", "localhost", "testclient"]))

    # Only inspect X-Forwarded-For if request directly originated from a trusted proxy
    if direct_ip in trusted:
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            ips = [ip.strip() for ip in forwarded_for.split(",") if ip.strip()]
            if ips:
                return ips[0]

        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()

    return direct_ip


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter with progressive backoff to prevent brute-force and credential stuffing."""

    def __init__(
        self,
        domain: str = "general",
        max_attempts: int = 5,
        window_seconds: int = 60,
        base_lockout_seconds: int = 60,
        max_lockout_seconds: int = 3600,
    ):
        self.domain = domain
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.base_lockout_seconds = base_lockout_seconds
        self.max_lockout_seconds = max_lockout_seconds

        # In-memory thread-safe fallback structures
        self._lock = threading.Lock()
        self._failures: Dict[str, List[float]] = defaultdict(list)
        self._locked_until: Dict[str, float] = {}
        self._consecutive_lockouts: Dict[str, int] = defaultdict(int)

    def _redis_keys(self, key: str) -> Dict[str, str]:
        return {
            "attempts": f"ratelimit:{self.domain}:attempts:{key}",
            "locked": f"ratelimit:{self.domain}:locked:{key}",
            "consecutive": f"ratelimit:{self.domain}:consec:{key}",
        }

    def is_rate_limited(self, key: str) -> bool:
        """Check if an identity key is currently locked out or has exceeded allowed attempts."""
        now = time.time()
        r = _get_redis_client()

        if r is not None:
            try:
                r_keys = self._redis_keys(key)

                # 1. Check active lockout
                locked_val = r.get(r_keys["locked"])
                if locked_val:
                    try:
                        locked_until = float(locked_val)
                        if locked_until > now:
                            return True
                    except ValueError:
                        pass

                # 2. Check attempts in sliding window
                cutoff = now - self.window_seconds
                r.zremrangebyscore(r_keys["attempts"], "-inf", cutoff)
                valid_count = r.zcard(r_keys["attempts"])

                if valid_count >= self.max_attempts:
                    consec_val = r.get(r_keys["consecutive"])
                    consecutive = int(consec_val) if consec_val and consec_val.isdigit() else 0
                    lockout_duration = min(
                        self.base_lockout_seconds * (2 ** consecutive),
                        self.max_lockout_seconds,
                    )
                    r.set(r_keys["locked"], str(now + lockout_duration), ex=int(lockout_duration) + 1)
                    r.set(r_keys["consecutive"], str(consecutive + 1), ex=self.max_lockout_seconds * 2)
                    return True

                return False
            except Exception as exc:
                logger.debug("Redis rate limiting error, falling back to local memory: %s", exc)

        # Fallback to local thread-safe in-memory sliding window
        with self._lock:
            locked_until = self._locked_until.get(key, 0.0)
            if locked_until > now:
                return True
            elif key in self._locked_until:
                self._locked_until.pop(key, None)

            cutoff = now - self.window_seconds
            valid_attempts = [ts for ts in self._failures[key] if ts > cutoff]
            self._failures[key] = valid_attempts

            if len(valid_attempts) >= self.max_attempts:
                consecutive = self._consecutive_lockouts[key]
                lockout_duration = min(
                    self.base_lockout_seconds * (2 ** consecutive),
                    self.max_lockout_seconds,
                )
                self._locked_until[key] = now + lockout_duration
                self._consecutive_lockouts[key] = consecutive + 1
                return True

            return False

    def get_remaining_lockout_seconds(self, key: str) -> int:
        """Get seconds remaining on active lockout, or 0 if not locked."""
        now = time.time()
        r = _get_redis_client()

        if r is not None:
            try:
                r_keys = self._redis_keys(key)
                locked_val = r.get(r_keys["locked"])
                if locked_val:
                    rem = float(locked_val) - now
                    if rem > 0:
                        return int(rem)
            except Exception as exc:
                logger.debug("Redis remaining lockout lookup error: %s", exc)

        with self._lock:
            locked_until = self._locked_until.get(key, 0.0)
            if locked_until > now:
                return int(locked_until - now)
            return 0

    def record_failure(self, key: str) -> None:
        """Record a failed attempt."""
        now = time.time()
        r = _get_redis_client()

        if r is not None:
            try:
                r_keys = self._redis_keys(key)
                member = f"{now}:{secrets.token_hex(4)}"
                p = r.pipeline()
                p.zadd(r_keys["attempts"], {member: now})
                p.expire(r_keys["attempts"], self.window_seconds * 2)
                p.execute()
            except Exception as exc:
                logger.debug("Redis record failure error: %s", exc)

        with self._lock:
            self._failures[key].append(now)

    def record_success(self, key: str) -> None:
        """Clear failed attempts and lockout state upon successful operation."""
        r = _get_redis_client()
        if r is not None:
            try:
                r_keys = self._redis_keys(key)
                r.delete(r_keys["attempts"], r_keys["locked"], r_keys["consecutive"])
            except Exception as exc:
                logger.debug("Redis record success error: %s", exc)

        with self._lock:
            self._failures.pop(key, None)
            self._locked_until.pop(key, None)
            self._consecutive_lockouts.pop(key, None)

    def reset(self) -> None:
        """Reset all rate limiter state (useful for tests)."""
        r = _get_redis_client()
        if r is not None:
            try:
                keys = r.keys(f"ratelimit:{self.domain}:*")
                if keys:
                    r.delete(*keys)
            except Exception:
                pass

        with self._lock:
            self._failures.clear()
            self._locked_until.clear()
            self._consecutive_lockouts.clear()

    clear = reset


# Global dedicated rate limiters for distinct sensitive domains
login_rate_limiter = SlidingWindowRateLimiter(
    domain="login",
    max_attempts=5,
    window_seconds=60,
    base_lockout_seconds=60,
)
password_reset_limiter = SlidingWindowRateLimiter(
    domain="pwd_reset",
    max_attempts=3,
    window_seconds=900,
    base_lockout_seconds=900,
)
mfa_rate_limiter = SlidingWindowRateLimiter(
    domain="mfa",
    max_attempts=5,
    window_seconds=300,
    base_lockout_seconds=300,
)
soar_execution_limiter = SlidingWindowRateLimiter(
    domain="soar",
    max_attempts=30,
    window_seconds=60,
    base_lockout_seconds=60,
)
