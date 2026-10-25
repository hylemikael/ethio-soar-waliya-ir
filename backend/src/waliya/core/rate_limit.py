"""In-memory sliding window rate limiter with progressive delay for security-critical endpoints."""

import time
from collections import defaultdict
from typing import Dict, List, Optional


class SlidingWindowRateLimiter:
    """Sliding-window rate limiter with progressive backoff to prevent brute-force and credential stuffing."""

    def __init__(
        self,
        max_attempts: int = 5,
        window_seconds: int = 60,
        base_lockout_seconds: int = 60,
        max_lockout_seconds: int = 3600,
    ):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.base_lockout_seconds = base_lockout_seconds
        self.max_lockout_seconds = max_lockout_seconds
        self._failures: Dict[str, List[float]] = defaultdict(list)
        self._locked_until: Dict[str, float] = {}
        self._consecutive_lockouts: Dict[str, int] = defaultdict(int)

    def is_rate_limited(self, key: str) -> bool:
        """Check if an identity key is currently locked out or has exceeded allowed attempts."""
        now = time.time()

        # Check explicit lockout lock
        locked_until = self._locked_until.get(key, 0.0)
        if locked_until > now:
            return True
        elif key in self._locked_until:
            self._locked_until.pop(key, None)

        # Check attempts in sliding window
        cutoff = now - self.window_seconds
        valid_attempts = [ts for ts in self._failures[key] if ts > cutoff]
        self._failures[key] = valid_attempts

        if len(valid_attempts) >= self.max_attempts:
            # Trigger progressive lockout
            consecutive = self._consecutive_lockouts[key]
            # Exponential backoff: base * 2^consecutive capped at max_lockout_seconds
            lockout_duration = min(self.base_lockout_seconds * (2 ** consecutive), self.max_lockout_seconds)
            self._locked_until[key] = now + lockout_duration
            self._consecutive_lockouts[key] = consecutive + 1
            return True

        return False

    def get_remaining_lockout_seconds(self, key: str) -> int:
        """Get seconds remaining on active lockout, or 0 if not locked."""
        now = time.time()
        locked_until = self._locked_until.get(key, 0.0)
        if locked_until > now:
            return int(locked_until - now)
        return 0

    def record_failure(self, key: str) -> None:
        """Record a failed attempt."""
        now = time.time()
        self._failures[key].append(now)

    def record_success(self, key: str) -> None:
        """Clear failed attempts and lockout state upon successful operation."""
        self._failures.pop(key, None)
        self._locked_until.pop(key, None)
        self._consecutive_lockouts.pop(key, None)

    def reset(self) -> None:
        """Reset all rate limiter state (useful for tests)."""
        self._failures.clear()
        self._locked_until.clear()
        self._consecutive_lockouts.clear()

    clear = reset


# Global dedicated rate limiters for distinct sensitive domains
login_rate_limiter = SlidingWindowRateLimiter(max_attempts=5, window_seconds=60, base_lockout_seconds=60)
password_reset_limiter = SlidingWindowRateLimiter(max_attempts=3, window_seconds=900, base_lockout_seconds=900)
mfa_rate_limiter = SlidingWindowRateLimiter(max_attempts=5, window_seconds=300, base_lockout_seconds=300)
soar_execution_limiter = SlidingWindowRateLimiter(max_attempts=30, window_seconds=60, base_lockout_seconds=60)
