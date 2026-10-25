"""Base provider adapter and secure transport specifications for threat intelligence feeds."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging
import re
from typing import Any, Dict, List, Optional, Set
import urllib.parse

import httpx
from pydantic import BaseModel, Field

logger = logging.getLogger("waliya.threat_intel.connectors.base")


class FeedFetchError(Exception):
    """Base exception for threat feed retrieval and parsing errors."""


class FeedAuthenticationError(FeedFetchError):
    """Raised when provider authentication fails or credentials are missing."""


class FeedRateLimitError(FeedFetchError):
    """Raised when provider rate limits are encountered (HTTP 429)."""


class FeedSecurityError(FeedFetchError):
    """Raised when transport security invariants are violated (untrusted host, unsafe redirect, oversized)."""


class RawIndicatorRecord(BaseModel):
    """Validated raw indicator extracted from a threat feed before normalization and storage."""
    value: str
    indicator_type: Optional[str] = None
    source_id: Optional[str] = None
    confidence: int = 50
    confidence_is_policy_derived: bool = False
    severity: str = "MEDIUM"
    threat_category: Optional[str] = None
    threat_actor: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    description: Optional[str] = None
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    is_active: bool = True
    raw_data: Optional[Dict[str, Any]] = None


class FeedFetchResult(BaseModel):
    """Container for records and execution diagnostics returned by a connector."""
    records: List[RawIndicatorRecord] = Field(default_factory=list)
    fetched_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)
    diagnostics: Dict[str, Any] = Field(default_factory=dict)


class BaseFeedConnector(ABC):
    """Abstract base class for secure, read-only threat intelligence feed connectors."""

    feed_id: str
    provider: str
    allowed_hosts: Set[str]
    max_response_bytes: int = 10 * 1024 * 1024  # 10 MB strict safety ceiling

    def __init__(self, timeout_seconds: float = 30.0, max_records: int = 1000):
        self.timeout_seconds = timeout_seconds
        self.max_records = max_records

    def validate_url(self, url: str) -> urllib.parse.ParseResult:
        """Enforce strict transport safety: HTTPS only and host within allowed provider hosts."""
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme.lower() != "https":
            raise FeedSecurityError(f"Insecure scheme '{parsed.scheme}'. Only HTTPS is permitted for threat feeds.")

        host = parsed.hostname.lower() if parsed.hostname else ""
        if not host:
            raise FeedSecurityError(f"Target URL '{url}' lacks a valid hostname.")

        if host not in self.allowed_hosts:
            raise FeedSecurityError(
                f"Host '{host}' is not in the explicit allowlist for feed '{self.feed_id}': {sorted(list(self.allowed_hosts))}"
            )

        return parsed

    def sanitize_string(self, text: str, secret_to_redact: Optional[str] = None) -> str:
        """Redact secrets and sensitive tokens from log messages and diagnostics."""
        if not text:
            return ""
        sanitized = text
        if secret_to_redact and len(secret_to_redact) > 3:
            sanitized = sanitized.replace(secret_to_redact, "[REDACTED_API_KEY]")
        # Common pattern redactor for Auth-Key or token in headers or strings
        sanitized = re.sub(r"(?i)(auth[-_]?key|api[-_]?key|token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{8,})['\"]?", r"\1: [REDACTED]", sanitized)
        return sanitized

    def parse_datetime(self, val: Any) -> Optional[datetime]:
        """Safely parse various provider datetime formats to UTC datetime."""
        if not val:
            return None
        if isinstance(val, datetime):
            return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
        if not isinstance(val, str):
            return None

        clean_str = val.strip().replace(" UTC", "").replace("Z", "+00:00")
        for fmt in (
            "%Y-%m-%d %H:%M:%S%z",
            "%Y-%m-%d %H:%M:%S",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d",
        ):
            try:
                dt = datetime.strptime(clean_str, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue

        try:
            dt = datetime.fromisoformat(clean_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except Exception:
            return None

    async def execute_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        json_body: Optional[Dict[str, Any]] = None,
        api_key_for_redaction: Optional[str] = None,
    ) -> httpx.Response:
        """Execute HTTPS request with certificate verification, size limits, and safe redirect validation."""
        self.validate_url(url)

        async with httpx.AsyncClient(verify=True, timeout=self.timeout_seconds, follow_redirects=False) as client:
            current_url = url
            retries = 0
            max_retries = 2

            while retries <= max_retries:
                try:
                    logger.debug("Executing TI fetch %s -> %s", method, self.sanitize_string(current_url, api_key_for_redaction))
                    response = await client.request(
                        method=method,
                        url=current_url,
                        headers=headers,
                        json=json_body if method.upper() == "POST" else None,
                    )

                    # Handle safe redirects manually to verify target host
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            raise FeedSecurityError("Redirect received without Location header")
                        redirect_url = urllib.parse.urljoin(current_url, location)
                        self.validate_url(redirect_url)  # Ensures target is also in allowed_hosts!
                        current_url = redirect_url
                        retries += 1
                        continue

                    # Rate limit handling (HTTP 429)
                    if response.status_code == 429:
                        if retries < max_retries:
                            retries += 1
                            logger.warning("Rate limited by %s (HTTP 429), retry %d/%d", self.feed_id, retries, max_retries)
                            continue
                        raise FeedRateLimitError(f"Rate limit exceeded (HTTP 429) on provider '{self.provider}'")

                    # Authentication failure
                    if response.status_code in (401, 403):
                        raise FeedAuthenticationError(
                            f"Authentication failed on provider '{self.provider}' (HTTP {response.status_code}). Verify configured API key."
                        )

                    # Enforce strict response size limit
                    content_length = response.headers.get("content-length")
                    if content_length and int(content_length) > self.max_response_bytes:
                        raise FeedSecurityError(
                            f"Response size {content_length} bytes exceeds maximum allowed limit {self.max_response_bytes} bytes."
                        )

                    response.raise_for_status()

                    # Check actual content length
                    if len(response.content) > self.max_response_bytes:
                        raise FeedSecurityError(
                            f"Response payload ({len(response.content)} bytes) exceeds maximum limit {self.max_response_bytes} bytes."
                        )

                    return response

                except (FeedSecurityError, FeedAuthenticationError, FeedRateLimitError):
                    raise
                except httpx.HTTPStatusError as exc:
                    sanitized_msg = self.sanitize_string(str(exc), api_key_for_redaction)
                    raise FeedFetchError(f"HTTP error from {self.provider}: {sanitized_msg}") from exc
                except httpx.RequestError as exc:
                    if retries < max_retries:
                        retries += 1
                        continue
                    sanitized_msg = self.sanitize_string(str(exc), api_key_for_redaction)
                    raise FeedFetchError(f"Network transport error connecting to {self.provider}: {sanitized_msg}") from exc

            raise FeedFetchError(f"Exhausted {max_retries} retries connecting to {self.provider}")

    @abstractmethod
    async def fetch_indicators(
        self,
        config_options: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> FeedFetchResult:
        """Fetch and parse indicators from the provider feed."""
