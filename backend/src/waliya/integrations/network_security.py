"""SSRF and Outbound Network Security validation for external integration webhooks."""

import ipaddress
import logging
import socket
from typing import List, Optional, Set
from urllib.parse import urlparse

import httpx

logger = logging.getLogger("waliya.integrations.network_security")

# Bounded timeouts for safe outbound webhook dispatch
DEFAULT_CONNECT_TIMEOUT_SECONDS = 5.0
DEFAULT_READ_TIMEOUT_SECONDS = 10.0
MAX_RESPONSE_BYTES = 16384  # 16 KB upper bound on external responses

# Explicitly blocked cloud metadata addresses
CLOUD_METADATA_IPS: Set[str] = {
    "169.254.169.254",
    "169.254.170.2",
    "fd00:ec2::254",
}


class SSRFValidationError(ValueError):
    """Raised when an outbound destination URL violates SSRF or network egress policies."""
    pass


def is_ip_prohibited(
    ip: ipaddress.IPv4Address | ipaddress.IPv6Address,
    allow_local_for_testing: bool = False,
) -> bool:
    """Check whether an IP address belongs to prohibited, internal, or cloud metadata ranges.

    Prohibited ranges include:
    - Loopback (127.0.0.0/8, ::1)
    - Link-local & cloud metadata (169.254.0.0/16, fe80::/10)
    - Private subnets (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7)
    - Multicast (224.0.0.0/4, ff00::/8)
    - Unspecified / Broadcast / Reserved (0.0.0.0/8, 255.255.255.255, 240.0.0.0/4, ::)
    """
    ip_str = str(ip)

    # Cloud metadata is ALWAYS unconditionally prohibited
    if ip_str in CLOUD_METADATA_IPS:
        return True

    # Link-local addresses are always prohibited
    if ip.is_link_local:
        return True

    # Multicast, reserved, and unspecified are always prohibited
    if ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        return True

    # If local test destinations are permitted, allow loopback and private subnets
    if allow_local_for_testing:
        return False

    # Production checks: loopback and private ranges strictly forbidden
    if ip.is_loopback or ip.is_private:
        return True

    return False


def resolve_hostname_ips(hostname: str, port: int = 443) -> List[ipaddress.IPv4Address | ipaddress.IPv6Address]:
    """Resolve destination hostname to all candidate IP addresses via socket.getaddrinfo.

    Raises:
        SSRFValidationError: If DNS resolution fails.
    """
    try:
        addr_info = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFValidationError(f"Destination hostname '{hostname}' could not be resolved: {exc}") from exc
    except Exception as exc:
        raise SSRFValidationError(f"Unexpected error resolving hostname '{hostname}': {exc}") from exc

    resolved_ips = []
    for entry in addr_info:
        sockaddr = entry[4]
        ip_str = sockaddr[0]
        try:
            resolved_ips.append(ipaddress.ip_address(ip_str))
        except ValueError:
            continue

    if not resolved_ips:
        raise SSRFValidationError(f"No valid IP addresses resolved for hostname '{hostname}'")

    return resolved_ips


def validate_destination_url(
    url: str,
    allow_local_for_testing: bool = False,
) -> None:
    """Strictly validate an outbound webhook destination URL against SSRF and network security rules.

    Validation Invariants:
    1. Scheme must be HTTPS (or HTTP strictly when allow_local_for_testing is True).
    2. Embedded credentials (user:pass) are rejected.
    3. Hostname must be present and valid.
    4. Port must be valid (1..65535).
    5. Resolves DNS hostname to IPs; all resolved addresses must pass prohibited range checks.
    6. Cloud metadata IPs (169.254.169.254) are rejected unconditionally.
    """
    if not url or not isinstance(url, str):
        raise SSRFValidationError("Destination URL must be a non-empty string")

    # Reject URLs with leading/trailing whitespace tricks
    stripped_url = url.strip()
    if stripped_url != url:
        raise SSRFValidationError("Destination URL cannot contain leading or trailing whitespace")

    try:
        parsed = urlparse(stripped_url)
    except Exception as exc:
        raise SSRFValidationError(f"Malformed URL: {exc}") from exc

    # Enforce allowed schemes
    if allow_local_for_testing:
        if parsed.scheme.lower() not in ("https", "http"):
            raise SSRFValidationError(f"Unsupported scheme '{parsed.scheme}'. Only HTTPS and HTTP (in test mode) are permitted.")
    else:
        if parsed.scheme.lower() != "https":
            raise SSRFValidationError(f"Insecure scheme '{parsed.scheme}'. Production outbound webhooks require HTTPS.")

    # Reject embedded user info
    if parsed.username or parsed.password:
        raise SSRFValidationError("Embedded credentials (username/password) in destination URLs are prohibited")

    hostname = parsed.hostname
    if not hostname:
        raise SSRFValidationError("Destination URL missing valid hostname")

    # Reject special dangerous hostnames
    lowered_host = hostname.lower()
    if lowered_host in ("metadata.google.internal", "instance-data", "metadata"):
        raise SSRFValidationError(f"Prohibited cloud metadata hostname '{hostname}'")

    # Validate port
    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    if not (1 <= port <= 65535):
        raise SSRFValidationError(f"Invalid destination port: {port}")

    # Check direct IP literals first
    try:
        direct_ip = ipaddress.ip_address(hostname)
        if is_ip_prohibited(direct_ip, allow_local_for_testing=allow_local_for_testing):
            raise SSRFValidationError(f"Destination IP '{direct_ip}' is in a prohibited or private range")
        return
    except ValueError:
        # Not a raw IP literal; proceed to DNS resolution
        pass

    # Resolve hostname to IP addresses
    resolved_ips = resolve_hostname_ips(hostname, port)
    for ip in resolved_ips:
        if is_ip_prohibited(ip, allow_local_for_testing=allow_local_for_testing):
            raise SSRFValidationError(
                f"Destination hostname '{hostname}' resolved to prohibited IP address '{ip}'"
            )


def create_safe_http_client(
    timeout_seconds: float = DEFAULT_READ_TIMEOUT_SECONDS,
    transport: Optional[httpx.AsyncBaseTransport] = None,
) -> httpx.AsyncClient:
    """Create an httpx AsyncClient configured for safe outbound webhook delivery.

    Guarantees:
    - follow_redirects=False (Strictly disables automatic unvalidated HTTP redirects)
    - Bounded connect and read timeouts
    - Reusable connection pooling with bounded connection counts
    """
    timeout = httpx.Timeout(
        timeout=timeout_seconds,
        connect=DEFAULT_CONNECT_TIMEOUT_SECONDS,
    )
    return httpx.AsyncClient(
        follow_redirects=False,
        timeout=timeout,
        transport=transport,
        headers={"User-Agent": "Waliya-IR-Notifier/2.0"},
    )
