"""Normalization and validation utilities for threat intelligence indicators."""

import ipaddress
import re
from typing import Optional, Tuple
import urllib.parse


# Regular expression for validating individual DNS domain labels
DOMAIN_LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
SHA256_HEX_REGEX = re.compile(r"^[a-f0-9]{64}$")


class IndicatorValidationError(ValueError):
    """Raised when an indicator value fails semantic validation or normalization."""


def normalize_ipv4(value: str) -> str:
    """Normalize and validate an IPv4 address.

    Returns canonical dotted-decimal representation.
    """
    clean_val = value.strip()
    try:
        ip = ipaddress.IPv4Address(clean_val)
        return str(ip)
    except Exception as exc:
        raise IndicatorValidationError(f"Invalid IPv4 address '{clean_val}': {exc}") from exc


def normalize_ipv6(value: str) -> str:
    """Normalize and validate an IPv6 address.

    Returns RFC 5952 lowercase compressed canonical representation.
    """
    clean_val = value.strip()
    try:
        ip = ipaddress.IPv6Address(clean_val)
        return ip.compressed.lower()
    except Exception as exc:
        raise IndicatorValidationError(f"Invalid IPv6 address '{clean_val}': {exc}") from exc


def normalize_domain(value: str) -> str:
    """Normalize and validate a domain name.

    Returns lowercase canonical domain name without trailing dot.
    """
    clean_val = value.strip().lower().rstrip(".")
    if not clean_val:
        raise IndicatorValidationError("Domain name cannot be empty")

    if len(clean_val) > 253:
        raise IndicatorValidationError(f"Domain name exceeds 253 characters ({len(clean_val)})")

    # Reject URLs passed as domains
    if "://" in clean_val or "/" in clean_val:
        raise IndicatorValidationError(f"Value '{clean_val}' appears to be a URL, not a bare domain name")

    # Reject ports passed as domains
    if ":" in clean_val:
        raise IndicatorValidationError(f"Domain name '{clean_val}' must not include a port specification")

    labels = clean_val.split(".")
    if len(labels) < 2:
        raise IndicatorValidationError(f"Domain name '{clean_val}' must contain at least two labels (e.g. 'domain.com')")

    for label in labels:
        if not label:
            raise IndicatorValidationError(f"Domain name '{clean_val}' contains empty labels")
        if len(label) > 63:
            raise IndicatorValidationError(f"Domain label '{label}' exceeds 63 characters")
        if not DOMAIN_LABEL_REGEX.match(label):
            raise IndicatorValidationError(f"Domain label '{label}' contains invalid characters or leading/trailing hyphens")

    # Top-level domain must not be purely numeric
    if labels[-1].isdigit():
        raise IndicatorValidationError(f"Top-level domain '{labels[-1]}' cannot be purely numeric")

    return clean_val


def normalize_sha256(value: str) -> str:
    """Normalize and validate a SHA-256 file hash.

    Returns 64-character lowercase hexadecimal string.
    """
    clean_val = value.strip().lower()
    if not SHA256_HEX_REGEX.match(clean_val):
        raise IndicatorValidationError(
            f"Invalid SHA-256 hash '{clean_val}'. Must be exactly 64 hexadecimal characters"
        )
    return clean_val


def normalize_url(value: str) -> str:
    """Normalize and validate an HTTP/HTTPS URL observable.

    Returns canonical URL with lowercase scheme and host.
    """
    clean_val = value.strip()
    if not clean_val:
        raise IndicatorValidationError("URL cannot be empty")

    try:
        parsed = urllib.parse.urlparse(clean_val)
    except Exception as exc:
        raise IndicatorValidationError(f"Failed parsing URL '{clean_val}': {exc}") from exc

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise IndicatorValidationError(
            f"URL '{clean_val}' has unsupported scheme '{parsed.scheme}'. Only 'http' and 'https' are supported"
        )

    netloc = parsed.netloc.lower()
    if not netloc:
        raise IndicatorValidationError(f"URL '{clean_val}' is missing a destination host")

    path = parsed.path or "/"
    canonical_url = urllib.parse.urlunparse((
        scheme,
        netloc,
        path,
        parsed.params,
        parsed.query,
        parsed.fragment,
    ))
    return canonical_url


def detect_indicator_type(value: str) -> str:
    """Auto-detect the indicator type of an observable string."""
    clean_val = value.strip()

    # 1. SHA-256
    if len(clean_val) == 64 and SHA256_HEX_REGEX.match(clean_val.lower()):
        return "SHA256"

    # 2. URL
    if clean_val.lower().startswith(("http://", "https://")):
        return "URL"

    # 3. IPv4
    try:
        ipaddress.IPv4Address(clean_val)
        return "IPV4"
    except Exception:
        pass

    # 4. IPv6
    try:
        ipaddress.IPv6Address(clean_val)
        return "IPV6"
    except Exception:
        pass

    # 5. Domain
    try:
        normalize_domain(clean_val)
        return "DOMAIN"
    except Exception:
        pass

    raise IndicatorValidationError(f"Cannot auto-detect indicator type for value '{clean_val}'")


def normalize_indicator(indicator_type: str, value: str) -> Tuple[str, str]:
    """Normalize and validate an indicator based on its specified type.

    Accepts indicator_type case-insensitively and returns canonical
    (normalized_type, normalized_value).
    """
    t = indicator_type.strip().upper()

    # Map legacy aliases
    if t == "IP":
        # Check if IPv4 or IPv6
        try:
            ipaddress.IPv4Address(value.strip())
            t = "IPV4"
        except Exception:
            try:
                ipaddress.IPv6Address(value.strip())
                t = "IPV6"
            except Exception:
                raise IndicatorValidationError(f"Value '{value}' is not a valid IPv4 or IPv6 address")

    elif t in ("FILE_HASH_SHA256", "HASH"):
        t = "SHA256"

    if t == "IPV4":
        return "IPV4", normalize_ipv4(value)
    elif t == "IPV6":
        return "IPV6", normalize_ipv6(value)
    elif t == "DOMAIN":
        return "DOMAIN", normalize_domain(value)
    elif t == "SHA256":
        return "SHA256", normalize_sha256(value)
    elif t == "URL":
        return "URL", normalize_url(value)
    else:
        raise IndicatorValidationError(
            f"Unsupported indicator type '{indicator_type}'. Supported types: IPV4, IPV6, DOMAIN, SHA256, URL"
        )
