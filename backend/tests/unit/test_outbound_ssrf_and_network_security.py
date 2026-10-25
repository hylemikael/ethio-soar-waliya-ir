"""Unit tests for SSRF prevention, URL validation, and outbound network security."""

import ipaddress
import pytest
import socket
from unittest.mock import patch

from waliya.integrations.network_security import (
    CLOUD_METADATA_IPS,
    SSRFValidationError,
    create_safe_http_client,
    is_ip_prohibited,
    resolve_hostname_ips,
    validate_destination_url,
)


def test_prohibited_ip_ranges():
    """Verify classification of loopback, private, link-local, multicast, and metadata IPs."""
    # Loopback
    assert is_ip_prohibited(ipaddress.ip_address("127.0.0.1"), allow_local_for_testing=False) is True
    assert is_ip_prohibited(ipaddress.ip_address("127.100.200.1"), allow_local_for_testing=False) is True
    assert is_ip_prohibited(ipaddress.ip_address("::1"), allow_local_for_testing=False) is True

    # Cloud metadata (ALWAYS prohibited even in test mode)
    assert is_ip_prohibited(ipaddress.ip_address("169.254.169.254"), allow_local_for_testing=True) is True
    assert is_ip_prohibited(ipaddress.ip_address("169.254.169.254"), allow_local_for_testing=False) is True
    assert is_ip_prohibited(ipaddress.ip_address("fd00:ec2::254"), allow_local_for_testing=True) is True

    # Private subnets
    assert is_ip_prohibited(ipaddress.ip_address("10.0.0.1"), allow_local_for_testing=False) is True
    assert is_ip_prohibited(ipaddress.ip_address("172.16.0.1"), allow_local_for_testing=False) is True
    assert is_ip_prohibited(ipaddress.ip_address("192.168.1.1"), allow_local_for_testing=False) is True
    assert is_ip_prohibited(ipaddress.ip_address("fc00::1"), allow_local_for_testing=False) is True

    # Multicast & Unspecified
    assert is_ip_prohibited(ipaddress.ip_address("224.0.0.1"), allow_local_for_testing=False) is True
    assert is_ip_prohibited(ipaddress.ip_address("0.0.0.0"), allow_local_for_testing=False) is True

    # Public internet IP should NOT be prohibited
    assert is_ip_prohibited(ipaddress.ip_address("8.8.8.8"), allow_local_for_testing=False) is False
    assert is_ip_prohibited(ipaddress.ip_address("93.184.216.34"), allow_local_for_testing=False) is False


def test_allow_local_for_testing_flag():
    """Verify loopback is tolerated only when allow_local_for_testing is True, but metadata is still blocked."""
    assert is_ip_prohibited(ipaddress.ip_address("127.0.0.1"), allow_local_for_testing=True) is False
    assert is_ip_prohibited(ipaddress.ip_address("192.168.1.50"), allow_local_for_testing=True) is False
    # Cloud metadata MUST remain prohibited
    assert is_ip_prohibited(ipaddress.ip_address("169.254.169.254"), allow_local_for_testing=True) is True


def test_url_scheme_validation():
    """Verify that insecure schemes and invalid URL formats are rejected."""
    # Plain HTTP rejected in production
    with pytest.raises(SSRFValidationError, match="Insecure scheme"):
        validate_destination_url("http://webhook.example.com/alerts", allow_local_for_testing=False)

    # Disallowed protocols
    with pytest.raises(SSRFValidationError):
        validate_destination_url("ftp://webhook.example.com/alerts", allow_local_for_testing=True)
    with pytest.raises(SSRFValidationError):
        validate_destination_url("file:///etc/passwd", allow_local_for_testing=True)
    with pytest.raises(SSRFValidationError):
        validate_destination_url("gopher://webhook.example.com", allow_local_for_testing=True)


def test_embedded_credentials_rejected():
    """Verify embedded user:pass in destination URLs are blocked."""
    with pytest.raises(SSRFValidationError, match="Embedded credentials"):
        validate_destination_url("https://admin:secret@webhook.example.com/hook")


def test_whitespace_and_empty_urls_rejected():
    """Verify URLs with leading/trailing whitespace or empty strings fail safely."""
    with pytest.raises(SSRFValidationError, match="non-empty string"):
        validate_destination_url("")
    with pytest.raises(SSRFValidationError, match="whitespace"):
        validate_destination_url("  https://webhook.example.com/hook  ")


def test_cloud_metadata_hostnames_rejected():
    """Verify prohibited metadata hostnames are blocked prior to DNS."""
    with pytest.raises(SSRFValidationError, match="cloud metadata hostname"):
        validate_destination_url("https://metadata.google.internal/computeMetadata/v1")
    with pytest.raises(SSRFValidationError, match="cloud metadata hostname"):
        validate_destination_url("https://instance-data/latest/meta-data")


def test_dns_resolution_failure_fails_safely():
    """Verify unresolvable hostnames fail safely with SSRFValidationError."""
    with patch("socket.getaddrinfo", side_effect=socket.gaierror("Name or service not known")):
        with pytest.raises(SSRFValidationError, match="could not be resolved"):
            validate_destination_url("https://nonexistent-domain-for-waliya-tests-999.org/hook")


def test_dns_rebinding_to_prohibited_ip_blocked():
    """Verify hostnames resolving to private or loopback IPs are blocked."""
    # Mock DNS resolving to loopback
    mock_addrinfo = [(None, None, None, None, ("127.0.0.1", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with pytest.raises(SSRFValidationError, match="resolved to prohibited IP"):
            validate_destination_url("https://attacker-rebound.com/hook", allow_local_for_testing=False)

    # Mock DNS resolving to cloud metadata IP
    mock_metadata = [(None, None, None, None, ("169.254.169.254", 443))]
    with patch("socket.getaddrinfo", return_value=mock_metadata):
        with pytest.raises(SSRFValidationError, match="resolved to prohibited IP"):
            validate_destination_url("https://attacker-metadata.com/hook", allow_local_for_testing=True)


def test_valid_public_destination_url_passes():
    """Verify legitimate public HTTPS destination passes validation."""
    mock_public = [(None, None, None, None, ("93.184.216.34", 443))]
    with patch("socket.getaddrinfo", return_value=mock_public):
        # Should execute without raising
        validate_destination_url("https://example.com/api/security/events", allow_local_for_testing=False)


def test_safe_http_client_redirect_protection():
    """Verify safe HTTP client has automatic redirects strictly disabled."""
    client = create_safe_http_client()
    assert client.follow_redirects is False
    assert client.timeout.read == 10.0
    assert client.timeout.connect == 5.0
