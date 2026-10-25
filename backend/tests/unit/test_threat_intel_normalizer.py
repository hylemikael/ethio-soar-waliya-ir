"""Unit tests for threat intelligence indicator normalization and validation."""

import pytest

from waliya.threat_intel.normalizer import (
    IndicatorValidationError,
    detect_indicator_type,
    normalize_domain,
    normalize_indicator,
    normalize_ipv4,
    normalize_ipv6,
    normalize_sha256,
    normalize_url,
)


def test_normalize_ipv4_valid():
    assert normalize_ipv4("192.168.1.1") == "192.168.1.1"
    assert normalize_ipv4("  10.0.0.1  ") == "10.0.0.1"
    assert normalize_ipv4("198.51.100.25") == "198.51.100.25"


def test_normalize_ipv4_invalid():
    with pytest.raises(IndicatorValidationError):
        normalize_ipv4("999.999.999.999")
    with pytest.raises(IndicatorValidationError):
        normalize_ipv4("192.168.1")
    with pytest.raises(IndicatorValidationError):
        normalize_ipv4("not-an-ip")
    with pytest.raises(IndicatorValidationError):
        normalize_ipv4("")


def test_normalize_ipv6_valid():
    # Expands and compresses to lowercase RFC 5952
    assert normalize_ipv6("2001:0DB8:0000:0000:0000:0000:0000:0001") == "2001:db8::1"
    assert normalize_ipv6("  ::1  ") == "::1"
    assert normalize_ipv6("fe80::1") == "fe80::1"


def test_normalize_ipv6_invalid():
    with pytest.raises(IndicatorValidationError):
        normalize_ipv6("2001:xyz::1")
    with pytest.raises(IndicatorValidationError):
        normalize_ipv6("::1::1")
    with pytest.raises(IndicatorValidationError):
        normalize_ipv6("")


def test_normalize_domain_valid():
    assert normalize_domain("MALICIOUS-C2.EXAMPLE.COM.") == "malicious-c2.example.com"
    assert normalize_domain("  sub.evil-domain.org  ") == "sub.evil-domain.org"
    assert normalize_domain("x.co") == "x.co"


def test_normalize_domain_invalid():
    # URL passed as domain
    with pytest.raises(IndicatorValidationError):
        normalize_domain("http://evil.com")
    # Port passed as domain
    with pytest.raises(IndicatorValidationError):
        normalize_domain("evil.com:8080")
    # Single label
    with pytest.raises(IndicatorValidationError):
        normalize_domain("localhost")
    # Trailing hyphen
    with pytest.raises(IndicatorValidationError):
        normalize_domain("evil-.com")
    # Numeric TLD
    with pytest.raises(IndicatorValidationError):
        normalize_domain("evil.123")
    # Empty
    with pytest.raises(IndicatorValidationError):
        normalize_domain("")


def test_normalize_sha256_valid():
    clean_hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert normalize_sha256(clean_hash.upper()) == clean_hash
    assert normalize_sha256(f"  {clean_hash}  ") == clean_hash


def test_normalize_sha256_invalid():
    # 63 characters
    with pytest.raises(IndicatorValidationError):
        normalize_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85")
    # 65 characters
    with pytest.raises(IndicatorValidationError):
        normalize_sha256("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b8555")
    # Non-hex characters
    with pytest.raises(IndicatorValidationError):
        normalize_sha256("g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")


def test_normalize_url_valid():
    norm = normalize_url("HTTP://C2.EXAMPLE.COM:8080/download/payload.sh?v=1#tag")
    assert norm == "http://c2.example.com:8080/download/payload.sh?v=1#tag"

    norm_bare = normalize_url("https://malicious.org")
    assert norm_bare == "https://malicious.org/"


def test_normalize_url_invalid():
    # Unsupported scheme
    with pytest.raises(IndicatorValidationError):
        normalize_url("ftp://files.example.com/malware.exe")
    # Missing host
    with pytest.raises(IndicatorValidationError):
        normalize_url("http:///path")
    # Missing scheme
    with pytest.raises(IndicatorValidationError):
        normalize_url("example.com/payload")


def test_detect_indicator_type():
    assert detect_indicator_type("198.51.100.1") == "IPV4"
    assert detect_indicator_type("2001:db8::1") == "IPV6"
    assert detect_indicator_type("bad-c2.example.com") == "DOMAIN"
    assert detect_indicator_type("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") == "SHA256"
    assert detect_indicator_type("http://bad-c2.example.com/bin") == "URL"

    with pytest.raises(IndicatorValidationError):
        detect_indicator_type("not an indicator @#$%")


def test_normalize_indicator_dispatch():
    t, v = normalize_indicator("ipv4", " 192.168.1.5 ")
    assert t == "IPV4" and v == "192.168.1.5"

    t, v = normalize_indicator("IP", "2001:0db8::1")
    assert t == "IPV6" and v == "2001:db8::1"

    t, v = normalize_indicator("FILE_HASH_SHA256", "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")
    assert t == "SHA256" and v == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    with pytest.raises(IndicatorValidationError):
        normalize_indicator("UNKNOWN_TYPE", "value")
