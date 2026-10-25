"""Unit tests for official ThreatFox connector."""

import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from waliya.threat_intel.connectors.base import (
    FeedAuthenticationError,
    FeedFetchError,
    FeedRateLimitError,
)
from waliya.threat_intel.connectors.threatfox import ThreatFoxConnector


@pytest.fixture
def threatfox_connector():
    return ThreatFoxConnector(timeout_seconds=5.0, max_records=50)


SAMPLE_THREATFOX_RESPONSE = {
    "query_status": "ok",
    "data": [
        {
            "id": 101,
            "ioc": "198.51.100.22:8080",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Botnet Command and Control Server",
            "ioc_type": "ip:port",
            "malware": "win.cobalt_strike",
            "malware_printable": "Cobalt Strike",
            "confidence_level": 85,
            "first_seen_utc": "2026-10-20 12:00:00",
            "last_seen_utc": "2026-10-22 15:30:00",
            "reporter": "abuse_ch",
            "tags": ["CobaltStrike", "beacon"],
        },
        {
            "id": 102,
            "ioc": "[2001:db8::beef]:443",
            "threat_type": "botnet_cc",
            "threat_type_desc": "Botnet Command and Control Server",
            "ioc_type": "ip:port",
            "malware": "elf.mirai",
            "malware_printable": "Mirai",
            "confidence_level": 90,
            "first_seen_utc": "2026-10-21 08:00:00",
            "last_seen_utc": "2026-10-22 10:00:00",
            "reporter": "researcher_a",
            "tags": ["mirai", "iot"],
        },
        {
            "id": 103,
            "ioc": "malicious-c2.example.com",
            "threat_type": "payload_delivery",
            "threat_type_desc": "Payload Delivery Domain",
            "ioc_type": "domain",
            "malware": "win.qakbot",
            "malware_printable": "QakBot",
            "confidence_level": 70,
            "first_seen_utc": "2026-10-22 09:00:00",
            "last_seen_utc": "2026-10-22 14:00:00",
            "reporter": "abuse_ch",
            "tags": ["qakbot"],
        },
        {
            "id": 104,
            "ioc": "https://drop.example.com/stage1.bin",
            "threat_type": "payload_delivery",
            "threat_type_desc": "Payload Delivery URL",
            "ioc_type": "url",
            "malware": "win.redline",
            "malware_printable": "RedLine Stealer",
            "confidence_level": 95,
            "first_seen_utc": "2026-10-22 11:00:00",
            "last_seen_utc": "2026-10-22 16:00:00",
            "reporter": "researcher_b",
            "tags": ["redline", "stealer"],
        },
        {
            "id": 105,
            "ioc": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "threat_type": "payload_delivery",
            "threat_type_desc": "Payload Hash",
            "ioc_type": "sha256_hash",
            "malware": "win.asyncrat",
            "malware_printable": "AsyncRAT",
            "confidence_level": 80,
            "first_seen_utc": "2026-10-22 13:00:00",
            "last_seen_utc": "2026-10-22 17:00:00",
            "reporter": "researcher_c",
            "tags": ["asyncrat"],
        },
        {
            "id": 106,
            "ioc": "098f6bcd4621d373cade4e832627b4f6",
            "threat_type": "payload_delivery",
            "threat_type_desc": "Legacy MD5 Hash",
            "ioc_type": "md5_hash",
            "malware": "win.trojan",
            "confidence_level": 50,
            "tags": ["unsupported"],
        },
    ]
}


@pytest.mark.asyncio
async def test_threatfox_requires_api_key(threatfox_connector):
    """Verify that ThreatFox connector refuses to run without an API key."""
    with pytest.raises(FeedAuthenticationError, match="WALIYA_TI_THREATFOX_API_KEY"):
        await threatfox_connector.fetch_indicators(config_options={"days": 1}, api_key=None)


@pytest.mark.asyncio
async def test_threatfox_successful_fetch_and_parse(threatfox_connector):
    """Verify successful parsing of multiple ThreatFox IOC types with IP extraction."""
    mock_response = MagicMock()
    mock_response.json.return_value = SAMPLE_THREATFOX_RESPONSE
    mock_response.status_code = 200
    mock_response.content = json.dumps(SAMPLE_THREATFOX_RESPONSE).encode("utf-8")
    mock_response.headers = {"content-length": str(len(mock_response.content))}

    with patch.object(threatfox_connector, "execute_request", AsyncMock(return_value=mock_response)) as mock_req:
        result = await threatfox_connector.fetch_indicators(config_options={"days": 3}, api_key="secret-tf-key")

        mock_req.assert_called_once()
        _, kwargs = mock_req.call_args
        assert kwargs["json_body"]["query"] == "get_iocs"
        assert kwargs["json_body"]["days"] == 3
        assert kwargs["headers"]["Auth-Key"] == "secret-tf-key"

        assert result.fetched_count == 6
        assert len(result.records) == 6

        # Check IPv4 extracted from ip:port
        ipv4_rec = next(r for r in result.records if r.source_id == "101")
        assert ipv4_rec.value == "198.51.100.22"
        assert ipv4_rec.indicator_type == "IPV4"
        assert ipv4_rec.confidence == 85
        assert ipv4_rec.confidence_is_policy_derived is False
        assert "malware:Cobalt Strike" in ipv4_rec.tags

        # Check IPv6 extracted from [ip]:port
        ipv6_rec = next(r for r in result.records if r.source_id == "102")
        assert ipv6_rec.value == "2001:db8::beef"
        assert ipv6_rec.indicator_type == "IPV6"
        assert ipv6_rec.confidence == 90

        # Check domain
        domain_rec = next(r for r in result.records if r.source_id == "103")
        assert domain_rec.value == "malicious-c2.example.com"
        assert domain_rec.indicator_type == "DOMAIN"

        # Check URL
        url_rec = next(r for r in result.records if r.source_id == "104")
        assert url_rec.value == "https://drop.example.com/stage1.bin"
        assert url_rec.indicator_type == "URL"

        # Check SHA-256
        sha_rec = next(r for r in result.records if r.source_id == "105")
        assert sha_rec.value == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert sha_rec.indicator_type == "SHA256"

        # Check unsupported MD5
        md5_rec = next(r for r in result.records if r.source_id == "106")
        assert md5_rec.indicator_type == "MD5_HASH"


@pytest.mark.asyncio
async def test_threatfox_no_results_handling(threatfox_connector):
    """Verify that query_status='no_result' returns 0 records cleanly without error."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"query_status": "no_result"}
    mock_response.status_code = 200
    mock_response.content = b'{"query_status": "no_result"}'
    mock_response.headers = {}

    with patch.object(threatfox_connector, "execute_request", AsyncMock(return_value=mock_response)):
        result = await threatfox_connector.fetch_indicators(config_options={"days": 1}, api_key="tf-key")
        assert result.fetched_count == 0
        assert len(result.records) == 0
        assert result.metadata["query_status"] == "no_result"


@pytest.mark.asyncio
async def test_threatfox_error_status_handling(threatfox_connector):
    """Verify that query_status='illegal_query' raises FeedFetchError."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"query_status": "illegal_query", "data": "Invalid days parameter"}
    mock_response.status_code = 200
    mock_response.content = b'{"query_status": "illegal_query"}'
    mock_response.headers = {}

    with patch.object(threatfox_connector, "execute_request", AsyncMock(return_value=mock_response)):
        with pytest.raises(FeedFetchError, match="Invalid days parameter"):
            await threatfox_connector.fetch_indicators(config_options={"days": 99}, api_key="tf-key")
