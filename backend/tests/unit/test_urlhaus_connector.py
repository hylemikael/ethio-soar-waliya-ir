"""Unit tests for official URLhaus connector."""

import json
from unittest.mock import AsyncMock, MagicMock, patch
import pytest

from waliya.threat_intel.connectors.base import (
    FeedAuthenticationError,
    FeedFetchError,
)
from waliya.threat_intel.connectors.urlhaus import URLhausConnector


@pytest.fixture
def urlhaus_connector():
    return URLhausConnector(timeout_seconds=5.0, max_records=50)


SAMPLE_URLHAUS_RESPONSE = {
    "query_status": "ok",
    "urls": [
        {
            "id": "223622",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/223622/",
            "url": "http://198.51.100.44/razor/r4z0r.mips",
            "url_status": "offline",
            "host": "198.51.100.44",
            "date_added": "2026-10-20 09:02:05 UTC",
            "threat": "malware_download",
            "reporter": "zbetcheckin",
            "tags": ["elf", "mirai"],
        },
        {
            "id": "223623",
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/223623/",
            "url": "https://malicious-delivery.example.org/payload.exe",
            "url_status": "online",
            "host": "malicious-delivery.example.org",
            "date_added": "2026-10-21 14:15:30 UTC",
            "threat": "malware_download",
            "reporter": "abuse_hunter",
            "tags": ["exe", "redline"],
        },
    ],
}


@pytest.mark.asyncio
async def test_urlhaus_requires_api_key(urlhaus_connector):
    """Verify that URLhaus connector requires configured API key."""
    with pytest.raises(FeedAuthenticationError, match="WALIYA_TI_URLHAUS_API_KEY"):
        await urlhaus_connector.fetch_indicators(config_options={}, api_key=None)


@pytest.mark.asyncio
async def test_urlhaus_successful_fetch_and_status_handling(urlhaus_connector):
    """Verify URLhaus response parsing, online vs offline handling, and policy-derived confidence."""
    mock_response = MagicMock()
    mock_response.json.return_value = SAMPLE_URLHAUS_RESPONSE
    mock_response.status_code = 200
    mock_response.content = json.dumps(SAMPLE_URLHAUS_RESPONSE).encode("utf-8")
    mock_response.headers = {"content-length": str(len(mock_response.content))}

    with patch.object(urlhaus_connector, "execute_request", AsyncMock(return_value=mock_response)) as mock_req:
        result = await urlhaus_connector.fetch_indicators(config_options={}, api_key="secret-uh-key")

        mock_req.assert_called_once()
        _, kwargs = mock_req.call_args
        assert kwargs["method"] == "GET"
        assert kwargs["headers"]["Auth-Key"] == "secret-uh-key"

        assert result.fetched_count == 2
        assert len(result.records) == 2

        # Offline URL: should be marked is_active=False
        offline_rec = next(r for r in result.records if r.source_id == "223622")
        assert offline_rec.value == "http://198.51.100.44/razor/r4z0r.mips"
        assert offline_rec.is_active is False
        assert offline_rec.confidence == 60
        assert offline_rec.confidence_is_policy_derived is True
        assert "policy:default_confidence" in offline_rec.tags
        assert "status:offline" in offline_rec.tags

        # Online URL: should be marked is_active=True
        online_rec = next(r for r in result.records if r.source_id == "223623")
        assert online_rec.value == "https://malicious-delivery.example.org/payload.exe"
        assert online_rec.is_active is True
        assert online_rec.confidence == 60
        assert "status:online" in online_rec.tags


@pytest.mark.asyncio
async def test_urlhaus_no_results_handling(urlhaus_connector):
    """Verify that query_status='no_results' returns 0 records cleanly."""
    mock_response = MagicMock()
    mock_response.json.return_value = {"query_status": "no_results"}
    mock_response.status_code = 200
    mock_response.content = b'{"query_status": "no_results"}'
    mock_response.headers = {}

    with patch.object(urlhaus_connector, "execute_request", AsyncMock(return_value=mock_response)):
        result = await urlhaus_connector.fetch_indicators(config_options={}, api_key="uh-key")
        assert result.fetched_count == 0
        assert len(result.records) == 0
