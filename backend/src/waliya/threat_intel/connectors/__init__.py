"""Threat intelligence feed connectors package."""

from waliya.threat_intel.connectors.base import (
    BaseFeedConnector,
    FeedAuthenticationError,
    FeedFetchError,
    FeedFetchResult,
    FeedRateLimitError,
    FeedSecurityError,
    RawIndicatorRecord,
)
from waliya.threat_intel.connectors.threatfox import ThreatFoxConnector
from waliya.threat_intel.connectors.urlhaus import URLhausConnector

CONNECTORS = {
    "threatfox": ThreatFoxConnector,
    "urlhaus": URLhausConnector,
}

__all__ = [
    "BaseFeedConnector",
    "FeedAuthenticationError",
    "FeedFetchError",
    "FeedFetchResult",
    "FeedRateLimitError",
    "FeedSecurityError",
    "RawIndicatorRecord",
    "ThreatFoxConnector",
    "URLhausConnector",
    "CONNECTORS",
]
