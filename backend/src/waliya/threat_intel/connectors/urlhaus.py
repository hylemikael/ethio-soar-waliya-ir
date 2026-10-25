"""Official URLhaus (abuse.ch) API connector for malicious URLs."""

from datetime import datetime, timedelta, timezone
import logging
from typing import Any, Dict, List, Optional, Set

from waliya.threat_intel.connectors.base import (
    BaseFeedConnector,
    FeedAuthenticationError,
    FeedFetchError,
    FeedFetchResult,
    RawIndicatorRecord,
)

logger = logging.getLogger("waliya.threat_intel.connectors.urlhaus")


class URLhausConnector(BaseFeedConnector):
    """Connector for abuse.ch URLhaus recent malicious URLs API."""

    feed_id: str = "urlhaus"
    provider: str = "URLhaus"
    allowed_hosts: Set[str] = {"urlhaus-api.abuse.ch", "urlhaus.abuse.ch"}
    api_url: str = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

    async def fetch_indicators(
        self,
        config_options: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> FeedFetchResult:
        """Fetch and parse recent malicious URLs from URLhaus."""
        if not api_key:
            raise FeedAuthenticationError(
                "URLhaus API key (abuse.ch Auth-Key) is required. Set WALIYA_TI_URLHAUS_API_KEY."
            )

        headers = {
            "Accept": "application/json",
            "Auth-Key": api_key,
        }

        response = await self.execute_request(
            method="GET",
            url=self.api_url,
            headers=headers,
            api_key_for_redaction=api_key,
        )

        try:
            payload = response.json()
        except Exception as exc:
            raise FeedFetchError(f"Failed to parse JSON response from URLhaus: {exc}") from exc

        query_status = payload.get("query_status")
        if query_status in ("no_results", "no_result"):
            logger.info("URLhaus returned no recent results")
            return FeedFetchResult(
                records=[],
                fetched_count=0,
                metadata={"query_status": query_status},
                diagnostics={"provider": self.provider, "message": "No new URLs in feed"},
            )

        if query_status != "ok":
            msg = payload.get("query_status") or "Unknown error"
            raise FeedFetchError(f"URLhaus query returned non-ok status: {msg}")

        url_items = payload.get("urls")
        if not isinstance(url_items, list):
            raise FeedFetchError("Malformed URLhaus response: 'urls' field is not a list")

        records: List[RawIndicatorRecord] = []
        now_utc = datetime.now(timezone.utc)
        default_expiry_days = int(config_options.get("expiry_days", 14))

        for item in url_items:
            if not isinstance(item, dict):
                continue

            raw_url = str(item.get("url") or "").strip()
            if not raw_url:
                continue

            source_id = str(item.get("id")) if item.get("id") is not None else None
            url_status = str(item.get("url_status") or "online").strip().lower()
            threat = str(item.get("threat") or "malware_download").strip()
            reporter = item.get("reporter")

            tags = list(item.get("tags") or [])
            if threat and f"threat:{threat}" not in tags:
                tags.append(f"threat:{threat}")
            if f"status:{url_status}" not in tags:
                tags.append(f"status:{url_status}")
            tags.append("policy:default_confidence")

            date_added = self.parse_datetime(item.get("date_added"))
            reference_ts = date_added or now_utc

            # Provider does not supply explicit numeric confidence; document policy default 60
            confidence = 60

            # Freshness and lifecycle:
            # Active if online; marked inactive or short-lived if offline
            is_active = (url_status == "online")
            expiry_ttl = default_expiry_days if is_active else 3
            expires_at = reference_ts + timedelta(days=expiry_ttl)

            description = f"URLhaus: {threat} ({url_status})"
            if reporter:
                description += f" reported by {reporter}"

            records.append(
                RawIndicatorRecord(
                    value=raw_url,
                    indicator_type="URL",
                    source_id=source_id,
                    confidence=confidence,
                    confidence_is_policy_derived=True,
                    severity="HIGH" if is_active else "MEDIUM",
                    threat_category=threat,
                    threat_actor=None,
                    tags=tags,
                    description=description,
                    first_seen=date_added,
                    last_seen=date_added,
                    expires_at=expires_at,
                    is_active=is_active,
                    raw_data=item,
                )
            )

            if len(records) >= self.max_records:
                logger.info("Reached maximum record ceiling (%d) for URLhaus feed run", self.max_records)
                break

        return FeedFetchResult(
            records=records,
            fetched_count=len(url_items),
            metadata={"query_status": query_status, "total_in_feed": len(url_items)},
            diagnostics={
                "provider": self.provider,
                "parsed_records": len(records),
            },
        )
