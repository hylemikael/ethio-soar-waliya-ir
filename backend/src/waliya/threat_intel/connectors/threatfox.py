"""Official ThreatFox (abuse.ch) community API connector."""

from datetime import datetime, timedelta, timezone
import ipaddress
import logging
import re
from typing import Any, Dict, List, Optional, Set

from waliya.threat_intel.connectors.base import (
    BaseFeedConnector,
    FeedAuthenticationError,
    FeedFetchError,
    FeedFetchResult,
    RawIndicatorRecord,
)

logger = logging.getLogger("waliya.threat_intel.connectors.threatfox")


class ThreatFoxConnector(BaseFeedConnector):
    """Connector for abuse.ch ThreatFox threat intelligence API."""

    feed_id: str = "threatfox"
    provider: str = "ThreatFox"
    allowed_hosts: Set[str] = {"threatfox-api.abuse.ch", "threatfox.abuse.ch"}
    api_url: str = "https://threatfox-api.abuse.ch/api/v1/"

    def _extract_ip_from_endpoint(self, ioc_val: str) -> str:
        """Extract IP address from ip:port representation safely."""
        clean = ioc_val.strip()
        # Bracketed IPv6 e.g. [2001:db8::1]:8080
        m = re.match(r"^\[([a-fA-F0-9:]+)\](?::\d+)?$", clean)
        if m:
            return m.group(1)

        # Standard IPv4 e.g. 192.0.2.1:8080
        if ":" in clean and clean.count(":") == 1:
            ip_part, _ = clean.split(":", 1)
            try:
                ipaddress.IPv4Address(ip_part)
                return ip_part
            except Exception:
                pass

        # Bare IP without port or unbracketed IPv6
        return clean

    async def fetch_indicators(
        self,
        config_options: Dict[str, Any],
        api_key: Optional[str] = None,
    ) -> FeedFetchResult:
        """Fetch and parse IOC records from ThreatFox.

        Enforces query window (1 to 7 days) and respects documented provider response schema.
        """
        if not api_key:
            raise FeedAuthenticationError(
                "ThreatFox API key (abuse.ch Auth-Key) is required. Set WALIYA_TI_THREATFOX_API_KEY."
            )

        days = int(config_options.get("days", 1))
        # ThreatFox community API bounds get_iocs to 1-7 days
        days = max(1, min(7, days))

        request_body = {
            "query": "get_iocs",
            "days": days,
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Auth-Key": api_key,
        }

        response = await self.execute_request(
            method="POST",
            url=self.api_url,
            headers=headers,
            json_body=request_body,
            api_key_for_redaction=api_key,
        )

        try:
            payload = response.json()
        except Exception as exc:
            raise FeedFetchError(f"Failed to parse JSON response from ThreatFox: {exc}") from exc

        query_status = payload.get("query_status")
        if query_status == "no_result":
            logger.info("ThreatFox returned no results for query window (days=%d)", days)
            return FeedFetchResult(
                records=[],
                fetched_count=0,
                metadata={"query_status": query_status, "days": days},
                diagnostics={"provider": self.provider, "message": "No new IOCs in query window"},
            )

        if query_status != "ok":
            msg = payload.get("data") or payload.get("query_status") or "Unknown error"
            raise FeedFetchError(f"ThreatFox query returned non-ok status: {msg}")

        data_items = payload.get("data")
        if not isinstance(data_items, list):
            raise FeedFetchError("Malformed ThreatFox response: 'data' field is not a list")

        records: List[RawIndicatorRecord] = []
        now_utc = datetime.now(timezone.utc)
        default_expiry_days = int(config_options.get("expiry_days", 30))

        for item in data_items:
            if not isinstance(item, dict):
                continue

            raw_ioc = str(item.get("ioc") or "").strip()
            if not raw_ioc:
                continue

            provider_ioc_type = str(item.get("ioc_type") or "").strip().lower()
            source_id = str(item.get("id")) if item.get("id") is not None else None

            # Map ThreatFox IOC types
            indicator_type: Optional[str] = None
            extracted_val = raw_ioc

            if provider_ioc_type == "ip:port":
                extracted_val = self._extract_ip_from_endpoint(raw_ioc)
                try:
                    ip_obj = ipaddress.ip_address(extracted_val)
                    indicator_type = "IPV4" if ip_obj.version == 4 else "IPV6"
                except Exception:
                    indicator_type = "IPV4"
            elif provider_ioc_type in ("domain", "hostname"):
                indicator_type = "DOMAIN"
            elif provider_ioc_type == "url":
                indicator_type = "URL"
            elif provider_ioc_type in ("sha256_hash", "sha256"):
                indicator_type = "SHA256"
            else:
                # Unsupported IOC types (e.g. md5_hash, sha1) left with provider label for skipped counter
                indicator_type = provider_ioc_type.upper()

            # ThreatFox provides explicit confidence_level (0-100)
            confidence_level = item.get("confidence_level")
            confidence = int(confidence_level) if isinstance(confidence_level, (int, float)) else 50
            confidence = max(0, min(100, confidence))

            threat_type = item.get("threat_type") or "malicious"
            threat_desc = item.get("threat_type_desc") or ""
            malware = item.get("malware_printable") or item.get("malware")

            tags = list(item.get("tags") or [])
            if malware and f"malware:{malware}" not in tags:
                tags.append(f"malware:{malware}")
            if threat_type and f"category:{threat_type}" not in tags:
                tags.append(f"category:{threat_type}")

            first_seen = self.parse_datetime(item.get("first_seen_utc"))
            last_seen = self.parse_datetime(item.get("last_seen_utc"))

            # Calculate expiry date based on local freshness policy and ThreatFox 180-day max
            reference_ts = last_seen or first_seen or now_utc
            calculated_expiry = reference_ts + timedelta(days=default_expiry_days)
            max_ceiling = reference_ts + timedelta(days=180)
            expires_at = min(calculated_expiry, max_ceiling)

            description_parts = []
            if malware:
                description_parts.append(f"ThreatFox: {malware}")
            if threat_desc:
                description_parts.append(f"({threat_desc})")
            description = " ".join(description_parts) if description_parts else f"ThreatFox IOC {raw_ioc}"

            records.append(
                RawIndicatorRecord(
                    value=extracted_val,
                    indicator_type=indicator_type,
                    source_id=source_id,
                    confidence=confidence,
                    confidence_is_policy_derived=False,
                    severity="HIGH" if confidence >= 75 else "MEDIUM",
                    threat_category=threat_type,
                    threat_actor=None,
                    tags=tags,
                    description=description,
                    first_seen=first_seen,
                    last_seen=last_seen,
                    expires_at=expires_at,
                    is_active=True,
                    raw_data=item,
                )
            )

            if len(records) >= self.max_records:
                logger.info("Reached maximum record ceiling (%d) for ThreatFox feed run", self.max_records)
                break

        return FeedFetchResult(
            records=records,
            fetched_count=len(data_items),
            metadata={"query_status": query_status, "days": days, "total_in_feed": len(data_items)},
            diagnostics={
                "provider": self.provider,
                "parsed_records": len(records),
                "query_window_days": days,
            },
        )
