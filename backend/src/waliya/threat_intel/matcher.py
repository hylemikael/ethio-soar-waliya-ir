"""Safe, deterministic threat intelligence indicator matching service.

Guarantees:
- Zero outbound network lookups or DNS queries to observed entities.
- Rejects malformed or incomplete observables gracefully.
- Ignores expired (expires_at <= now) or inactive (is_active == False) indicators.
- Bounded, index-accelerated database queries.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.db.models import ThreatIndicatorModel
from waliya.threat_intel.normalizer import (
    IndicatorValidationError,
    detect_indicator_type,
    normalize_indicator,
)

logger = logging.getLogger("waliya.threat_intel.matcher")

IGNORABLE_OBSERVABLES = {
    "127.0.0.1",
    "::1",
    "0.0.0.0",
    "::",
    "localhost",
    "localhost.localdomain",
}


class ThreatIntelMatcher:
    """Offline indicator matching service for security telemetry and observables with bounded caching."""

    # Thread-safe in-memory cache: (indicator_type, canonical_value) -> (cached_at, [ThreatIndicatorModel])
    _cache: Dict[Tuple[str, str], Tuple[datetime, List[ThreatIndicatorModel]]] = {}
    _cache_max_size: int = 4096
    _cache_ttl_seconds: float = 60.0

    @classmethod
    def clear_cache(cls) -> None:
        """Clear all entries from the in-memory observable matcher cache."""
        cls._cache.clear()

    @classmethod
    def _is_ignorable(cls, observable: str) -> bool:
        """Check if an observable is local/loopback and should not trigger database lookups."""
        return observable.lower().strip() in IGNORABLE_OBSERVABLES

    @classmethod
    async def match_observable(
        cls,
        session: AsyncSession,
        observable: str,
        indicator_type: Optional[str] = None,
    ) -> List[ThreatIndicatorModel]:
        """Match a single observable string against active, non-expired threat indicators.

        Returns matching ThreatIndicatorModel instances ordered by confidence descending.
        Never performs network or DNS lookups.
        """
        if not observable or not isinstance(observable, str):
            return []

        clean_obs = observable.strip()
        if not clean_obs or cls._is_ignorable(clean_obs):
            return []

        # 1. Resolve and normalize type and value
        try:
            if not indicator_type:
                target_type = detect_indicator_type(clean_obs)
            else:
                target_type = indicator_type

            norm_type, norm_value = normalize_indicator(target_type, clean_obs)
        except (IndicatorValidationError, ValueError) as exc:
            logger.debug("Observable '%s' failed normalization: %s", clean_obs, exc)
            return []

        cache_key = (norm_type, norm_value)
        now_utc = datetime.now(timezone.utc)

        # Check in-memory cache
        if cache_key in cls._cache:
            cached_at, cached_models = cls._cache[cache_key]
            if (now_utc - cached_at).total_seconds() < cls._cache_ttl_seconds:
                # Filter out expired or deactivated records from cache view
                valid = [
                    m for m in cached_models
                    if m.is_active and (m.expires_at is None or m.expires_at > now_utc)
                ]
                return valid

        # 2. Query matching active and non-expired indicators using indexed columns
        query = (
            select(ThreatIndicatorModel)
            .where(
                ThreatIndicatorModel.indicator_type == norm_type,
                ThreatIndicatorModel.value == norm_value,
                ThreatIndicatorModel.is_active == True,
                or_(
                    ThreatIndicatorModel.expires_at.is_(None),
                    ThreatIndicatorModel.expires_at > now_utc,
                ),
            )
            .order_by(desc(ThreatIndicatorModel.confidence))
        )

        res = await session.execute(query)
        models = list(res.scalars().all())

        # Update cache bounded by max_size
        if len(cls._cache) >= cls._cache_max_size:
            # Evict oldest entry
            oldest_k = next(iter(cls._cache))
            cls._cache.pop(oldest_k, None)

        cls._cache[cache_key] = (now_utc, models)
        return models

    @classmethod
    async def match_observables_batch(
        cls,
        session: AsyncSession,
        observables: List[Tuple[str, Optional[str]]],
    ) -> Dict[str, List[ThreatIndicatorModel]]:
        """Match a batch of (observable, optional_type) tuples against threat indicators.

        Returns a dictionary mapping each raw observable string to its matching indicators.
        """
        results: Dict[str, List[ThreatIndicatorModel]] = {}
        if not observables:
            return results

        # Normalize valid observables and group by (type, value)
        normalized_lookup: Dict[Tuple[str, str], List[str]] = {}
        now_utc = datetime.now(timezone.utc)
        uncached_keys: Set[Tuple[str, str]] = set()

        for raw_val, raw_type in observables:
            results[raw_val] = []
            if not raw_val or not isinstance(raw_val, str):
                continue
            clean_v = raw_val.strip()
            if not clean_v or cls._is_ignorable(clean_v):
                continue

            try:
                t = raw_type or detect_indicator_type(clean_v)
                norm_type, norm_val = normalize_indicator(t, clean_v)
                cache_key = (norm_type, norm_val)
                normalized_lookup.setdefault(cache_key, []).append(raw_val)

                # Check cache first
                if cache_key in cls._cache:
                    cached_at, cached_models = cls._cache[cache_key]
                    if (now_utc - cached_at).total_seconds() < cls._cache_ttl_seconds:
                        valid = [
                            m for m in cached_models
                            if m.is_active and (m.expires_at is None or m.expires_at > now_utc)
                        ]
                        results[raw_val].extend(valid)
                        continue

                uncached_keys.add(cache_key)
            except Exception:
                continue

        if not uncached_keys:
            return results

        # Query distinct normalized values only for uncached keys
        conditions = [
            (ThreatIndicatorModel.indicator_type == t) & (ThreatIndicatorModel.value == v)
            for t, v in uncached_keys
        ]

        query = (
            select(ThreatIndicatorModel)
            .where(
                or_(*conditions),
                ThreatIndicatorModel.is_active == True,
                or_(
                    ThreatIndicatorModel.expires_at.is_(None),
                    ThreatIndicatorModel.expires_at > now_utc,
                ),
            )
            .order_by(desc(ThreatIndicatorModel.confidence))
        )

        res = await session.execute(query)
        matched_models = res.scalars().all()

        # Group models by normalized key and update cache
        by_key: Dict[Tuple[str, str], List[ThreatIndicatorModel]] = {k: [] for k in uncached_keys}
        for m in matched_models:
            key = (m.indicator_type, m.value)
            if key in by_key:
                by_key[key].append(m)

        for key, models in by_key.items():
            if len(cls._cache) >= cls._cache_max_size:
                oldest_k = next(iter(cls._cache))
                cls._cache.pop(oldest_k, None)
            cls._cache[key] = (now_utc, models)
            raw_keys = normalized_lookup.get(key, [])
            for raw_k in raw_keys:
                results[raw_k].extend(models)

        return results

    @classmethod
    async def match_event_observables(
        cls,
        session: AsyncSession,
        event_data: Dict[str, Any],
    ) -> List[Dict[str, Any]]:
        """Extract observables from event attributes and return structured match records."""
        attrs = event_data.get("attributes") or event_data.get("normalized", {}).get("attributes") or {}
        observables: List[Tuple[str, Optional[str]]] = []

        # IP observables (ignoring loopback / local addresses)
        if "src_ip" in attrs and attrs["src_ip"] and not cls._is_ignorable(str(attrs["src_ip"])):
            observables.append((str(attrs["src_ip"]), "IP"))
        if "dst_ip" in attrs and attrs["dst_ip"] and not cls._is_ignorable(str(attrs["dst_ip"])):
            observables.append((str(attrs["dst_ip"]), "IP"))

        # File hash observables
        if "sha256" in attrs and attrs["sha256"]:
            observables.append((str(attrs["sha256"]), "SHA256"))

        # Domain observables
        if "domain" in attrs and attrs["domain"] and not cls._is_ignorable(str(attrs["domain"])):
            observables.append((str(attrs["domain"]), "DOMAIN"))
        if "hostname" in attrs and attrs["hostname"] and not cls._is_ignorable(str(attrs["hostname"])):
            observables.append((str(attrs["hostname"]), "DOMAIN"))

        # URL observables
        if "url" in attrs and attrs["url"]:
            observables.append((str(attrs["url"]), "URL"))

        if not observables:
            return []

        matches_map = await cls.match_observables_batch(session, observables)
        now_utc = datetime.now(timezone.utc)

        structured_matches: List[Dict[str, Any]] = []
        seen_indicator_ids: Set[UUID] = set()

        for raw_obs, matched_indicators in matches_map.items():
            for ind in matched_indicators:
                if ind.id in seen_indicator_ids:
                    continue
                seen_indicator_ids.add(ind.id)
                structured_matches.append({
                    "observable": raw_obs,
                    "indicator_id": str(ind.id),
                    "indicator_type": ind.indicator_type,
                    "value": ind.value,
                    "source": ind.source,
                    "source_id": ind.source_id,
                    "confidence": ind.confidence,
                    "severity": ind.severity,
                    "threat_category": ind.threat_category,
                    "threat_actor": ind.threat_actor,
                    "tags": ind.tags,
                    "description": ind.description,
                    "first_seen": ind.first_seen.isoformat() if ind.first_seen else None,
                    "last_seen": ind.last_seen.isoformat() if ind.last_seen else None,
                    "matched_at": now_utc.isoformat(),
                    "investigative_note": (
                        f"Observable '{raw_obs}' matched known threat indicator ({ind.indicator_type}) "
                        f"from {ind.source} with confidence {ind.confidence}% "
                        f"[{ind.threat_category or 'GENERAL_MALICIOUS'}]."
                    ),
                })

        return structured_matches
