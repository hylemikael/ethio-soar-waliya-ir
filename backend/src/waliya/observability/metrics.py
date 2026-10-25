"""In-memory thread-safe operational metrics collector with bounded cardinality."""

import threading
from collections import deque
from datetime import datetime, timezone
from typing import Dict, List, Optional

from waliya.contracts import OperationalMetricsResponse


class OperationalMetricsCollector:
    """Thread-safe collector for bounded platform operational metrics without external monitoring services."""

    def __init__(self, max_duration_samples: int = 200):
        self._lock = threading.Lock()
        self._max_samples = max_duration_samples
        self._http_requests: Dict[str, int] = {}
        self._request_durations: deque = deque(maxlen=max_duration_samples)
        self._telemetry_processed_total: int = 0
        self._telemetry_errors_total: int = 0
        self._inbound_events_total: Dict[str, int] = {
            "accepted": 0,
            "rejected": 0,
            "duplicate": 0,
        }
        self._outbound_deliveries_total: Dict[str, int] = {
            "success": 0,
            "failed": 0,
            "retried": 0,
            "dead_letter": 0,
        }

    def record_http_request(self, method: str, status_code: int, duration_ms: float) -> None:
        """Record an HTTP request count and latency with strictly bounded label cardinality."""
        method_clean = method.upper() if method else "UNKNOWN"
        # Map status code to status class (2xx, 3xx, 4xx, 5xx)
        status_class = f"{status_code // 100}xx"
        metric_key = f"{method_clean}_{status_class}"

        with self._lock:
            self._http_requests[metric_key] = self._http_requests.get(metric_key, 0) + 1
            if duration_ms >= 0:
                self._request_durations.append(duration_ms)

    def record_telemetry_processed(self, count: int = 1) -> None:
        """Increment count of processed telemetry events."""
        if count <= 0:
            return
        with self._lock:
            self._telemetry_processed_total += count

    def record_telemetry_error(self, count: int = 1) -> None:
        """Increment count of telemetry processing errors."""
        if count <= 0:
            return
        with self._lock:
            self._telemetry_errors_total += count

    def record_inbound_event(self, status: str, count: int = 1) -> None:
        """Record inbound security event outcome (accepted, rejected, duplicate)."""
        key = status.lower()
        if key not in self._inbound_events_total:
            key = "other"
        with self._lock:
            self._inbound_events_total[key] = self._inbound_events_total.get(key, 0) + count

    def record_outbound_delivery(self, status: str, count: int = 1) -> None:
        """Record outbound notification delivery outcome (success, failed, retried, dead_letter)."""
        key = status.lower()
        if key not in self._outbound_deliveries_total:
            key = "other"
        with self._lock:
            self._outbound_deliveries_total[key] = self._outbound_deliveries_total.get(key, 0) + count

    def get_metrics(self) -> OperationalMetricsResponse:
        """Return snapshot of operational metrics."""
        with self._lock:
            durations = list(self._request_durations)
            avg_duration = round(sum(durations) / len(durations), 2) if durations else 0.0

            return OperationalMetricsResponse(
                timestamp=datetime.now(timezone.utc),
                http_requests_total=dict(self._http_requests),
                avg_request_duration_ms=avg_duration,
                telemetry_processed_total=self._telemetry_processed_total,
                telemetry_errors_total=self._telemetry_errors_total,
                inbound_events_total=dict(self._inbound_events_total),
                outbound_deliveries_total=dict(self._outbound_deliveries_total),
            )

    def reset(self) -> None:
        """Reset all counters to zero (used in test teardown)."""
        with self._lock:
            self._http_requests.clear()
            self._request_durations.clear()
            self._telemetry_processed_total = 0
            self._telemetry_errors_total = 0
            self._inbound_events_total = {"accepted": 0, "rejected": 0, "duplicate": 0}
            self._outbound_deliveries_total = {"success": 0, "failed": 0, "retried": 0, "dead_letter": 0}


# Global singleton instance
_collector = OperationalMetricsCollector()


def get_metrics_collector() -> OperationalMetricsCollector:
    """Retrieve global operational metrics collector singleton."""
    return _collector
