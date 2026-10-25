"""Unit tests for correlation IDs, sensitive data filter, bounded metrics, and worker monitoring."""

import logging
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from starlette.requests import Request
from starlette.responses import Response

from waliya.contracts import DependencyHealthStatus
from waliya.observability.correlation import (
    CorrelationIdMiddleware,
    SensitiveDataFilter,
    get_request_id,
    request_id_ctx,
)
from waliya.observability.metrics import OperationalMetricsCollector
from waliya.observability.worker_monitor import (
    get_worker_health_summary,
    record_worker_heartbeat,
)


@pytest.mark.asyncio
async def test_correlation_id_middleware_generates_new_id():
    """Verify middleware assigns a new req_ ID when no correlation header is provided."""
    middleware = CorrelationIdMiddleware(app=None)

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/health/liveness",
        "headers": [],
    }
    request = Request(scope)

    captured_ctx_id = None

    async def mock_call_next(req: Request) -> Response:
        nonlocal captured_ctx_id
        captured_ctx_id = get_request_id()
        return Response("ok", status_code=200)

    response = await middleware.dispatch(request, mock_call_next)

    assert response.headers.get("X-Request-ID") is not None
    assert response.headers["X-Request-ID"].startswith("req_")
    assert captured_ctx_id == response.headers["X-Request-ID"]
    # Context variable reset after dispatch
    assert get_request_id() == ""


@pytest.mark.asyncio
async def test_correlation_id_middleware_preserves_valid_incoming_id():
    """Verify middleware preserves a valid existing correlation ID header."""
    middleware = CorrelationIdMiddleware(app=None)

    custom_id = "test-corr-id-12345"
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/telemetry",
        "headers": [(b"x-request-id", custom_id.encode())],
    }
    request = Request(scope)

    captured_ctx_id = None

    async def mock_call_next(req: Request) -> Response:
        nonlocal captured_ctx_id
        captured_ctx_id = get_request_id()
        return Response("accepted", status_code=202)

    response = await middleware.dispatch(request, mock_call_next)

    assert response.headers.get("X-Request-ID") == custom_id
    assert captured_ctx_id == custom_id


@pytest.mark.asyncio
async def test_correlation_id_middleware_replaces_invalid_header():
    """Verify middleware rejects and regenerates correlation IDs containing illegal characters."""
    middleware = CorrelationIdMiddleware(app=None)

    malicious_id = "bad id with spaces and <script>"
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/api/v1/health",
        "headers": [(b"x-request-id", malicious_id.encode())],
    }
    request = Request(scope)

    async def mock_call_next(req: Request) -> Response:
        return Response("ok", status_code=200)

    response = await middleware.dispatch(request, mock_call_next)

    assigned_id = response.headers.get("X-Request-ID")
    assert assigned_id.startswith("req_")
    assert "bad id" not in assigned_id


def test_sensitive_data_filter_redacts_keys_and_patterns():
    """Verify SensitiveDataFilter scrubs credentials, secrets, tokens, and authorization headers."""
    log_filter = SensitiveDataFilter()

    # 1. Plain string message with secret
    record = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg='Connecting with password="super_secret_password" and secret="jwt_key"',
        args=(),
        exc_info=None,
    )
    log_filter.filter(record)
    assert "super_secret_password" not in record.msg
    assert "[REDACTED]" in record.msg

    # 2. Authorization header in message
    record_auth = logging.LogRecord(
        name="test",
        level=logging.WARNING,
        pathname="test.py",
        lineno=20,
        msg='Header authorization="Bearer sensitive_token_xyz" rejected',
        args=(),
        exc_info=None,
    )
    log_filter.filter(record_auth)
    assert "sensitive_token_xyz" not in record_auth.msg
    assert "[REDACTED]" in record_auth.msg

    # 3. Sensitive arguments dictionary
    record_dict = logging.LogRecord(
        name="test",
        level=logging.INFO,
        pathname="test.py",
        lineno=30,
        msg="User login payload: %s",
        args={"username": "admin", "api_key": "live_secret_key_123"},
        exc_info=None,
    )
    log_filter.filter(record_dict)
    assert record_dict.args["username"] == "admin"
    assert record_dict.args["api_key"] == "[REDACTED]"


def test_operational_metrics_collector_bounded_labels():
    """Verify OperationalMetricsCollector enforces bounded cardinality and computes averages."""
    collector = OperationalMetricsCollector(max_duration_samples=10)
    collector.reset()

    # Record varied HTTP requests
    collector.record_http_request("GET", 200, 10.0)
    collector.record_http_request("GET", 204, 20.0)
    collector.record_http_request("POST", 201, 30.0)
    collector.record_http_request("POST", 400, 15.0)
    collector.record_http_request("DELETE", 500, 50.0)

    metrics = collector.get_metrics()
    assert metrics.http_requests_total.get("GET_2xx") == 2
    assert metrics.http_requests_total.get("POST_2xx") == 1
    assert metrics.http_requests_total.get("POST_4xx") == 1
    assert metrics.http_requests_total.get("DELETE_5xx") == 1

    # Average latency across 10 + 20 + 30 + 15 + 50 = 125 / 5 = 25.0 ms
    assert metrics.avg_request_duration_ms == 25.0

    # Record pipeline operations
    collector.record_telemetry_processed(15)
    collector.record_telemetry_error(2)
    collector.record_inbound_event("accepted", 5)
    collector.record_inbound_event("duplicate", 3)
    collector.record_inbound_event("rejected", 1)
    collector.record_outbound_delivery("success", 4)
    collector.record_outbound_delivery("retried", 2)
    collector.record_outbound_delivery("dead_letter", 1)

    updated = collector.get_metrics()
    assert updated.telemetry_processed_total == 15
    assert updated.telemetry_errors_total == 2
    assert updated.inbound_events_total["accepted"] == 5
    assert updated.inbound_events_total["duplicate"] == 3
    assert updated.inbound_events_total["rejected"] == 1
    assert updated.outbound_deliveries_total["success"] == 4
    assert updated.outbound_deliveries_total["retried"] == 2
    assert updated.outbound_deliveries_total["dead_letter"] == 1


@pytest.mark.asyncio
async def test_worker_monitor_heartbeat_and_summary():
    """Verify worker heartbeat recording and degradation diagnostics."""
    mock_redis = AsyncMock()

    # 1. Test record_worker_heartbeat
    await record_worker_heartbeat(
        redis=mock_redis,
        group_name="detection_group",
        consumer_name="worker_test_1",
        stream_name="stream:telemetry:raw",
        processed_count=100,
        error_count=2,
        last_batch_size=10,
    )
    mock_redis.hset.assert_awaited_once()
    mock_redis.expire.assert_awaited()
    mock_redis.sadd.assert_awaited_once()

    # 2. Test get_worker_health_summary
    mock_redis.xlen.return_value = 150
    mock_redis.xinfo_groups.return_value = [
        {"name": "detection_group", "pending": 5, "lag": 10}
    ]
    mock_redis.smembers.return_value = [b"worker_test_1"]
    mock_redis.hgetall.return_value = {
        b"worker_id": b"worker_test_1",
        b"group_name": b"detection_group",
        b"stream_name": b"stream:telemetry:raw",
        b"timestamp": datetime.now(timezone.utc).isoformat().encode(),
        b"processed_count": b"100",
        b"error_count": b"2",
    }

    workers, length, lag, pel = await get_worker_health_summary(
        redis=mock_redis,
        stream_name="stream:telemetry:raw",
        group_name="detection_group",
    )

    assert length == 150
    assert lag == 10
    assert pel == 5
    assert len(workers) == 1
    assert workers[0].worker_id == "worker_test_1"
    assert workers[0].status == DependencyHealthStatus.HEALTHY
    assert workers[0].processed_count == 100
    assert workers[0].error_count == 2
