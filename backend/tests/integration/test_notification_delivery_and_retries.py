"""Integration tests for notification delivery, bounded retries, and loop prevention."""

from datetime import datetime, timezone
from unittest.mock import patch
from uuid import uuid4
import httpx
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import func, select

from waliya.config import settings
from waliya.db.models import (
    FindingModel,
    IncidentModel,
    NotificationDeliveryModel,
    NotificationDestinationModel,
)
from waliya.db.session import async_session_factory
from waliya.integrations.delivery_service import NotificationDeliveryService
from waliya.integrations.payloads import (
    NotificationEventType,
    build_incident_created_payload,
)
from waliya.integrations.signing import (
    encrypt_destination_secret,
    verify_notification_signature,
)
from waliya.main import create_app


@pytest.fixture
def admin_headers():
    return {"X-Admin-Key": settings.ADMIN_API_KEY}


@pytest_asyncio.fixture
async def async_client():
    app = create_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.mark.asyncio
async def test_successful_webhook_delivery_and_hmac_verification():
    """Verify end-to-end delivery of an incident notification with HMAC verification."""
    secret = "production-receiver-webhook-secret-12345"
    captured_requests = []

    # Mock remote receiver handler
    def mock_handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append({
            "headers": dict(request.headers),
            "content": request.content,
        })
        return httpx.Response(200, json={"status": "received"})

    mock_transport = httpx.MockTransport(mock_handler)
    mock_http_client = httpx.AsyncClient(transport=mock_transport)

    dest_id = uuid4()
    async with async_session_factory() as session:
        dest = NotificationDestinationModel(
            id=dest_id,
            name="Mock SOC Webhook",
            destination_url="https://soc.enterprise.net/webhooks/incidents",
            is_enabled=True,
            subscribed_events=["INCIDENT_CREATED"],
            signing_secret_enc=encrypt_destination_secret(secret),
        )
        session.add(dest)
        await session.commit()

        # Queue a notification
        inc_id = uuid4()
        now = datetime.now(timezone.utc)
        payload = build_incident_created_payload(
            incident_id=inc_id,
            title="Suspicious SSH Activity",
            severity="HIGH",
            composite_risk_score=85.0,
            status="OPEN",
            first_seen=now,
            last_seen=now,
            affected_entities=["192.168.1.55", "user:root"],
            mitre_attack_ids=["T1021.004"],
        )
        deliveries = await NotificationDeliveryService.queue_notification(
            session=session,
            event_type=NotificationEventType.INCIDENT_CREATED.value,
            event_id=str(inc_id),
            payload=payload,
        )
        target_deliveries = [d for d in deliveries if d.destination_id == dest.id]
        assert len(target_deliveries) == 1
        delivery = target_deliveries[0]
        assert delivery.status == "PENDING"
        await session.commit()

        # Dispatch with mock transport and mock DNS resolution
        mock_addrinfo = [(None, None, None, None, ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            delivered = await NotificationDeliveryService.dispatch_delivery(
                session=session,
                delivery=delivery,
                allow_local_for_testing=False,
                http_client=mock_http_client,
            )
            await session.commit()

        assert delivered.status == "DELIVERED"
        assert delivered.response_status_code == 200
        assert delivered.delivered_at is not None
        assert delivered.attempt_count == 1

        # Verify destination status was updated
        await session.refresh(dest)
        assert dest.last_delivery_status == "DELIVERED"
        assert dest.last_delivery_at is not None

        # Verify remote receiver received valid HMAC signature over transmitted bytes
        assert len(captured_requests) == 1
        req = captured_requests[0]
        sig_header = req["headers"]["x-waliya-signature"]
        raw_body = req["content"]
        assert verify_notification_signature(secret, raw_body, sig_header) is True


@pytest.mark.asyncio
async def test_non_retryable_client_error():
    """Verify HTTP 400/404 rejections are classified as PERMANENTLY_FAILED immediately."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, text="Bad Request: unknown format")

    mock_transport = httpx.MockTransport(mock_handler)
    mock_http_client = httpx.AsyncClient(transport=mock_transport)

    dest_id = uuid4()
    async with async_session_factory() as session:
        dest = NotificationDestinationModel(
            id=dest_id,
            name="Failing Webhook",
            destination_url="https://bad-endpoint.example.com/hook",
            is_enabled=True,
            subscribed_events=["*"],
        )
        session.add(dest)
        await session.commit()

        delivery_id = uuid4()
        delivery = NotificationDeliveryModel(
            id=uuid4(),
            destination_id=dest.id,
            delivery_id=delivery_id,
            event_type="TEST_NOTIFICATION",
            event_id="test",
            status="PENDING",
            payload={"test": True},
        )
        session.add(delivery)
        await session.commit()

        mock_addrinfo = [(None, None, None, None, ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            result = await NotificationDeliveryService.dispatch_delivery(
                session=session,
                delivery=delivery,
                allow_local_for_testing=False,
                http_client=mock_http_client,
            )
            await session.commit()

        assert result.status == "PERMANENTLY_FAILED"
        assert result.response_status_code == 400
        assert "External destination rejected delivery" in result.error_message
        assert result.next_attempt_at is None


@pytest.mark.asyncio
async def test_retryable_server_error_and_exponential_backoff():
    """Verify HTTP 500 or timeout schedules bounded exponential retry."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(503, text="Service Unavailable")

    mock_transport = httpx.MockTransport(mock_handler)
    mock_http_client = httpx.AsyncClient(transport=mock_transport)

    dest_id = uuid4()
    async with async_session_factory() as session:
        dest = NotificationDestinationModel(
            id=dest_id,
            name="Flaky Webhook",
            destination_url="https://flaky-server.example.com/hook",
            is_enabled=True,
            subscribed_events=["*"],
        )
        session.add(dest)
        await session.commit()

        delivery = NotificationDeliveryModel(
            id=uuid4(),
            destination_id=dest.id,
            delivery_id=uuid4(),
            event_type="TEST_NOTIFICATION",
            event_id="test-retry",
            status="PENDING",
            attempt_count=0,
            max_attempts=3,
            payload={"retry_test": True},
        )
        session.add(delivery)
        await session.commit()

        mock_addrinfo = [(None, None, None, None, ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            # Attempt 1 -> RETRY_SCHEDULED
            res1 = await NotificationDeliveryService.dispatch_delivery(
                session=session,
                delivery=delivery,
                http_client=mock_http_client,
            )
            assert res1.status == "RETRY_SCHEDULED"
            assert res1.attempt_count == 1
            assert res1.next_attempt_at is not None

            # Attempt 2 -> RETRY_SCHEDULED
            res2 = await NotificationDeliveryService.dispatch_delivery(
                session=session,
                delivery=delivery,
                http_client=mock_http_client,
            )
            assert res2.status == "RETRY_SCHEDULED"
            assert res2.attempt_count == 2

            # Attempt 3 (ceiling reached) -> PERMANENTLY_FAILED
            res3 = await NotificationDeliveryService.dispatch_delivery(
                session=session,
                delivery=delivery,
                http_client=mock_http_client,
            )
            assert res3.status == "PERMANENTLY_FAILED"
            assert res3.attempt_count == 3
            assert res3.next_attempt_at is None


@pytest.mark.asyncio
async def test_notification_loop_prevention():
    """Verify delivery failures NEVER generate new security findings or incidents."""
    async with async_session_factory() as session:
        # Count findings and incidents before failure
        findings_before = (await session.execute(select(func.count(FindingModel.id)))).scalar()
        incidents_before = (await session.execute(select(func.count(IncidentModel.id)))).scalar()

        # Trigger failed delivery
        dest = NotificationDestinationModel(
            id=uuid4(),
            name="Failing Endpoint",
            destination_url="https://bad-host.test/alerts",
            is_enabled=True,
            subscribed_events=["*"],
        )
        session.add(dest)
        await session.commit()

        delivery = NotificationDeliveryModel(
            id=uuid4(),
            destination_id=dest.id,
            delivery_id=uuid4(),
            event_type="TEST_NOTIFICATION",
            event_id="test-loop",
            status="PENDING",
            payload={"test": "data"},
        )
        session.add(delivery)
        await session.commit()

        # Mock exception
        mock_client = httpx.AsyncClient(
            transport=httpx.MockTransport(lambda req: (_ for _ in ()).throw(httpx.ConnectError("Connection refused")))
        )
        mock_addrinfo = [(None, None, None, None, ("93.184.216.34", 443))]
        with patch("socket.getaddrinfo", return_value=mock_addrinfo):
            await NotificationDeliveryService.dispatch_delivery(
                session=session,
                delivery=delivery,
                http_client=mock_client,
            )
            await session.commit()

        findings_after = (await session.execute(select(func.count(FindingModel.id)))).scalar()
        incidents_after = (await session.execute(select(func.count(IncidentModel.id)))).scalar()

        # INVARIANT: Notification failures must never increase finding or incident counts
        assert findings_after == findings_before
        assert incidents_after == incidents_before


@pytest.mark.asyncio
async def test_disabled_destinations_receive_no_deliveries():
    """Verify disabled destinations are ignored during event queueing."""
    async with async_session_factory() as session:
        dest = NotificationDestinationModel(
            id=uuid4(),
            name="Disabled Hook",
            destination_url="https://disabled.example.com/hook",
            is_enabled=False,
            subscribed_events=["INCIDENT_CREATED"],
        )
        session.add(dest)
        await session.commit()

        payload = build_incident_created_payload(
            incident_id=uuid4(),
            title="Test Alert",
            severity="LOW",
            composite_risk_score=10.0,
            status="OPEN",
            first_seen=datetime.now(timezone.utc),
            last_seen=datetime.now(timezone.utc),
            affected_entities=[],
            mitre_attack_ids=[],
        )

        deliveries = await NotificationDeliveryService.queue_notification(
            session=session,
            event_type=NotificationEventType.INCIDENT_CREATED.value,
            event_id="test",
            payload=payload,
        )

        # Ensure no deliveries were created for the disabled destination
        disabled_deliveries = [d for d in deliveries if d.destination_id == dest.id]
        assert len(disabled_deliveries) == 0


@pytest.mark.asyncio
async def test_deliveries_api_pagination_and_retry(async_client, admin_headers):
    """Verify GET /deliveries filtering/pagination and POST /deliveries/{id}/retry."""
    async with async_session_factory() as session:
        dest = NotificationDestinationModel(
            id=uuid4(),
            name="History Webhook",
            destination_url="https://history.example.com/events",
            is_enabled=True,
            subscribed_events=["*"],
        )
        session.add(dest)

        failed_delivery = NotificationDeliveryModel(
            id=uuid4(),
            destination_id=dest.id,
            delivery_id=uuid4(),
            event_type="TEST_NOTIFICATION",
            event_id="test-hist",
            status="PERMANENTLY_FAILED",
            attempt_count=5,
            payload={"info": "failed-attempt"},
            error_message="HTTP 500: Server Error",
        )
        session.add(failed_delivery)
        await session.commit()
        failed_id = failed_delivery.id

    # Query delivery history via API
    resp = await async_client.get(
        "/api/v1/integrations/deliveries?limit=10&offset=0",
        headers=admin_headers,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 1
    found = [d for d in data["deliveries"] if d["id"] == str(failed_id)]
    assert len(found) == 1
    assert found[0]["status"] == "PERMANENTLY_FAILED"

    # Test manual retry endpoint
    def mock_handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"status": "recovered"})

    mock_addrinfo = [(None, None, None, None, ("93.184.216.34", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        with patch("waliya.integrations.delivery_service.create_safe_http_client", return_value=httpx.AsyncClient(transport=httpx.MockTransport(mock_handler))):
            retry_resp = await async_client.post(
                f"/api/v1/integrations/deliveries/{failed_id}/retry",
                headers=admin_headers,
            )
            assert retry_resp.status_code == 200
            retry_data = retry_resp.json()
            assert retry_data["status"] == "DELIVERED"
            assert retry_data["response_status_code"] == 200
