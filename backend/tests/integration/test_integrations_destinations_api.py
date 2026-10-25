"""Integration tests for outbound notification destinations API."""

from unittest.mock import patch
from uuid import uuid4
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from waliya.config import settings
from waliya.db.models import AuditLedgerModel, NotificationDestinationModel
from waliya.db.session import async_session_factory
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
async def test_destinations_api_authentication_required(async_client):
    """Verify unauthorized requests are rejected with 401 or 403."""
    # No auth header -> 401
    resp = await async_client.get("/api/v1/integrations/destinations")
    assert resp.status_code == 401

    # Invalid key -> 403
    resp = await async_client.get(
        "/api/v1/integrations/destinations",
        headers={"X-Admin-Key": "invalid-secret-key"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_destination_success_and_secret_redaction(async_client, admin_headers):
    """Verify destination creation encrypts secret and never discloses it in plaintext."""
    mock_addrinfo = [(None, None, None, None, ("93.184.216.34", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        payload = {
            "name": "SIEM Integration Hook",
            "destination_url": "https://siem.enterprise.gov.et/events",
            "is_enabled": True,
            "subscribed_events": ["INCIDENT_CREATED", "INCIDENT_STATUS_CHANGED"],
            "signing_secret": "my-ultra-secret-key-12345",
        }
        resp = await async_client.post(
            "/api/v1/integrations/destinations",
            json=payload,
            headers=admin_headers,
        )
        assert resp.status_code == 201
        data = resp.json()

        dest_id = data["id"]
        assert data["name"] == "SIEM Integration Hook"
        assert data["destination_url"] == "https://siem.enterprise.gov.et/events"
        assert data["is_enabled"] is True
        assert data["subscribed_events"] == ["INCIDENT_CREATED", "INCIDENT_STATUS_CHANGED"]
        assert data["has_signing_secret"] is True
        # Plaintext secret MUST NEVER be returned
        assert "signing_secret" not in data
        assert "my-ultra-secret-key-12345" not in resp.text

        # Verify DB encrypted persistence
        async with async_session_factory() as session:
            db_res = await session.execute(
                select(NotificationDestinationModel).where(NotificationDestinationModel.id == dest_id)
            )
            db_dest = db_res.scalars().first()
            assert db_dest is not None
            assert db_dest.signing_secret_enc is not None
            assert db_dest.signing_secret_enc != "my-ultra-secret-key-12345"
            assert db_dest.signing_secret_enc.startswith("gAAAAA")

            # Verify audit ledger recorded destination creation
            audit_res = await session.execute(
                select(AuditLedgerModel).where(
                    AuditLedgerModel.action == "NOTIFICATION_DESTINATION_CREATED",
                    AuditLedgerModel.target_entity == str(dest_id),
                )
            )
            audit_entry = audit_res.scalars().first()
            assert audit_entry is not None
            assert "my-ultra-secret-key-12345" not in audit_entry.canonical_payload


@pytest.mark.asyncio
async def test_create_destination_ssrf_rejection(async_client, admin_headers):
    """Verify attempts to configure cloud metadata or prohibited URLs are blocked."""
    # Attempting to configure AWS metadata service
    payload = {
        "name": "Metadata Attack Target",
        "destination_url": "https://169.254.169.254/latest/meta-data",
        "is_enabled": True,
        "subscribed_events": ["*"],
    }
    resp = await async_client.post(
        "/api/v1/integrations/destinations",
        json=payload,
        headers=admin_headers,
    )
    assert resp.status_code == 400
    assert "Invalid destination URL" in resp.json()["detail"]


@pytest.mark.asyncio
async def test_destination_lifecycle_crud(async_client, admin_headers):
    """Verify listing, detail, patching, and deletion of destinations."""
    mock_addrinfo = [(None, None, None, None, ("93.184.216.34", 443))]
    with patch("socket.getaddrinfo", return_value=mock_addrinfo):
        # 1. Create
        create_resp = await async_client.post(
            "/api/v1/integrations/destinations",
            json={
                "name": "Lifecycle Destination",
                "destination_url": "https://soar-hub.internal.corp/alerts",
                "is_enabled": True,
                "subscribed_events": ["INCIDENT_CREATED"],
            },
            headers=admin_headers,
        )
        assert create_resp.status_code == 201
        dest_id = create_resp.json()["id"]

        # 2. Detail
        get_resp = await async_client.get(
            f"/api/v1/integrations/destinations/{dest_id}",
            headers=admin_headers,
        )
        assert get_resp.status_code == 200
        assert get_resp.json()["name"] == "Lifecycle Destination"

        # 3. Patch
        patch_resp = await async_client.patch(
            f"/api/v1/integrations/destinations/{dest_id}",
            json={
                "name": "Updated Destination Name",
                "is_enabled": False,
                "subscribed_events": ["INCIDENT_CREATED", "RESPONSE_PLAN_STATE_CHANGED"],
            },
            headers=admin_headers,
        )
        assert patch_resp.status_code == 200
        patched_data = patch_resp.json()
        assert patched_data["name"] == "Updated Destination Name"
        assert patched_data["is_enabled"] is False
        assert len(patched_data["subscribed_events"]) == 2

        # 4. List contains updated destination
        list_resp = await async_client.get(
            "/api/v1/integrations/destinations",
            headers=admin_headers,
        )
        assert list_resp.status_code == 200
        items = list_resp.json()
        matching = [item for item in items if item["id"] == dest_id]
        assert len(matching) == 1
        assert matching[0]["is_enabled"] is False

        # 5. Delete
        del_resp = await async_client.delete(
            f"/api/v1/integrations/destinations/{dest_id}",
            headers=admin_headers,
        )
        assert del_resp.status_code == 200
        assert del_resp.json()["status"] == "DELETED"

        # 6. Verify 404 after deletion
        get_deleted = await async_client.get(
            f"/api/v1/integrations/destinations/{dest_id}",
            headers=admin_headers,
        )
        assert get_deleted.status_code == 404
