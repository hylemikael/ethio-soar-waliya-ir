"""Integration tests for inbound security event sources management API."""

from uuid import uuid4
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy import select

from waliya.config import settings
from waliya.db.models import AuditLedgerModel, InboundSourceModel
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
async def test_inbound_sources_api_auth_required(async_client):
    """Verify inbound source management requires valid administrator credentials."""
    # Missing auth -> 401
    resp = await async_client.get("/api/v1/integrations/sources")
    assert resp.status_code == 401

    # Invalid admin key -> 403
    resp = await async_client.get(
        "/api/v1/integrations/sources",
        headers={"X-Admin-Key": "invalid-admin-key"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_create_inbound_source_crud_and_audit(async_client, admin_headers):
    """Verify source registration, secret encryption, secret redaction, update, and deletion."""
    unique_slug = f"edr-crowdstrike-{uuid4().hex[:6]}"
    create_payload = {
        "source_id": unique_slug,
        "name": "Production CrowdStrike EDR",
        "provider_type": "EDR",
        "is_enabled": True,
        "auth_type": "HMAC_SHA256",
        "shared_secret": "my-ultra-secure-inbound-secret-key-32chars",
        "permitted_event_types": ["EXTERNAL_ALERT", "PROCESS_EXECUTION"],
    }

    # 1. Register Source
    resp = await async_client.post(
        "/api/v1/integrations/sources",
        json=create_payload,
        headers=admin_headers,
    )
    assert resp.status_code == 201
    created_data = resp.json()
    assert created_data["source_id"] == unique_slug
    assert created_data["provider_type"] == "EDR"
    assert created_data["is_enabled"] is True
    assert created_data["has_shared_secret"] is True
    assert "shared_secret" not in created_data
    assert "shared_secret_enc" not in created_data
    source_uuid = created_data["id"]

    # 2. Check Database and Audit Ledger
    async with async_session_factory() as session:
        # DB check: secret is encrypted
        db_source = await session.get(InboundSourceModel, source_uuid)
        assert db_source is not None
        assert db_source.shared_secret_enc != "my-ultra-secure-inbound-secret-key-32chars"

        # Audit ledger check
        audit_query = select(AuditLedgerModel).where(
            AuditLedgerModel.action == "INBOUND_SOURCE_CREATED",
            AuditLedgerModel.target_entity == f"source:{unique_slug}",
        )
        audit_res = await session.execute(audit_query)
        audit_entry = audit_res.scalars().first()
        assert audit_entry is not None
        assert "EDR" in audit_entry.canonical_payload

    # 3. Duplicate slug rejection (409 Conflict)
    resp_dup = await async_client.post(
        "/api/v1/integrations/sources",
        json=create_payload,
        headers=admin_headers,
    )
    assert resp_dup.status_code == 409
    assert "already exists" in resp_dup.json()["detail"]

    # 4. List sources
    resp_list = await async_client.get(
        "/api/v1/integrations/sources",
        headers=admin_headers,
    )
    assert resp_list.status_code == 200
    sources_list = resp_list.json()
    matching = [s for s in sources_list if s["source_id"] == unique_slug]
    assert len(matching) == 1
    assert matching[0]["has_shared_secret"] is True

    # 5. Get source by slug and by UUID
    resp_get_slug = await async_client.get(
        f"/api/v1/integrations/sources/{unique_slug}",
        headers=admin_headers,
    )
    assert resp_get_slug.status_code == 200
    assert resp_get_slug.json()["id"] == source_uuid

    resp_get_uuid = await async_client.get(
        f"/api/v1/integrations/sources/{source_uuid}",
        headers=admin_headers,
    )
    assert resp_get_uuid.status_code == 200
    assert resp_get_uuid.json()["source_id"] == unique_slug

    # 6. Update source (disable it and update permitted types)
    update_payload = {
        "is_enabled": False,
        "permitted_event_types": ["EXTERNAL_ALERT"],
    }
    resp_update = await async_client.patch(
        f"/api/v1/integrations/sources/{unique_slug}",
        json=update_payload,
        headers=admin_headers,
    )
    assert resp_update.status_code == 200
    assert resp_update.json()["is_enabled"] is False
    assert resp_update.json()["permitted_event_types"] == ["EXTERNAL_ALERT"]

    # 7. Delete source
    resp_delete = await async_client.delete(
        f"/api/v1/integrations/sources/{unique_slug}",
        headers=admin_headers,
    )
    assert resp_delete.status_code == 200
    assert resp_delete.json()["status"] == "DELETED"

    # Confirm 404
    resp_after = await async_client.get(
        f"/api/v1/integrations/sources/{unique_slug}",
        headers=admin_headers,
    )
    assert resp_after.status_code == 404
