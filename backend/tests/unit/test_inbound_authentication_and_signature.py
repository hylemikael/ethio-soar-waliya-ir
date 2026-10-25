"""Unit tests for inbound external event authentication, HMAC-SHA256 signatures, and freshness windows."""

from datetime import datetime, timedelta, timezone
import json
from uuid import uuid4

import pytest
from fastapi import HTTPException

from waliya.contracts import InboundSourceCreate, InboundSourceResponse
from waliya.db.models import InboundSourceModel
from waliya.integrations.inbound_service import InboundIngestionService, MAX_TIMESTAMP_DRIFT_SECONDS
from waliya.integrations.signing import (
    compute_notification_signature,
    decrypt_destination_secret,
    encrypt_destination_secret,
    verify_notification_signature,
)


@pytest.mark.unit
def test_inbound_secret_encryption_roundtrip():
    """Verify shared secrets are encrypted and decrypted accurately using platform key."""
    plaintext_secret = "super-secret-hmac-key-1234567890"
    encrypted = encrypt_destination_secret(plaintext_secret)
    assert encrypted != plaintext_secret
    assert len(encrypted) > len(plaintext_secret)

    decrypted = decrypt_destination_secret(encrypted)
    assert decrypted == plaintext_secret


@pytest.mark.unit
def test_hmac_signature_generation_and_verification():
    """Verify HMAC-SHA256 calculation over raw bytes with constant-time verification."""
    secret = "test-shared-secret-32-chars-long"
    payload = json.dumps({"external_event_id": "evt-123", "severity": "HIGH"}).encode("utf-8")

    sig = compute_notification_signature(secret, payload)
    assert isinstance(sig, str)
    assert len(sig) == 64

    # Direct match
    assert verify_notification_signature(secret, payload, sig) is True

    # With sha256= prefix
    assert verify_notification_signature(secret, payload, f"sha256={sig}") is True

    # Uppercase hex
    assert verify_notification_signature(secret, payload, sig.upper()) is True

    # Corrupted signature
    bad_sig = "a" * 64
    assert verify_notification_signature(secret, payload, bad_sig) is False

    # Tampered payload bytes
    tampered_payload = json.dumps({"external_event_id": "evt-123", "severity": "CRITICAL"}).encode("utf-8")
    assert verify_notification_signature(secret, tampered_payload, sig) is False


@pytest.mark.unit
def test_timestamp_freshness_window_parser():
    """Verify parser accepts ISO-8601 strings, Zulu times, and numeric epoch timestamps."""
    service = InboundIngestionService()

    now_utc = datetime.now(timezone.utc)
    iso_z = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")
    parsed_z = service._parse_header_timestamp(iso_z)
    assert parsed_z.tzinfo is not None
    assert abs((now_utc - parsed_z).total_seconds()) < 2.0

    epoch_sec = str(now_utc.timestamp())
    parsed_sec = service._parse_header_timestamp(epoch_sec)
    assert abs((now_utc - parsed_sec).total_seconds()) < 2.0

    epoch_ms = str(now_utc.timestamp() * 1000.0)
    parsed_ms = service._parse_header_timestamp(epoch_ms)
    assert abs((now_utc - parsed_ms).total_seconds()) < 2.0

    # Malformed timestamp raises 400 Bad Request
    with pytest.raises(HTTPException) as exc_info:
        service._parse_header_timestamp("not-a-valid-timestamp")
    assert exc_info.value.status_code == 400


@pytest.mark.unit
def test_secret_redaction_in_contracts():
    """Verify contracts never expose plaintext secrets in responses."""
    source_create = InboundSourceCreate(
        source_id="test-slug",
        name="Test Inbound Source",
        provider_type="GENERIC",
        shared_secret="secret-key-16-characters-min",
    )
    assert source_create.shared_secret == "secret-key-16-characters-min"

    # InboundSourceResponse only has boolean has_shared_secret
    response = InboundSourceResponse(
        id=uuid4(),
        source_id="test-slug",
        name="Test Inbound Source",
        provider_type="GENERIC",
        is_enabled=True,
        auth_type="HMAC_SHA256",
        has_shared_secret=True,
        permitted_event_types=["EXTERNAL_ALERT"],
        total_events_received=0,
        total_events_accepted=0,
        total_events_rejected=0,
        total_events_deduplicated=0,
        created_by="admin",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
    )
    data = response.model_dump()
    assert "shared_secret" not in data
    assert "shared_secret_enc" not in data
    assert data["has_shared_secret"] is True
