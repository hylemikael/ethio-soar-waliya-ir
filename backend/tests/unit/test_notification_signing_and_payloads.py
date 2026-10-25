"""Unit tests for notification payload contracts, data minimization, and HMAC signing."""

from datetime import datetime, timezone
from uuid import UUID, uuid4
import json

from waliya.core.crypto import canonicalize_json
from waliya.integrations.payloads import (
    NotificationEventType,
    NotificationPayload,
    build_detection_finding_created_payload,
    build_incident_created_payload,
    build_incident_status_changed_payload,
    build_response_plan_state_changed_payload,
    build_test_notification_payload,
    build_threat_intel_matched_payload,
)
from waliya.integrations.signing import (
    build_signed_headers,
    compute_notification_signature,
    decrypt_destination_secret,
    encrypt_destination_secret,
    verify_notification_signature,
)


def test_secret_encryption_at_rest():
    """Verify destination signing secrets are encrypted with Fernet and decrypted accurately."""
    raw_secret = "super-secret-webhook-key-12345"
    encrypted = encrypt_destination_secret(raw_secret)
    assert encrypted != raw_secret
    assert encrypted.startswith("gAAAAA")  # Fernet token prefix

    decrypted = decrypt_destination_secret(encrypted)
    assert decrypted == raw_secret


def test_hmac_sha256_signature_and_verification():
    """Verify HMAC-SHA256 signature calculation and constant-time verification."""
    secret = "my-test-signing-secret"
    payload = {"message": "hello", "count": 42}
    canonical_bytes = canonicalize_json(payload).encode("utf-8")

    sig = compute_notification_signature(secret, canonical_bytes)
    assert isinstance(sig, str)
    assert len(sig) == 64  # SHA-256 hex length

    # Exact verification succeeds
    assert verify_notification_signature(secret, canonical_bytes, sig) is True

    # 'sha256=' prefix format also accepted
    assert verify_notification_signature(secret, canonical_bytes, f"sha256={sig}") is True

    # Tampered payload fails verification
    tampered_bytes = canonicalize_json({"message": "tampered", "count": 42}).encode("utf-8")
    assert verify_notification_signature(secret, tampered_bytes, sig) is False

    # Wrong secret fails verification
    assert verify_notification_signature("wrong-secret", canonical_bytes, sig) is False


def test_build_signed_headers():
    """Verify formatted outbound headers match specification."""
    raw_secret = "production-webhook-secret-999"
    secret_enc = encrypt_destination_secret(raw_secret)
    delivery_id = uuid4()
    now_utc = datetime.now(timezone.utc)
    payload_dict = {"event": "test", "data": 123}

    headers, canonical_bytes = build_signed_headers(
        delivery_id=delivery_id,
        event_type=NotificationEventType.INCIDENT_CREATED.value,
        timestamp=now_utc,
        payload_dict=payload_dict,
        secret_ciphertext=secret_enc,
    )

    assert headers["Content-Type"] == "application/json"
    assert headers["User-Agent"] == "Waliya-IR-Notifier/2.0"
    assert headers["X-Waliya-Delivery-Id"] == str(delivery_id)
    assert headers["X-Waliya-Event-Type"] == "INCIDENT_CREATED"
    assert headers["X-Waliya-Timestamp"] == now_utc.isoformat()
    assert "X-Waliya-Signature" in headers

    # Verify signature in header matches canonical bytes
    assert verify_notification_signature(raw_secret, canonical_bytes, headers["X-Waliya-Signature"]) is True


def test_incident_created_payload_data_minimization():
    """Verify incident created payload excludes raw telemetry and includes minimized metadata."""
    inc_id = uuid4()
    now = datetime.now(timezone.utc)
    entities = ["192.168.1.100", "user:admin", "process:mimikatz.exe", "host:srv01"]

    payload = build_incident_created_payload(
        incident_id=inc_id,
        title="Credential Dumping Alert",
        severity="HIGH",
        composite_risk_score=78.5,
        status="OPEN",
        first_seen=now,
        last_seen=now,
        affected_entities=entities,
        mitre_attack_ids=["T1003"],
    )

    p_dict = payload.model_dump(mode="json")
    assert p_dict["schema_version"] == "1.0"
    assert p_dict["event_type"] == "INCIDENT_CREATED"
    assert p_dict["incident_id"] == str(inc_id)
    assert p_dict["severity"] == "HIGH"
    assert "details" in p_dict
    assert p_dict["details"]["risk_score"] == 78.5
    assert p_dict["details"]["entity_count"] == 4
    # Ensure raw event dumps or tokens are NOT present
    assert "telemetry" not in p_dict
    assert "raw_events" not in p_dict
    assert "api_token" not in p_dict


def test_test_notification_payload():
    """Verify test notifications are explicitly flagged as test events."""
    dest_id = uuid4()
    payload = build_test_notification_payload(
        destination_id=dest_id,
        destination_name="Security SIEM Webhook",
    )

    assert payload.is_test is True
    assert payload.event_type == NotificationEventType.TEST_NOTIFICATION.value
    assert "connectivity verified" in payload.details["test_message"].lower()
