"""Unit tests for cryptographic utilities in waliya.core.crypto."""

import uuid
from datetime import datetime, timedelta, timezone

from waliya.core.crypto import (
    GENESIS_HASH,
    canonicalize_json,
    compute_audit_record_hash,
    compute_command_signature,
    verify_command_signature,
)


def test_canonicalize_json_deterministic():
    """Verify that JSON serialization is deterministic and order-independent."""
    obj1 = {"b": 2, "a": 1, "c": {"y": "val", "x": [3, 2, 1]}}
    obj2 = {"a": 1, "c": {"x": [3, 2, 1], "y": "val"}, "b": 2}

    assert canonicalize_json(obj1) == canonicalize_json(obj2)
    assert canonicalize_json(obj1) == '{"a":1,"b":2,"c":{"x":[3,2,1],"y":"val"}}'


def test_command_signature_generation_and_verification():
    """Verify HMAC-SHA256 signature generation and constant-time verification."""
    cmd_id = uuid.uuid4()
    agent_id = uuid.uuid4()
    nonce = uuid.uuid4()
    now = datetime.now(timezone.utc)
    expires = now + timedelta(seconds=60)
    secret = "test-agent-secret-key-32bytes-hex"

    sig = compute_command_signature(
        command_id=cmd_id,
        agent_id=agent_id,
        action="BLOCK_IP",
        parameters={"ip": "198.51.100.42", "direction": "BOTH"},
        sequence=1,
        nonce=nonce,
        issued_at=now,
        expires_at=expires,
        secret_key=secret,
    )
    assert len(sig) == 64

    # Verification must succeed with identical parameters
    is_valid = verify_command_signature(
        received_signature=sig,
        command_id=cmd_id,
        agent_id=agent_id,
        action="BLOCK_IP",
        parameters={"ip": "198.51.100.42", "direction": "BOTH"},
        sequence=1,
        nonce=nonce,
        issued_at=now,
        expires_at=expires,
        secret_key=secret,
    )
    assert is_valid is True

    # Verification must fail if parameters are tampered with
    tampered_valid = verify_command_signature(
        received_signature=sig,
        command_id=cmd_id,
        agent_id=agent_id,
        action="BLOCK_IP",
        parameters={"ip": "198.51.100.43", "direction": "BOTH"},  # Tampered IP!
        sequence=1,
        nonce=nonce,
        issued_at=now,
        expires_at=expires,
        secret_key=secret,
    )
    assert tampered_valid is False

    # Verification must fail if secret key is incorrect
    wrong_key_valid = verify_command_signature(
        received_signature=sig,
        command_id=cmd_id,
        agent_id=agent_id,
        action="BLOCK_IP",
        parameters={"ip": "198.51.100.42", "direction": "BOTH"},
        sequence=1,
        nonce=nonce,
        issued_at=now,
        expires_at=expires,
        secret_key="wrong-secret-key",
    )
    assert wrong_key_valid is False


def test_audit_record_hash_chaining():
    """Verify SHA-256 hash chaining across consecutive audit ledger records."""
    t0 = datetime(2026, 10, 22, 12, 0, 0, tzinfo=timezone.utc)
    t1 = t0 + timedelta(seconds=10)

    # Record 0 (Genesis to 1)
    rec1_id = uuid.uuid4()
    hash1 = compute_audit_record_hash(
        previous_hash=GENESIS_HASH,
        sequence_number=1,
        record_id=rec1_id,
        timestamp=t0,
        actor_id="admin_1",
        action="REGISTER_AGENT",
        target_entity="Agent:srv-1",
        canonical_payload='{"hostname":"srv-1"}',
    )
    assert len(hash1) == 64

    # Record 1 to 2
    rec2_id = uuid.uuid4()
    hash2 = compute_audit_record_hash(
        previous_hash=hash1,
        sequence_number=2,
        record_id=rec2_id,
        timestamp=t1,
        actor_id="analyst_bob",
        action="APPROVE_RESPONSE",
        target_entity="Incident:10",
        canonical_payload='{"action":"BLOCK_IP"}',
    )
    assert len(hash2) == 64
    assert hash1 != hash2

    # Tampering test: if record 1 payload was retroactively modified, hash1 changes, breaking record 2
    tampered_hash1 = compute_audit_record_hash(
        previous_hash=GENESIS_HASH,
        sequence_number=1,
        record_id=rec1_id,
        timestamp=t0,
        actor_id="admin_1",
        action="REGISTER_AGENT",
        target_entity="Agent:srv-1",
        canonical_payload='{"hostname":"srv-1-tampered"}',
    )
    assert tampered_hash1 != hash1
