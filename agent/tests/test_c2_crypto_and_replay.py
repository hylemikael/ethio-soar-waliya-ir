"""Tests for C2 HMAC-SHA256 signature verification and replay defense."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import UUID, uuid4

import pytest

from waliya_agent.c2.crypto import (
    canonicalize_json,
    compute_command_signature,
    verify_command_signature,
)
from waliya_agent.c2.replay import ReplayDefenseStore


def test_canonicalize_json_deterministic():
    """Verify deterministic formatting of nested JSON structures."""
    data1 = {"b": 2, "a": 1, "nested": {"z": True, "m": None}}
    data2 = {"a": 1, "nested": {"m": None, "z": True}, "b": 2}
    assert canonicalize_json(data1) == canonicalize_json(data2)
    assert canonicalize_json(data1) == '{"a":1,"b":2,"nested":{"m":null,"z":true}}'


def test_command_signature_generation_and_verification(mock_agent_id: UUID, mock_signing_secret: str):
    """Verify that valid HMAC-SHA256 signatures pass and tampered ones fail."""
    command_id = uuid4()
    action = "BLOCK_IP"
    parameters = {"ip_address": "198.51.100.88", "direction": "BOTH"}
    sequence = 1
    nonce = uuid4()
    now_utc = datetime.now(timezone.utc)
    expires_at = now_utc + timedelta(minutes=5)

    sig = compute_command_signature(
        command_id=command_id,
        agent_id=mock_agent_id,
        action=action,
        parameters=parameters,
        sequence=sequence,
        nonce=nonce,
        issued_at=now_utc,
        expires_at=expires_at,
        secret_key=mock_signing_secret,
    )

    # 1. Verification succeeds with identical inputs
    assert verify_command_signature(
        received_signature=sig,
        command_id=command_id,
        agent_id=mock_agent_id,
        action=action,
        parameters=parameters,
        sequence=sequence,
        nonce=nonce,
        issued_at=now_utc,
        expires_at=expires_at,
        secret_key=mock_signing_secret,
    ) is True

    # 2. Tampering parameter fails
    tampered_params = {"ip_address": "198.51.100.99", "direction": "BOTH"}
    assert verify_command_signature(
        received_signature=sig,
        command_id=command_id,
        agent_id=mock_agent_id,
        action=action,
        parameters=tampered_params,
        sequence=sequence,
        nonce=nonce,
        issued_at=now_utc,
        expires_at=expires_at,
        secret_key=mock_signing_secret,
    ) is False

    # 3. Wrong secret key fails
    assert verify_command_signature(
        received_signature=sig,
        command_id=command_id,
        agent_id=mock_agent_id,
        action=action,
        parameters=parameters,
        sequence=sequence,
        nonce=nonce,
        issued_at=now_utc,
        expires_at=expires_at,
        secret_key="wrong-secret-key-1234567890",
    ) is False


def test_replay_defense_monotonic_sequence(temp_dir: Path):
    """Verify that command sequences must be strictly monotonically increasing."""
    db_file = temp_dir / "replay.db"
    store = ReplayDefenseStore(db_path=db_file)

    now = datetime.now(timezone.utc)
    future = now + timedelta(minutes=5)

    # 1. First command (seq 1) -> accepted
    valid, _ = store.validate_and_record_command(
        sequence=1,
        nonce=uuid4(),
        command_id=uuid4(),
        expires_at=future,
    )
    assert valid is True
    assert store.get_highest_sequence() == 1

    # 2. Duplicate sequence 1 -> rejected
    valid, reason = store.validate_and_record_command(
        sequence=1,
        nonce=uuid4(),
        command_id=uuid4(),
        expires_at=future,
    )
    assert valid is False
    assert "replay detected" in reason

    # 3. Lower sequence 0 -> rejected
    valid, reason = store.validate_and_record_command(
        sequence=0,
        nonce=uuid4(),
        command_id=uuid4(),
        expires_at=future,
    )
    assert valid is False

    # 4. Next sequence 2 -> accepted
    valid, _ = store.validate_and_record_command(
        sequence=2,
        nonce=uuid4(),
        command_id=uuid4(),
        expires_at=future,
    )
    assert valid is True
    assert store.get_highest_sequence() == 2


def test_replay_defense_duplicate_nonce_and_expiry(temp_dir: Path):
    """Verify rejection of duplicate nonces and expired commands."""
    db_file = temp_dir / "replay.db"
    store = ReplayDefenseStore(db_path=db_file)

    now = datetime.now(timezone.utc)
    past = now - timedelta(seconds=10)
    future = now + timedelta(minutes=5)

    # 1. Expired command -> rejected immediately
    valid, reason = store.validate_and_record_command(
        sequence=1,
        nonce=uuid4(),
        command_id=uuid4(),
        expires_at=past,
    )
    assert valid is False
    assert "expired" in reason

    # 2. Replayed nonce with higher sequence -> rejected
    same_nonce = uuid4()
    valid, _ = store.validate_and_record_command(
        sequence=1,
        nonce=same_nonce,
        command_id=uuid4(),
        expires_at=future,
    )
    assert valid is True

    valid, reason = store.validate_and_record_command(
        sequence=2,
        nonce=same_nonce,
        command_id=uuid4(),
        expires_at=future,
    )
    assert valid is False
    assert "replay attack detected" in reason


def test_replay_defense_persistence_across_restarts(temp_dir: Path):
    """Verify that highest sequence is persisted across process restarts."""
    db_file = temp_dir / "replay.db"
    store1 = ReplayDefenseStore(db_path=db_file)

    future = datetime.now(timezone.utc) + timedelta(minutes=5)
    store1.validate_and_record_command(sequence=42, nonce=uuid4(), command_id=uuid4(), expires_at=future)
    assert store1.get_highest_sequence() == 42

    # Reopen with new instance
    store2 = ReplayDefenseStore(db_path=db_file)
    assert store2.get_highest_sequence() == 42

    # Any sequence <= 42 must be rejected
    valid, _ = store2.validate_and_record_command(sequence=42, nonce=uuid4(), command_id=uuid4(), expires_at=future)
    assert valid is False
