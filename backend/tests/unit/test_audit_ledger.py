"""Unit tests for the tamper-evident cryptographic audit ledger service."""

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4
import pytest

from waliya.audit.ledger_service import AuditLedgerService
from waliya.contracts import AuditVerificationResponse
from waliya.core.crypto import GENESIS_HASH, compute_audit_record_hash
from waliya.db.models import AuditLedgerModel


@pytest.mark.asyncio
async def test_audit_ledger_record_hash_chaining():
    """Verify sequential records correctly link previous_hash to prior current_hash."""
    session = AsyncMock()

    # In-memory storage simulating database
    chain = []

    def mock_add(record):
        chain.append(record)

    session.add = mock_add

    # Record 1 (Genesis link)
    mock_res_empty = MagicMock()
    mock_res_empty.scalars.return_value.first.return_value = None
    session.execute.return_value = mock_res_empty

    rec1 = await AuditLedgerService.record_action(
        session=session,
        actor_id="analyst_alice",
        action="INCIDENT_STATUS_CHANGED",
        target_entity="incident:123",
        payload={"from": "OPEN", "to": "INVESTIGATING"},
    )
    assert rec1.sequence_number == 1
    assert rec1.previous_hash == GENESIS_HASH
    assert len(rec1.current_hash) == 64

    # Record 2 (Chained to Record 1)
    mock_res_rec1 = MagicMock()
    mock_res_rec1.scalars.return_value.first.return_value = rec1
    session.execute.return_value = mock_res_rec1

    rec2 = await AuditLedgerService.record_action(
        session=session,
        actor_id="analyst_bob",
        action="RESPONSE_ACTION_APPROVED",
        target_entity="command:456",
        payload={"action": "BLOCK_IP", "ip": "1.2.3.4"},
    )
    assert rec2.sequence_number == 2
    assert rec2.previous_hash == rec1.current_hash
    assert rec2.current_hash != rec1.current_hash


@pytest.mark.asyncio
async def test_audit_chain_verification_clean():
    """Verify verify_chain returns True on an untampered audit chain."""
    session = AsyncMock()

    # Construct clean 3-record chain
    t1 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 22, 10, 5, 0, tzinfo=timezone.utc)

    id1, id2 = uuid4(), uuid4()
    p1 = '{"status":"OPEN"}'
    p2 = '{"status":"CONTAINED"}'

    h1 = compute_audit_record_hash(GENESIS_HASH, 1, id1, t1, "admin", "CREATE", "inc:1", p1)
    rec1 = AuditLedgerModel(
        sequence_number=1, id=id1, timestamp=t1, actor_id="admin", actor_role="ADMIN",
        action="CREATE", target_entity="inc:1", canonical_payload=p1,
        previous_hash=GENESIS_HASH, current_hash=h1,
    )

    h2 = compute_audit_record_hash(h1, 2, id2, t2, "admin", "UPDATE", "inc:1", p2)
    rec2 = AuditLedgerModel(
        sequence_number=2, id=id2, timestamp=t2, actor_id="admin", actor_role="ADMIN",
        action="UPDATE", target_entity="inc:1", canonical_payload=p2,
        previous_hash=h1, current_hash=h2,
    )

    mock_res = MagicMock()
    mock_res.scalars.return_value.all.return_value = [rec1, rec2]
    session.execute.return_value = mock_res

    res = await AuditLedgerService.verify_chain(session)
    assert res.verified is True
    assert res.total_records == 2
    assert res.tamper_detected is False
    assert res.latest_hash == h2


@pytest.mark.asyncio
async def test_audit_chain_tamper_detection():
    """Verify tampering with a payload or hash link is immediately detected."""
    session = AsyncMock()

    t1 = datetime(2026, 10, 22, 10, 0, 0, tzinfo=timezone.utc)
    id1 = uuid4()
    p1 = '{"status":"OPEN"}'

    h1 = compute_audit_record_hash(GENESIS_HASH, 1, id1, t1, "admin", "CREATE", "inc:1", p1)
    rec1 = AuditLedgerModel(
        sequence_number=1, id=id1, timestamp=t1, actor_id="admin", actor_role="ADMIN",
        action="CREATE", target_entity="inc:1", canonical_payload=p1,
        previous_hash=GENESIS_HASH, current_hash=h1,
    )

    # Malicious actor modified the payload of rec1 without knowing the secret / valid hash
    rec1_tampered = AuditLedgerModel(
        sequence_number=1, id=id1, timestamp=t1, actor_id="admin", actor_role="ADMIN",
        action="CREATE", target_entity="inc:1",
        canonical_payload='{"status":"TAMPERED_VALUE"}',  # Tampered!
        previous_hash=GENESIS_HASH, current_hash=h1,
    )

    mock_res = MagicMock()
    mock_res.scalars.return_value.all.return_value = [rec1_tampered]
    session.execute.return_value = mock_res

    res = await AuditLedgerService.verify_chain(session)
    assert res.verified is False
    assert res.tamper_detected is True
    assert res.broken_sequence == 1
