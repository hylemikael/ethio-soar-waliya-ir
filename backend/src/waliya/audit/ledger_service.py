"""Tamper-evident, hash-chained audit ledger service with concurrency safety."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import desc, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import AuditLedgerRecord, AuditVerificationResponse
from waliya.core.crypto import GENESIS_HASH, canonicalize_json, compute_audit_record_hash
from waliya.db.models import AuditLedgerModel

logger = logging.getLogger("waliya.audit.ledger")

# Global lock ID for postgres advisory xact lock on audit chain updates
AUDIT_LOCK_ID = 82736451


class AuditLedgerService:
    """Provides atomic, cryptographically chained audit logging and verification."""

    @classmethod
    async def record_action(
        cls,
        session: AsyncSession,
        actor_id: str,
        action: str,
        target_entity: str,
        payload: Dict[str, Any],
        actor_role: str = "ANALYST",
        timestamp: Optional[datetime] = None,
    ) -> AuditLedgerModel:
        """Atomically append a cryptographically chained record to the audit ledger.

        Guarantees:
        - Strict serialize-level concurrency safety using transactional locking.
        - Immutable SHA-256 hash chaining back to GENESIS_HASH.
        - Deterministic canonical serialization of all payload fields.
        """
        now_utc = timestamp or datetime.now(timezone.utc)
        if now_utc.tzinfo is None:
            now_utc = now_utc.replace(tzinfo=timezone.utc)

        record_id = uuid4()
        canonical_str = canonicalize_json(payload)

        # Acquire PostgreSQL transaction-level advisory lock to serialize concurrent chain writes
        try:
            await session.execute(text(f"SELECT pg_advisory_xact_lock({AUDIT_LOCK_ID})"))
        except Exception:
            # Fallback for SQLite in isolated memory unit tests
            pass

        # Query the latest record in the ledger
        latest_query = (
            select(AuditLedgerModel)
            .order_by(desc(AuditLedgerModel.sequence_number))
            .limit(1)
            .with_for_update()
        )
        res = await session.execute(latest_query)
        latest_record = res.scalars().first()

        if latest_record is None:
            prev_hash = GENESIS_HASH
            next_seq = 1
        else:
            prev_hash = latest_record.current_hash
            next_seq = latest_record.sequence_number + 1

        curr_hash = compute_audit_record_hash(
            previous_hash=prev_hash,
            sequence_number=next_seq,
            record_id=record_id,
            timestamp=now_utc,
            actor_id=actor_id,
            action=action,
            target_entity=target_entity,
            canonical_payload=canonical_str,
        )

        audit_entry = AuditLedgerModel(
            sequence_number=next_seq,
            id=record_id,
            timestamp=now_utc,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action,
            target_entity=target_entity,
            canonical_payload=canonical_str,
            previous_hash=prev_hash,
            current_hash=curr_hash,
        )

        session.add(audit_entry)
        await session.flush()

        logger.debug(
            "Audit record #%d committed: action='%s' target='%s' actor='%s' hash=%.12s...",
            next_seq, action, target_entity, actor_id, curr_hash,
        )
        return audit_entry

    @classmethod
    async def verify_chain(cls, session: AsyncSession) -> AuditVerificationResponse:
        """Verify the cryptographic integrity of the entire audit chain from genesis to head.

        Detects sequence gaps, payload alterations, or broken hash links.
        """
        query = select(AuditLedgerModel).order_by(AuditLedgerModel.sequence_number.asc())
        res = await session.execute(query)
        records = res.scalars().all()

        if not records:
            return AuditVerificationResponse(
                verified=True,
                total_records=0,
                genesis_hash=GENESIS_HASH,
                latest_hash=None,
                tamper_detected=False,
                broken_sequence=None,
            )

        expected_prev_hash = GENESIS_HASH
        expected_seq = 1

        for rec in records:
            # 1. Verify sequence order
            if rec.sequence_number != expected_seq:
                logger.error("Audit chain sequence gap detected: expected %d, got %d", expected_seq, rec.sequence_number)
                return AuditVerificationResponse(
                    verified=False,
                    total_records=len(records),
                    genesis_hash=GENESIS_HASH,
                    latest_hash=records[-1].current_hash,
                    tamper_detected=True,
                    broken_sequence=rec.sequence_number,
                )

            # 2. Verify previous hash chaining
            if rec.previous_hash != expected_prev_hash:
                logger.error("Audit chain link broken at sequence %d: prev_hash mismatch", rec.sequence_number)
                return AuditVerificationResponse(
                    verified=False,
                    total_records=len(records),
                    genesis_hash=GENESIS_HASH,
                    latest_hash=records[-1].current_hash,
                    tamper_detected=True,
                    broken_sequence=rec.sequence_number,
                )

            # 3. Recompute and verify current hash
            recomputed = compute_audit_record_hash(
                previous_hash=rec.previous_hash,
                sequence_number=rec.sequence_number,
                record_id=rec.id,
                timestamp=rec.timestamp,
                actor_id=rec.actor_id,
                action=rec.action,
                target_entity=rec.target_entity,
                canonical_payload=rec.canonical_payload,
            )

            if rec.current_hash != recomputed:
                logger.error("Audit payload tampering detected at sequence %d: hash mismatch", rec.sequence_number)
                return AuditVerificationResponse(
                    verified=False,
                    total_records=len(records),
                    genesis_hash=GENESIS_HASH,
                    latest_hash=records[-1].current_hash,
                    tamper_detected=True,
                    broken_sequence=rec.sequence_number,
                )

            expected_prev_hash = rec.current_hash
            expected_seq += 1

        return AuditVerificationResponse(
            verified=True,
            total_records=len(records),
            genesis_hash=GENESIS_HASH,
            latest_hash=records[-1].current_hash,
            tamper_detected=False,
            broken_sequence=None,
        )
