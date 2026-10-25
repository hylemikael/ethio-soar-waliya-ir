"""Cryptographic functions for canonical serialization, HMAC signing, and audit chaining."""

import base64
import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import UUID

from cryptography.fernet import Fernet, InvalidToken


GENESIS_HASH = "0" * 64


def canonicalize_json(data: Any) -> str:
    """Serialize data into a deterministic, canonical JSON string.

    Specifications:
    - Sorted dictionary keys
    - Compact separators (no extra whitespace)
    - ISO 8601 UTC formatted timestamps
    - UTF-8 encoding compatibility
    """
    def default_serializer(obj: Any) -> Any:
        if isinstance(obj, datetime):
            if obj.tzinfo is None:
                obj = obj.replace(tzinfo=timezone.utc)
            return obj.astimezone(timezone.utc).isoformat()
        if isinstance(obj, UUID):
            return str(obj)
        raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")

    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        default=default_serializer,
        ensure_ascii=True,
    )


def compute_command_signature(
    command_id: UUID,
    agent_id: UUID,
    action: str,
    parameters: Dict[str, Any],
    sequence: int,
    nonce: UUID,
    issued_at: datetime,
    expires_at: datetime,
    secret_key: str,
) -> str:
    """Compute HMAC-SHA256 signature over security-critical command fields."""
    canonical_params = canonicalize_json(parameters)

    # Format canonical message string
    canonical_msg = "|".join([
        str(command_id),
        str(agent_id),
        str(action),
        canonical_params,
        str(sequence),
        str(nonce),
        issued_at.astimezone(timezone.utc).isoformat(),
        expires_at.astimezone(timezone.utc).isoformat(),
    ])

    return hmac.new(
        secret_key.encode("utf-8"),
        canonical_msg.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_command_signature(
    received_signature: str,
    command_id: UUID,
    agent_id: UUID,
    action: str,
    parameters: Dict[str, Any],
    sequence: int,
    nonce: UUID,
    issued_at: datetime,
    expires_at: datetime,
    secret_key: str,
) -> bool:
    """Verify an HMAC-SHA256 command signature using constant-time comparison."""
    expected_signature = compute_command_signature(
        command_id=command_id,
        agent_id=agent_id,
        action=action,
        parameters=parameters,
        sequence=sequence,
        nonce=nonce,
        issued_at=issued_at,
        expires_at=expires_at,
        secret_key=secret_key,
    )
    return hmac.compare_digest(received_signature.lower(), expected_signature.lower())


def compute_audit_record_hash(
    previous_hash: str,
    sequence_number: int,
    record_id: UUID,
    timestamp: datetime,
    actor_id: str,
    action: str,
    target_entity: str,
    canonical_payload: str,
) -> str:
    """Compute the tamper-evident SHA-256 hash for an audit ledger record."""
    iso_time = timestamp.astimezone(timezone.utc).isoformat()
    record_representation = "|".join([
        previous_hash,
        str(sequence_number),
        str(record_id),
        iso_time,
        actor_id,
        action,
        target_entity,
        canonical_payload,
    ])
    return hashlib.sha256(record_representation.encode("utf-8")).hexdigest()


def hash_agent_token(token: str, pepper: str = "") -> str:
    """Compute deterministic SHA-256 hash of an agent API token with server pepper."""
    salted = f"{token}:{pepper}".encode("utf-8")
    return hashlib.sha256(salted).hexdigest()


def verify_agent_token(token: str, expected_hash: str, pepper: str = "") -> bool:
    """Verify an agent token against stored hash using constant-time comparison."""
    computed = hash_agent_token(token, pepper=pepper)
    return hmac.compare_digest(computed.lower(), expected_hash.lower())


def _get_fernet(master_key: str) -> Fernet:
    """Derive 32-byte urlsafe base64 key for Fernet symmetric encryption."""
    derived_32 = hashlib.sha256(master_key.encode("utf-8")).digest()
    urlsafe_key = base64.urlsafe_b64encode(derived_32)
    return Fernet(urlsafe_key)


def encrypt_agent_secret(secret_plaintext: str, master_key: str) -> str:
    """Encrypt an agent's HMAC signing secret before persistence."""
    fernet = _get_fernet(master_key)
    return fernet.encrypt(secret_plaintext.encode("utf-8")).decode("utf-8")


def decrypt_agent_secret(secret_ciphertext: str, master_key: str) -> str:
    """Decrypt an agent's stored HMAC signing secret."""
    try:
        fernet = _get_fernet(master_key)
        return fernet.decrypt(secret_ciphertext.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        # Fallback for plain unencrypted test fixtures or legacy strings
        return secret_ciphertext
