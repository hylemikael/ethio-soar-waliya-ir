"""Cryptographic signature generation and verification for agent C2 command channel."""

import hashlib
import hmac
import json
from datetime import datetime, timezone
from typing import Any, Dict
from uuid import UUID


def canonicalize_json(data: Any) -> str:
    """Serialize data into a deterministic, canonical JSON string matching backend format."""
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
    """Verify HMAC-SHA256 command signature using constant-time comparison."""
    if not received_signature or len(received_signature) != 64:
        return False

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

    return hmac.compare_digest(expected_signature.lower(), received_signature.lower())
