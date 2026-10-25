"""Cryptographic signing and verification utilities for outbound webhook notifications."""

import hashlib
import hmac
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from uuid import UUID

from waliya.config import settings
from waliya.core.crypto import canonicalize_json, decrypt_agent_secret, encrypt_agent_secret


def encrypt_destination_secret(secret_plaintext: str) -> str:
    """Encrypt a destination's webhook signing secret using master platform key."""
    return encrypt_agent_secret(secret_plaintext, master_key=settings.SECRET_KEY)


def decrypt_destination_secret(secret_ciphertext: str) -> str:
    """Decrypt a destination's stored webhook signing secret."""
    return decrypt_agent_secret(secret_ciphertext, master_key=settings.SECRET_KEY)


def compute_notification_signature(
    secret: str,
    canonical_payload_bytes: bytes,
) -> str:
    """Compute HMAC-SHA256 hex digest over canonical payload bytes."""
    return hmac.new(
        secret.encode("utf-8"),
        canonical_payload_bytes,
        hashlib.sha256,
    ).hexdigest()


def verify_notification_signature(
    secret: str,
    canonical_payload_bytes: bytes,
    received_signature: str,
) -> bool:
    """Verify an HMAC-SHA256 signature over payload bytes using constant-time comparison.

    Accepts both bare hex digest or 'sha256=<hex>' format.
    """
    if not received_signature or not secret:
        return False

    clean_sig = received_signature.strip()
    if clean_sig.startswith("sha256="):
        clean_sig = clean_sig.split("sha256=", 1)[1].strip()

    expected = compute_notification_signature(secret, canonical_payload_bytes)
    return hmac.compare_digest(clean_sig.lower(), expected.lower())


def build_signed_headers(
    delivery_id: UUID,
    event_type: str,
    timestamp: datetime,
    payload_dict: Dict[str, Any],
    secret_ciphertext: Optional[str] = None,
) -> Tuple[Dict[str, str], bytes]:
    """Format outbound HTTP headers including delivery metadata and HMAC-SHA256 signature.

    Returns:
        Tuple of (headers_dict, canonical_payload_bytes).
    """
    canonical_str = canonicalize_json(payload_dict)
    canonical_bytes = canonical_str.encode("utf-8")

    ts_iso = (
        timestamp.astimezone(timezone.utc).isoformat()
        if timestamp.tzinfo
        else timestamp.replace(tzinfo=timezone.utc).isoformat()
    )

    headers = {
        "Content-Type": "application/json",
        "User-Agent": "Waliya-IR-Notifier/2.0",
        "X-Waliya-Delivery-Id": str(delivery_id),
        "X-Waliya-Event-Type": str(event_type),
        "X-Waliya-Timestamp": ts_iso,
    }

    if secret_ciphertext:
        secret = decrypt_destination_secret(secret_ciphertext)
        if secret:
            sig = compute_notification_signature(secret, canonical_bytes)
            headers["X-Waliya-Signature"] = sig

    return headers, canonical_bytes
