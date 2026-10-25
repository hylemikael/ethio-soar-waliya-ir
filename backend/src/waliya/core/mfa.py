"""RFC 6238 TOTP Multi-Factor Authentication (MFA) & Recovery Engine.

Specifications:
- Algorithm: HMAC-SHA1 Time-Based One-Time Password (TOTP RFC 6238 / RFC 4226)
- Digits: 6
- Time Step: 30 seconds
- Drift Tolerance: ±1 step (30 seconds before and after)
- Secret Encryption: Fernet symmetric encryption at rest using WALIYA_SECRET_KEY
- Recovery Codes: 8 single-use cryptographically random backup codes
"""

import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from typing import List, Optional, Tuple
from urllib.parse import quote

from cryptography.fernet import Fernet


TOTP_DIGITS = 6
TOTP_STEP_SECONDS = 30
TOTP_DRIFT_STEPS = 1  # ±30 seconds
NUM_RECOVERY_CODES = 8


def _get_fernet_key(secret_key: str) -> bytes:
    """Derive a stable 32-byte url-safe base64 Fernet key from the application master secret."""
    digest = hashlib.sha256(secret_key.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_secret(plain_text: str, secret_key: str) -> str:
    """Encrypt sensitive string (TOTP secret or recovery codes) for storage at rest."""
    f = Fernet(_get_fernet_key(secret_key))
    encrypted_bytes = f.encrypt(plain_text.encode("utf-8"))
    return encrypted_bytes.decode("ascii")


def decrypt_secret(cipher_text: str, secret_key: str) -> str:
    """Decrypt stored sensitive string using application master secret."""
    f = Fernet(_get_fernet_key(secret_key))
    decrypted_bytes = f.decrypt(cipher_text.encode("ascii"))
    return decrypted_bytes.decode("utf-8")


def generate_totp_secret() -> str:
    """Generate a high-entropy Base32 encoded 160-bit (20-byte) TOTP secret."""
    raw_secret = secrets.token_bytes(20)
    return base64.b32encode(raw_secret).decode("ascii").replace("=", "")


def generate_totp_uri(
    secret: str,
    username: str,
    issuer: str = "Ethio-SOAR (Waliya-IR)",
) -> str:
    """Generate RFC 6238 compliant otpauth:// URI for authenticator apps."""
    label = f"{issuer}:{username}"
    return f"otpauth://totp/{quote(label)}?secret={secret}&issuer={quote(issuer)}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}"


def generate_recovery_codes(secret_key: str, num_codes: int = NUM_RECOVERY_CODES) -> Tuple[List[str], str]:
    """Generate single-use backup recovery codes and their encrypted storage payload.

    Returns:
        (plain_codes_for_user, encrypted_storage_json)
    """
    plain_codes = []
    hashed_codes = []
    for _ in range(num_codes):
        # Format: xxxx-xxxx (8 hex characters)
        code = f"{secrets.token_hex(2)}-{secrets.token_hex(2)}"
        plain_codes.append(code)
        hashed_codes.append(hashlib.sha256(code.encode("utf-8")).hexdigest())

    payload = json.dumps(hashed_codes)
    encrypted_payload = encrypt_secret(payload, secret_key)
    return plain_codes, encrypted_payload


def generate_totp_code(secret: str, for_time: Optional[float] = None) -> str:
    """Compute 6-digit TOTP code for the specified timestamp (defaults to current time)."""
    ts = for_time if for_time is not None else time.time()
    counter = int(ts // TOTP_STEP_SECONDS)

    # Pad secret with '=' if necessary for base32 decoding
    padded_secret = secret.upper()
    padding_needed = (8 - len(padded_secret) % 8) % 8
    padded_secret += "=" * padding_needed

    key = base64.b32decode(padded_secret.encode("ascii"))
    msg = struct.pack(">Q", counter)
    h = hmac.new(key, msg, hashlib.sha1).digest()

    offset = h[-1] & 0x0F
    code_int = struct.unpack(">I", h[offset : offset + 4])[0] & 0x7FFFFFFF
    token = code_int % (10 ** TOTP_DIGITS)
    return f"{token:0{TOTP_DIGITS}d}"


def verify_totp_code(
    secret: str,
    code: str,
    window: int = TOTP_DRIFT_STEPS,
    at_time: Optional[float] = None,
) -> bool:
    """Verify candidate TOTP code against secret with drift tolerance window."""
    if not code or not code.isdigit() or len(code) != TOTP_DIGITS:
        return False

    current_ts = at_time if at_time is not None else time.time()
    for drift in range(-window, window + 1):
        target_ts = current_ts + (drift * TOTP_STEP_SECONDS)
        expected = generate_totp_code(secret, for_time=target_ts)
        if hmac.compare_digest(code.strip(), expected):
            return True

    return False


def verify_and_consume_recovery_code(
    recovery_code: str,
    encrypted_recovery_payload: str,
    secret_key: str,
) -> Tuple[bool, Optional[str]]:
    """Validate candidate recovery code, and consume it if valid.

    Returns:
        (is_valid, updated_encrypted_recovery_payload)
    """
    if not recovery_code or not encrypted_recovery_payload:
        return False, None

    try:
        decrypted_json = decrypt_secret(encrypted_recovery_payload, secret_key)
        stored_hashes: List[str] = json.loads(decrypted_json)
    except Exception:
        return False, None

    candidate_hash = hashlib.sha256(recovery_code.strip().lower().encode("utf-8")).hexdigest()

    matched_index = -1
    for idx, stored_hash in enumerate(stored_hashes):
        if hmac.compare_digest(candidate_hash, stored_hash):
            matched_index = idx
            break

    if matched_index >= 0:
        # Consume the used recovery code
        stored_hashes.pop(matched_index)
        updated_encrypted = encrypt_secret(json.dumps(stored_hashes), secret_key)
        return True, updated_encrypted

    return False, None
