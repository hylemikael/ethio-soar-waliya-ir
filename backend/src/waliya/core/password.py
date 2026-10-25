"""NIST SP 800-63B-4 Compliant Password Policy, Hashing & Verification Engine.

Specifications:
- Algorithm: PBKDF2-HMAC-SHA256 with 600,000 iterations (NIST SP 800-63B-4 §5.1.1.2)
- Salt: 16 bytes cryptographically secure random bytes via secrets.token_bytes
- Storage Format: pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
- Minimum Length: 12 characters (recommended for organizational security)
- Maximum Length: 128 characters (supports long passphrases and password managers)
- Blacklist: Disallows top compromised/common passwords and username substring matches
- Upgrades: Transparent hash upgrade capability for cryptographic agility
"""

import base64
import hashlib
import hmac
import re
import secrets
from typing import Optional, Set, Tuple


# NIST SP 800-63B-4 Parameter Specifications
CURRENT_HASH_ALGO = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16

# Minimum and Maximum Lengths
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 128

# Common and breached password blacklist (top common passwords, default credentials, repetitive patterns)
COMMON_PASSWORDS_BLACKLIST: Set[str] = {
    "password", "password123", "password1234", "password12345", "password!",
    "admin", "administrator", "admin123", "admin1234", "admin12345", "admin!",
    "123456", "12345678", "123456789", "1234567890", "111111", "000000",
    "qwerty", "qwertyuiop", "qwerty123", "asdfghjkl", "zxcvbnm",
    "welcome", "welcome1", "welcome123", "welcome!", "letmein", "letmein123",
    "monkey", "dragon", "master", "shadow", "superman", "batman",
    "trustno1", "iloveyou", "princess", "football", "baseball",
    "changeit", "changeme", "default", "root", "toor", "guest",
    "waliya", "waliya123", "waliyair", "ethiosoar", "ethiopia",
}


class PasswordPolicyError(ValueError):
    """Raised when a candidate password violates NIST SP 800-63B-4 policy rules."""
    pass


def validate_password_complexity(password: str, username: Optional[str] = None) -> None:
    """Validate candidate password against NIST SP 800-63B-4 recommendations.

    Rules:
    1. Length between MIN_PASSWORD_LENGTH (12) and MAX_PASSWORD_LENGTH (128).
    2. Not in common / breached password dictionary.
    3. Does not contain the username as a case-insensitive substring (if username >= 3 chars).
    4. Supports all printable characters and spaces without arbitrary composition rules.
    """
    if not password or not isinstance(password, str):
        raise PasswordPolicyError("Password must be a non-empty string.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password is too short. Minimum length is {MIN_PASSWORD_LENGTH} characters."
        )

    if len(password) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password is too long. Maximum length is {MAX_PASSWORD_LENGTH} characters."
        )

    norm_pwd = password.strip().lower()
    if norm_pwd in COMMON_PASSWORDS_BLACKLIST:
        raise PasswordPolicyError(
            "Password is too common or easily guessed. Please choose a more complex passphrase."
        )

    # Check for simple repetition (e.g. 'aaaaaaaaaaaa')
    if len(set(password)) < 4:
        raise PasswordPolicyError(
            "Password contains too many repetitive characters."
        )

    if username and len(username.strip()) >= 3:
        clean_user = username.strip().lower()
        if clean_user in norm_pwd:
            raise PasswordPolicyError(
                "Password must not contain your username."
            )


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 600,000 iterations and 16-byte random salt."""
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(derived).decode("ascii")
    return f"{CURRENT_HASH_ALGO}${iterations}${salt_b64}${hash_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored hash using constant-time comparison."""
    if not password or not stored_hash:
        return False

    parts = stored_hash.split("$")
    if len(parts) != 4:
        return False

    algo, iterations_str, salt_b64, expected_hash_b64 = parts
    if algo != CURRENT_HASH_ALGO:
        return False

    try:
        iterations = int(iterations_str)
        salt = base64.b64decode(salt_b64.encode("ascii"))
        expected_hash = base64.b64decode(expected_hash_b64.encode("ascii"))
    except (ValueError, TypeError):
        return False

    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
    )

    return hmac.compare_digest(derived, expected_hash)


def verify_and_check_upgrade(
    password: str,
    stored_hash: str,
) -> Tuple[bool, Optional[str]]:
    """Verify password and check if hash parameters need upgrading.

    Returns:
        (is_valid, upgraded_hash_if_needed)
    """
    is_valid = verify_password(password, stored_hash)
    if not is_valid:
        return False, None

    parts = stored_hash.split("$")
    if len(parts) == 4:
        try:
            stored_iterations = int(parts[1])
            if stored_iterations < PBKDF2_ITERATIONS:
                # Upgrade hash to current iteration parameter
                new_hash = hash_password(password, iterations=PBKDF2_ITERATIONS)
                return True, new_hash
        except ValueError:
            pass

    return True, None


def generate_secure_reset_token() -> Tuple[str, str]:
    """Generate a high-entropy password reset token and its SHA-256 storage hash.

    Returns:
        (plaintext_token_for_user, token_hash_for_db)
    """
    plaintext_token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(plaintext_token.encode("utf-8")).hexdigest()
    return plaintext_token, token_hash


def verify_reset_token(plaintext_token: str, stored_token_hash: str) -> bool:
    """Verify a reset token using constant-time comparison against the stored SHA-256 hash."""
    if not plaintext_token or not stored_token_hash:
        return False
    candidate_hash = hashlib.sha256(plaintext_token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate_hash.lower(), stored_token_hash.lower())
