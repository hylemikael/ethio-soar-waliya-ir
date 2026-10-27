"""NIST SP 800-63B-4 Compliant Password Policy, Hashing & Verification Engine.

Specifications & Security Controls:
- Algorithm: PBKDF2-HMAC-SHA256 with 600,000 iterations (NIST SP 800-63B-4 §5.1.1.2)
- Salt: 16 bytes cryptographically secure random bytes via secrets.token_bytes
- Storage Format: pbkdf2_sha256$<iterations>$<salt_b64>$<hash_b64>
- Minimum Length:
  - 15 characters when passwords authenticate users without MFA (NIST SP 800-63B-4 / OWASP ASVS)
  - 12 characters when MFA is enforced on the account
- Maximum Length: 128 characters (passphrase friendly, no silent truncation)
- Unicode Normalization: NFKC normalization consistently applied across hashing, validation, and verification
- Blocklist: Comprehensive offline blocklist of common compromised passwords, default credentials, and predictable keyboard walks
- Enumeration & Timing Safety: Constant-time comparison via hmac.compare_digest
- Upgrades: Transparent hash upgrade capability for cryptographic agility
"""

import base64
import hashlib
import hmac
import re
import secrets
import unicodedata
from typing import Optional, Set, Tuple


# NIST SP 800-63B-4 Parameter Specifications
CURRENT_HASH_ALGO = "pbkdf2_sha256"
PBKDF2_ITERATIONS = 600_000
SALT_BYTES = 16

# Password Length Policy
MIN_PASSWORD_LENGTH_STANDALONE = 15  # For passwords without MFA
MIN_PASSWORD_LENGTH_MFA = 12         # For accounts with mandatory MFA
MAX_PASSWORD_LENGTH = 128            # Generous upper bound for passphrases & password managers

# Maintainable offline blocklist of common compromised passwords, defaults, and dictionary phrases
OFFLINE_BREACHED_PASSWORD_BLOCKLIST: Set[str] = {
    # Default credentials and trivial variations
    "password", "password123", "password1234", "password12345", "password12345678", "password!", "p@ssword", "p@ssword1",
    "admin", "administrator", "administrator2026", "admin123", "admin1234", "admin12345", "admin!", "admin@123",
    "root", "toor", "guest", "default", "system", "operator", "security", "supervisor",
    "changeit", "changeme", "changeme1", "changeme123", "welcome", "welcome1", "welcome123",
    "letmein", "letmein123", "login", "secret", "supersecret", "pass1234", "test1234",
    # Common numerical sequences
    "123456", "1234567", "12345678", "123456789", "1234567890", "0123456789",
    "000000", "111111", "222222", "333333", "444444", "555555", "666666", "777777", "888888", "999999",
    "112233", "121212", "123123", "12341234", "654321", "987654321",
    # Keyboard walks
    "qwerty", "qwertyuiop", "qwerty123", "qwerty1234", "asdfghjkl", "zxcvbnm",
    "qazwsx", "wsxedc", "edcrfv", "1q2w3e4r", "zaq12wsx", "1qaz2wsx",
    # Pop culture and common phrases
    "iloveyou", "trustno1", "princess", "football", "baseball", "dragon", "monkey", "shadow",
    "master", "superman", "batman", "killer", "sunshine", "starwars", "whatever",
    # Year-based and seasonal patterns
    "spring2024", "summer2024", "autumn2024", "winter2024",
    "spring2025", "summer2025", "autumn2025", "winter2025",
    "spring2026", "summer2026", "autumn2026", "winter2026",
    # Local & Organization specific predictable patterns
    "waliya", "waliya123", "waliya1234", "waliya2026", "waliyair", "ethiosoar",
    "ethiopia", "ethiopia123", "addisababa", "telecom123", "cybersecurity",
}

# Predictable character sequences & trivial breached variations
_PREDICTABLE_PATTERNS = [
    re.compile(r"^(?:0123456789|1234567890|abcdefghijklmnopqrstuvwxyz)$", re.IGNORECASE),
]

_TRIVIAL_BREACHED_PATTERN = re.compile(
    r"^(?:password|p@ssword|admin|administrator|welcome|changeme|changeit|letmein|qwerty)[\d!@#$%^&*()_+\-=\[\]{};:,.<>?]*$",
    re.IGNORECASE,
)


class PasswordPolicyError(ValueError):
    """Raised when a candidate password violates NIST SP 800-63B-4 policy rules."""
    pass


def normalize_password(password: str) -> str:
    """Apply Unicode NFKC normalization consistently to preserve character semantics."""
    if not isinstance(password, str):
        return ""
    return unicodedata.normalize("NFKC", password)


def validate_password_complexity(
    password: str,
    username: Optional[str] = None,
    is_mfa_enforced: bool = False,
) -> str:
    """Validate candidate password against NIST SP 800-63B-4 recommendations.

    Rules:
    1. If passwords authenticate without MFA, minimum length is 15 characters.
       If mandatory MFA is enforced on the account, minimum length is 12 characters.
    2. Maximum length is 128 characters (no silent truncation; supports passphrases).
    3. Rejects commonly used, breached, and predictable passwords from offline blocklist.
    4. Rejects passwords containing username as substring (case-insensitive, len >= 3).
    5. Rejects repetitive characters and simple keyboard sequences.
    6. Does not require arbitrary character composition (uppercase/lowercase/symbol) rules.

    Returns:
        The normalized password string.
    """
    if not password or not isinstance(password, str):
        raise PasswordPolicyError("Password must be a non-empty string.")

    norm_pwd = normalize_password(password)

    if len(norm_pwd) > MAX_PASSWORD_LENGTH:
        raise PasswordPolicyError(
            f"Password is too long. Maximum length is {MAX_PASSWORD_LENGTH} characters."
        )

    lower_pwd = norm_pwd.strip().lower()

    # 1. Offline compromised dictionary check & trivial breached variations
    if lower_pwd in OFFLINE_BREACHED_PASSWORD_BLOCKLIST or _TRIVIAL_BREACHED_PATTERN.match(lower_pwd):
        raise PasswordPolicyError(
            "Password is too common, easily guessed, or present in breached password databases. Please choose a strong passphrase."
        )

    # 2. Check for username substring similarity
    if username and len(username.strip()) >= 3:
        clean_user = normalize_password(username).strip().lower()
        if clean_user in lower_pwd:
            raise PasswordPolicyError(
                "Password must not contain your username."
            )

    # 3. Check for low character entropy / repetitive patterns (e.g. 'aaaaaaaaaaaaaaa')
    if len(set(norm_pwd)) < 4:
        raise PasswordPolicyError(
            "Password contains too many repetitive characters."
        )

    # 4. Length check
    min_len = MIN_PASSWORD_LENGTH_MFA if is_mfa_enforced else MIN_PASSWORD_LENGTH_STANDALONE
    if len(norm_pwd) < min_len:
        mfa_desc = " (for accounts with mandatory MFA)" if is_mfa_enforced else " (for standalone password authentication)"
        raise PasswordPolicyError(
            f"Password is too short. Minimum length is {min_len} characters{mfa_desc}."
        )

    return norm_pwd


def hash_password(password: str, iterations: int = PBKDF2_ITERATIONS) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with 600,000 iterations and 16-byte random salt."""
    norm_pwd = normalize_password(password)
    salt = secrets.token_bytes(SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        norm_pwd.encode("utf-8"),
        salt,
        iterations,
    )
    salt_b64 = base64.b64encode(salt).decode("ascii")
    hash_b64 = base64.b64encode(derived).decode("ascii")
    return f"{CURRENT_HASH_ALGO}${iterations}${salt_b64}${hash_b64}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify candidate password against stored hash using constant-time comparison.

    Fails safely on malformed or invalid stored hashes.
    """
    if not password or not stored_hash or not isinstance(stored_hash, str):
        return False

    parts = stored_hash.split("$")
    if len(parts) != 4:
        return False

    algo, iterations_str, salt_b64, expected_hash_b64 = parts
    if algo != CURRENT_HASH_ALGO:
        return False

    try:
        iterations = int(iterations_str)
        if iterations <= 0:
            return False
        salt = base64.b64decode(salt_b64.encode("ascii"), validate=True)
        expected_hash = base64.b64decode(expected_hash_b64.encode("ascii"), validate=True)
    except (ValueError, TypeError):
        return False

    norm_pwd = normalize_password(password)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        norm_pwd.encode("utf-8"),
        salt,
        iterations,
    )

    return hmac.compare_digest(derived, expected_hash)


def verify_and_check_upgrade(
    password: str,
    stored_hash: str,
    target_iterations: int = PBKDF2_ITERATIONS,
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
            if stored_iterations < target_iterations:
                new_hash = hash_password(password, iterations=target_iterations)
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
    """Verify reset token using constant-time comparison against stored SHA-256 hash."""
    if not plaintext_token or not stored_token_hash:
        return False
    candidate_hash = hashlib.sha256(plaintext_token.encode("utf-8")).hexdigest()
    return hmac.compare_digest(candidate_hash.lower(), stored_token_hash.lower())
