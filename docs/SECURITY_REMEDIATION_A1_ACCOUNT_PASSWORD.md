# ETHIO-SOAR (Waliya-IR): Security Remediation Report — A1: Account & Password Security Hardening

**Platform:** Ethio-SOAR (Waliya-IR)  
**Security Domain:** A1 — Account & Password Security  
**Engineering Phase:** Enterprise Security Hardening  
**Target Standard:** NIST SP 800-63B-4, RFC 6238, OWASP ASVS v4.0.3  
**Status:** IMPLEMENTED & INDEPENDENTLY VERIFIED  
**Date:** 2026-10-25  

---

## 1. Executive Summary

This security remediation phase systematically hardened Ethio-SOAR (Waliya-IR)'s identity, credential management, multi-factor authentication, and session boundaries. Prior to this implementation, authentication mechanisms relied on process-local in-memory state for rate limiting, session revocation, and pending MFA challenge tokens. In multi-worker containerized deployments, this created critical security partitions where session revocations were ignored by peer workers, rate limiters could be bypassed by load-balanced requests, and MFA tokens could fail or be replayed across worker nodes. Furthermore, password policies lacked Unicode canonical normalization and dual length enforcement for standalone versus MFA-enforced accounts.

All identified vulnerabilities have been remediated directly in the codebase, integrated with Redis-backed distributed synchronization, backed by thread-safe offline fallback mechanisms, and verified against a dedicated 13-test integration test suite alongside the full platform regression suite (450 total automated tests with 100% pass rate).

---

## 2. Threat Assessment & Vulnerabilities Remediated

| Vulnerability ID | Component | Severity | Description & Attack Vector | Remediated State |
| :--- | :--- | :--- | :--- | :--- |
| **VULN-A1-01** | `rate_limit.py` | HIGH | **In-Memory Rate Limiting Partition:** Rate limiting counters were stored in a Python in-memory dictionary. An attacker performing credential stuffing could bypass rate limits by distributing requests across multiple Uvicorn workers or container replicas. | Replaced with distributed Redis Sorted Sets (`ZADD`, `ZREMRANGEBYSCORE`, `ZCARD`) with exponential lockout backoff. |
| **VULN-A1-02** | `rate_limit.py` / `auth.py` | HIGH | **IP-Only Rate Limiting (Distributed Brute Force):** Rate limiting only tracked client IP. An attacker rotating residential proxy IPs could launch distributed brute-force attacks against a single high-privilege account without triggering lockouts. | Implemented multi-signal rate limiting enforcing constraints on both IP address and targeted account (`user:{username}`). |
| **VULN-A1-03** | `rate_limit.py` | MEDIUM | **Untrusted Header Spoofing (`X-Forwarded-For`):** Client IP extraction naively accepted forwarding headers from untrusted clients, allowing attackers to forge arbitrary client IPs to evade IP lockouts. | Added `get_client_ip()` validating upstream socket against `settings.TRUSTED_PROXIES` before inspecting proxy headers. |
| **VULN-A1-04** | `session.py` | HIGH | **In-Memory Session Revocation Partition:** `_REVOKED_SESSIONS` was a local dictionary. A user logging out or changing their password on Worker A remained logged in on Worker B. | Implemented distributed revocation registry in Redis (`session:revoked:{id}` and `session:user_revoked_before:{uid}`) with DB fallback. |
| **VULN-A1-05** | `auth.py` | MEDIUM | **MFA Challenge Token Ephemerality & Replay:** `_PENDING_MFA_CHALLENGES` was local in-memory. An attacker could attempt to replay challenge tokens across workers or brute-force TOTP codes within the challenge window. | Distributed Redis challenge store (`mfa:challenge:{token}`) using atomic `GETDEL` consumption upon submission, enforcing strict single-use. |
| **VULN-A1-06** | `auth.py` | HIGH | **Account Enumeration Timing Side-Channel:** Missing users failed in ~0.5ms while existing users computed PBKDF2 in ~500ms. Attackers could map valid organizational usernames via response latency. | Implemented static dummy PBKDF2 hashing (`_DUMMY_PBKDF2_HASH`) executed with candidate credentials whenever an account does not exist or is inactive. |
| **VULN-A1-07** | `password.py` | MEDIUM | **Password Policy & Normalization Gap:** Standalone passwords allowed 12 characters without MFA; Unicode was not normalized, allowing authentication bypass via non-normalized forms; blocklist was incomplete. | Enforced NIST SP 800-63B-4 dual policy: 15-char min standalone, 12-char min with MFA, NFKC normalization, offline blocklist + trivial pattern regex. |
| **VULN-A1-08** | `auth.py` | HIGH | **Machine API Key Personal Endpoint Bypass:** `X-Admin-Key` could be supplied to personal account endpoints (`/auth/mfa/disable`, `/auth/password/change`), bypassing personal re-authentication. | Restricted personal endpoints strictly to interactive user sessions (`actor.auth_method == "session"` and `actor.user_id is not None`). |
| **VULN-A1-09** | `auth.py` | MEDIUM | **Privileged Role MFA Disablement:** Privileged accounts (`ADMIN`, `OPERATOR`) could disable MFA, exposing critical response capabilities to single-factor compromise. | Enforced mandatory MFA policy rejecting disablement requests for `ADMIN` and `OPERATOR` roles. |
| **VULN-A1-10** | `mfa.py` / `auth.py` | MEDIUM | **Concurrent Recovery Code Double-Spend:** Concurrent requests submitting the same single-use backup code could succeed before database record updates committed. | Acquired PostgreSQL row-level locks (`select(...).with_for_update()`) on `UserModel` during verification. |

---

## 3. Architecture & Implemented Security Controls

### 3.1. NIST SP 800-63B-4 Password Security Engine (`waliya.core.password`)
- **Dual Length Policy:**
  - `MIN_PASSWORD_LENGTH_STANDALONE = 15`: Passwords authenticating users without MFA must be at least 15 characters.
  - `MIN_PASSWORD_LENGTH_MFA = 12`: Accounts with mandatory MFA enrolled may use passwords down to 12 characters.
  - `MAX_PASSWORD_LENGTH = 128`: Full support for long passphrases and password managers without silent truncation.
- **Composition Rules:** Avoids arbitrary composition rules (no mandatory special characters or uppercase digits) in accordance with NIST guidance to encourage high-entropy passphrases.
- **Unicode NFKC Normalization:** `normalize_password()` applies NFKC normalization consistently prior to hashing, policy validation, and verification, preventing canonical equivalence bypasses.
- **Compromised Credential Screening:** Combines an offline blocklist (`OFFLINE_BREACHED_PASSWORD_BLOCKLIST`) covering known default credentials, sequential patterns, seasonal keys, and a compiled regex (`_TRIVIAL_BREACHED_PATTERN`) that catches trivial permutations of compromised dictionary roots.
- **Username Similarity & Entropy Rejection:** Rejects passwords containing the account username (case-insensitive substring match) and passwords with fewer than 4 unique characters.
- **PBKDF2-HMAC-SHA256 Cryptographic Agility:** 600,000 iterations using a cryptographically secure 16-byte random salt (`secrets.token_bytes(16)`).
- **Safe Failure on Malformed Hashes:** Fails safely with `False` on empty inputs, invalid string formats, corrupted base64, negative iteration counts, or unknown algorithm prefixes without throwing unhandled exceptions.
- **Transparent Upgrade:** `verify_and_check_upgrade()` detects hashes generated under legacy iteration counts (< 600,000) and produces an upgraded hash on successful login.

### 3.2. Distributed Rate Limiting & Proxy Verification (`waliya.core.rate_limit`)
- **Redis Sorted Set Sliding Window:**
  - Key schema: `ratelimit:{domain}:attempts:{key}`.
  - Scores represent epoch timestamps; pruned using `ZREMRANGEBYSCORE -inf (now - window)`.
  - Automatic TTL on sorted sets (`window_seconds * 2`) prevents Redis memory leaks.
- **Exponential Backoff Lockouts:**
  - Consecutive lockouts double in duration: `min(base_lockout * (2 ** consecutive), max_lockout)`.
  - Stored in Redis under `ratelimit:{domain}:locked:{key}` with exact TTL.
- **Multi-Signal Protection:** Login attempts check both `client_ip` and `user:{username.lower()}`. A distributed attacker cannot brute-force an account across multiple IPs, and an attacker cannot credential-stuff multiple accounts from one IP.
- **Resilient Fallback:** When Redis is unreachable or during unit tests without Redis, operations automatically fall back to thread-safe local dictionaries protected by `threading.Lock`.
- **Trusted Reverse Proxy IP Resolution:** `get_client_ip()` verifies `request.client.host` against `settings.TRUSTED_PROXIES` before parsing `X-Forwarded-For` or `X-Real-IP`.

### 3.3. Distributed Session Management & Revocation (`waliya.core.session`)
- **Distributed Invalidation:**
  - `revoke_session(session_id)` writes to Redis `session:revoked:{session_id}` with TTL matching remaining token lifespan.
  - `revoke_all_user_sessions(user_id)` writes `session:user_revoked_before:{user_id}` with an 8-hour TTL.
- **Dual-Tier Check:** `is_session_revoked()` performs an in-memory check followed by Redis verification, ensuring zero-latency invalidation across multiple workers.
- **Full Revocation on Credential Changes:** Active sessions are immediately invalidated when a user logs out, changes their password, completes a password reset, or is deactivated by an administrator.

### 3.4. Multi-Factor Authentication & Challenge Isolation (`waliya.core.mfa` & `auth.py`)
- **RFC 6238 TOTP Standard:** HMAC-SHA1, 6 digits, 30-second step, with $\pm 1$ step (30s) drift tolerance.
- **Confirmation Step:** Secrets and 8 single-use recovery codes are stored in pending state until verified with an authenticator app code.
- **Fernet Encryption at Rest:** All TOTP secrets and hashed recovery code payloads are symmetrically encrypted using Fernet derived from `WALIYA_SECRET_KEY`.
- **Single-Use Challenge Tokens:** Pending MFA login challenges are stored in Redis (`mfa:challenge:{token}`) and consumed atomically with Redis `GETDEL` upon code submission. Replay attacks are rejected with HTTP 400.
- **Concurrency Protection for Recovery Codes:** PostgreSQL row locks (`with_for_update()`) serialize recovery code verification, preventing concurrent double-spending of backup codes.
- **Mandatory MFA Policy:** Privileged roles (`ADMIN`, `OPERATOR`) cannot disable MFA.

### 3.5. Administrative Machine Key (`X-Admin-Key`) Isolation
- Machine-to-machine API key authentication is strictly quarantined to automated system interfaces and rule synchronization.
- Personal endpoints (`/auth/mfa/enroll`, `/auth/mfa/verify`, `/auth/mfa/disable`, `/auth/password/change`) enforce `actor.auth_method == "session"` and require a valid `actor.user_id`. Passing `X-Admin-Key` returns HTTP 403 Forbidden.

---

## 4. Verification & Automated Test Evidence

### 4.1. Dedicated A1 Integration Test Suite
The dedicated test suite `backend/tests/integration/test_a1_account_password_security.py` tests all security controls:

```bash
backend/.venv/bin/pytest backend/tests/integration/test_a1_account_password_security.py -v
```

**Results:**
- `test_nist_dual_length_policy_and_passphrases`: PASSED
- `test_unicode_nfkc_normalization`: PASSED
- `test_offline_breached_blocklist_and_similarity`: PASSED
- `test_pbkdf2_safe_failure_on_malformed_hashes`: PASSED
- `test_transparent_hash_upgrade`: PASSED
- `test_redis_distributed_sliding_window_rate_limiter`: PASSED
- `test_trusted_proxy_ip_resolution`: PASSED
- `test_distributed_session_revocation`: PASSED
- `test_user_bulk_session_revocation`: PASSED
- `test_admin_api_key_forbidden_on_personal_endpoints`: PASSED
- `test_single_use_mfa_challenge_tokens_and_replay_defense`: PASSED
- `test_privileged_mfa_cannot_be_disabled`: PASSED
- `test_multi_signal_account_rate_limiting`: PASSED

**13 passed in 10.98s**

### 4.2. Full Platform Regression Quality Gates
The complete regression test suite was executed across all components:

| Test Suite | Total Tests | Passed | Failed | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Backend Test Suite** (`backend/tests/`) | 346 | 346 | 0 | 100% PASS |
| **Agent Test Suite** (`agent/tests/`) | 62 | 62 | 0 | 100% PASS |
| **Simulator Test Suite** (`sim/tests/`) | 42 | 42 | 0 | 100% PASS |
| **Total Automated Tests** | **450** | **450** | **0** | **100% PASS** |
| **Frontend Production Build** (`npm run build`) | 1,585 modules | Built in 23.73s | 0 | SUCCESS |

---

## 5. Configuration & Deployment Guidance

### 5.1. Environment Variables Added / Updated

| Variable | Default Value | Description |
| :--- | :--- | :--- |
| `WALIYA_TRUSTED_PROXIES` | `["127.0.0.1", "::1", "localhost"]` | List of trusted reverse proxy IP addresses from which `X-Forwarded-For` is accepted. |
| `WALIYA_MFA_ENFORCED_FOR_PRIVILEGED` | `true` | When true, accounts with `ADMIN` or `OPERATOR` roles cannot disable MFA. |
| `WALIYA_REDIS_URL` | `redis://:waliya_redis_dev_secret@127.0.0.1:6380/0` | Redis connection URL for distributed rate limiting, session revocation, and MFA challenges. |
| `WALIYA_SECRET_KEY` | *(Must be $\ge 32$ random chars in production)* | Master encryption key for Fernet at-rest encryption of MFA secrets. |

### 5.2. Reverse Proxy Deployment Guidance (Nginx)
When deploying behind Nginx or an enterprise load balancer, configure:
```nginx
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
```
Ensure the upstream internal IP of the reverse proxy is registered in `WALIYA_TRUSTED_PROXIES`.

---

## 6. Residual Risks & Roadmap

1. **Hardware Security Keys (WebAuthn / FIDO2):** RFC 6238 TOTP protects against remote credential stuffing, but remains vulnerable to real-time reverse-proxy phishing (e.g., Evilginx). Future phases should implement FIDO2/WebAuthn for phishing-resistant hardware tokens.
2. **External Breach API Integration:** The current implementation uses an offline dictionary of common breached credentials. Adding an optional k-Anonymity lookup against HaveIBeenPwned API during password changes would broaden breach detection.
3. **Anomalous Geo-Velocity Detection:** Login events are recorded in the audit ledger with client IP. Adding alerting for concurrent logins from disparate geographical regions will further strengthen operational visibility.

---

**Sign-off:** Principal Application Security Engineer  
**Audit Status:** PASSED — Phase A1 Complete & Verified

