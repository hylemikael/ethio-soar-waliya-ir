# Waliya Medical Center Demo

Waliya Medical Center is a small, fictional hospital website intended for local demonstration and security workflow testing. It runs independently from the main Ethio-SOAR project and does not modify the existing backend, frontend, Docker setup, or database.

## Purpose

- Showcase a polished medical website with:
  - Home and hospital information
  - Service catalog
  - Appointment booking form
  - Patient login portal
  - Protected staff dashboard
- Demonstrate secure local login behavior using hashed passwords
- Record login attempts and appointment events in structured JSON logs
- Provide harmless monitoring examples for file-integrity and webshell-indicator review

## Local run commands

From the project root:

```bash
python3 demo-hospital/app.py
```

The site listens on:

```text
http://127.0.0.1:5001
```

To stop the service:

```bash
# Press Ctrl+C in the terminal running the app
```

## Demo credentials

### Patient accounts

- Username: `patient1`
  Password: `PatientPass!2025`
- Username: `patient2`
  Password: `Care123!Patient`

### Staff accounts

- Username: `dr_abel`
  Password: `Staff@2025`
- Username: `admin`
  Password: `Admin@2025`

All account data and patient information in this demo are fictional. These accounts are seeded locally in the demo SQLite database only.

## Important files

- `demo-hospital/app.py` — Flask app, seeded accounts, local security logging, authentication logic
- `demo-hospital/waliya_integration.py` — optional HMAC-signed JSONL forwarder for Waliya-IR
- `demo-hospital/data/hospital_demo.db` — local SQLite database for users, appointments, and login attempts
- `demo-hospital/logs/security_events.jsonl` — structured security events in JSON Lines format
- `demo-hospital/monitoring/file_integrity_baseline.txt` — harmless sample file-integrity baseline for local monitoring
- `demo-hospital/monitoring/webshell_indicators.txt` — harmless simulated indicator review output
- `demo-hospital/tests/test_app.py` — app test suite for login flows, access control, and appointments

## Structured log output

Security events are written to JSON Lines in:

```text
demo-hospital/logs/security_events.jsonl
```

Each entry includes a timestamp, event type, username, role, outcome, source IP, request path, and user agent.

## Optional Waliya-IR inbound integration

The forwarder uses Waliya-IR's existing inbound source and event endpoints. It does not write to the Waliya-IR database directly and does not change Waliya-IR authentication or security configuration.

The receiving source must first be registered by a Waliya-IR administrator. The inbound API is:

- Register source: `POST /api/v1/integrations/sources` with `X-Admin-Key`
- Submit event: `POST /api/v1/integrations/inbound/{source_id}/events`
- Required event headers: `X-Waliya-Source-Id`, `X-Waliya-Timestamp`, and `X-Waliya-Signature`
- Signature: lowercase HMAC-SHA256 hex digest over the exact raw JSON request body
- Timestamp: UTC ISO-8601 with `Z`; the receiver rejects timestamps outside its five-minute freshness window

The receiver accepts `AUTHENTICATION` and `SYSTEM_LOG` events for this source. Hospital authentication failures are mapped to `AUTHENTICATION` events with `attributes.status=FAILURE`, matching Waliya-IR's built-in authentication-failure rule input. Other hospital log events are sent as `SYSTEM_LOG`. The forwarder expects an explicit `202` response with `ACCEPTED` or `DUPLICATE` and an event ID; errors are reported as failures, not treated as successful ingestion.

Use the local API address exposed by your Waliya-IR deployment. This project's Docker frontend publishes its API proxy on `http://127.0.0.1:8080`, which is the forwarder's default; set `WALIYA_API_URL` if your local deployment exposes the API differently. The utility deliberately rejects non-loopback API URLs and plain HTTP to remote hosts.

1. Provide the API URL, source ID, and a random shared secret of at least 32 characters to the forwarder. Do not put secret values in source files or commit them:

   ```bash
   export WALIYA_API_URL=http://127.0.0.1:8000
   export WALIYA_SOURCE_ID=demo-hospital
   read -rsp 'Waliya-IR admin API key: ' WALIYA_ADMIN_API_KEY; echo
   export WALIYA_ADMIN_API_KEY
   read -rsp 'New inbound HMAC secret (32+ characters): ' WALIYA_HMAC_SECRET; echo
   export WALIYA_HMAC_SECRET
   ```

2. Register the source using the authorized admin endpoint:

   ```bash
   python3 demo-hospital/waliya_integration.py register
   unset WALIYA_ADMIN_API_KEY
   ```

   Save the same HMAC secret in your approved local secret manager/environment for forwarding. The API encrypts its registered copy and does not return the secret. Re-registering an existing source is not automatic; resolve an existing source through the authorized administration workflow.

3. Forward the current JSONL log snapshot:

   ```bash
   python3 demo-hospital/waliya_integration.py forward
   ```

   Optional `--log PATH` selects a different JSONL file; `--limit N` limits one run. This one-shot command reads the current file from the beginning. Event IDs are stable for each line at its byte offset, so replayed lines are acknowledged as duplicates by Waliya-IR; newly appended lines are forwarded on a later run. It does not run as a background service or maintain a local checkpoint.

For a local-only demonstration, credentials may be kept in the git-ignored `demo-hospital/.env.local` with filesystem permissions restricted to the current user (`chmod 600`). Load it into the current shell with `set -a; . demo-hospital/.env.local; set +a`; do not commit it or share its contents.

An `ACCEPTED` response confirms durable ingestion into Waliya-IR's event/outbox path, not a detection finding. The backend publishes queued events to `stream:telemetry:raw`; the running telemetry consumer and an applicable active rule are required for detection. A successful sender run alone must not be reported as a detection.

## Monitoring examples

The demo includes harmless sample files used for local monitoring demonstrations:

- `demo-hospital/monitoring/file_integrity_baseline.txt`
- `demo-hospital/monitoring/webshell_indicators.txt`

These are intentionally non-executable and do not perform real malicious actions.

## Test procedures

Run the included tests from the project root:

```bash
python3 -m unittest discover -s demo-hospital/tests -p 'test_*.py'
```

Covered checks:

- homepage renders successfully
- patient login succeeds with valid credentials
- failed login attempts are recorded
- staff dashboard access is protected
- appointment booking is persisted
- integration event mapping, signing format, and loopback URL guard

## Security notes

- The app binds to `127.0.0.1` and is designed for local-only demonstration use.
- Session cookies are HTTP-only and same-site restricted.
- Passwords are safely hashed with PBKDF2-HMAC-SHA256.
- No external networks or external services are used.
- This demo is not connected to the main Ethio-SOAR database or deployment stack.

## Operational caution

This demo is a local security demonstration only. Do not expose it publicly or treat it as production hospital software.
