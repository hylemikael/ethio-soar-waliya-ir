"""Forward Waliya Medical Center security JSONL events to Waliya-IR."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import ipaddress
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG_PATH = BASE_DIR / "logs" / "security_events.jsonl"
DEFAULT_API_URL = "http://127.0.0.1:8080"
DEFAULT_SOURCE_ID = "demo-hospital"
ALLOWED_EVENT_TYPES = ["AUTHENTICATION", "SYSTEM_LOG"]
MAX_RESPONSE_BYTES = 64 * 1024


class IntegrationError(RuntimeError):
    """Raised when configuration or a Waliya-IR response is invalid."""


def validate_api_url(api_url: str) -> str:
    """Require a loopback API URL and prevent credentials or URL fragments."""
    parsed = urlsplit(api_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise IntegrationError("WALIYA_API_URL must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise IntegrationError("WALIYA_API_URL must not contain credentials, query, or fragment.")
    try:
        is_loopback = ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        is_loopback = parsed.hostname.lower() == "localhost"
    if not is_loopback:
        raise IntegrationError("WALIYA_API_URL must target localhost or a loopback IP.")
    return api_url.rstrip("/")


def normalize_source_id(source_id: str) -> str:
    source_id = source_id.strip().lower()
    if not re.fullmatch(r"[a-z0-9_-]{2,64}", source_id):
        raise IntegrationError("Source ID must be 2-64 letters, digits, underscores, or hyphens.")
    return source_id


def make_payload(log_event: dict, file_offset: int, raw_line: bytes) -> dict:
    """Map one hospital log record to Waliya's generic inbound event contract."""
    event_name = str(log_event.get("event") or "hospital.log")
    outcome = str(log_event.get("outcome") or "").upper()
    is_auth_event = event_name.startswith("auth.login.")
    event_type = "AUTHENTICATION" if is_auth_event else "SYSTEM_LOG"

    attributes = {
        "application": "Waliya Medical Center Demo",
        "source_event": event_name[:128],
        "status": outcome if outcome in {"SUCCESS", "FAILURE"} else "UNKNOWN",
    }
    for source_key, target_key, max_length in (
        ("username", "username", 128),
        ("role", "role", 32),
        ("source_ip", "src_ip", 64),
        ("request_path", "request_path", 256),
        ("user_agent", "user_agent", 512),
    ):
        value = log_event.get(source_key)
        if isinstance(value, str) and value:
            attributes[target_key] = value[:max_length]

    line_digest = hashlib.sha256(raw_line).hexdigest()[:32]
    return {
        "schema_version": "1.0",
        "external_event_id": f"whmc-{file_offset:x}-{line_digest}"[:128],
        "event_type": event_type,
        "timestamp": log_event.get("timestamp"),
        "severity": "HIGH" if is_auth_event and outcome == "FAILURE" else "INFORMATIONAL",
        "title": (
            "Hospital authentication failure"
            if is_auth_event and outcome == "FAILURE"
            else "Hospital authentication event"
            if is_auth_event
            else "Hospital application security log"
        ),
        "description": "Security event emitted by the fictional Waliya Medical Center demo.",
        "attributes": attributes,
        "raw_metadata": {
            "integration": "demo-hospital",
            "source_event_id": f"whmc-{file_offset:x}-{line_digest}",
        },
    }


def signed_request_headers(source_id: str, secret: str, raw_body: bytes) -> dict[str, str]:
    """Build the timestamped HMAC-SHA256 headers required by the inbound API."""
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    signature = hmac.new(secret.encode("utf-8"), raw_body, hashlib.sha256).hexdigest()
    return {
        "Content-Type": "application/json",
        "X-Waliya-Source-Id": source_id,
        "X-Waliya-Timestamp": timestamp,
        "X-Waliya-Signature": signature,
    }


def _request_json(url: str, body: bytes, headers: dict[str, str]) -> tuple[int, dict]:
    req = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(req, timeout=30) as response:
            status_code = response.status
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        raise IntegrationError(f"Waliya-IR returned HTTP {exc.code}; event was not confirmed.") from None
    except URLError as exc:
        raise IntegrationError(f"Could not reach Waliya-IR: {exc.reason}") from None
    except TimeoutError:
        raise IntegrationError("Waliya-IR request timed out; ingestion was not confirmed.") from None
    if len(response_body) > MAX_RESPONSE_BYTES:
        raise IntegrationError("Waliya-IR response exceeded the local size limit.")
    try:
        parsed = json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise IntegrationError("Waliya-IR returned a non-JSON response; event was not confirmed.") from None
    if not isinstance(parsed, dict):
        raise IntegrationError("Waliya-IR returned an invalid response; event was not confirmed.")
    return status_code, parsed


def register_source(api_url: str, admin_key: str, source_id: str, secret: str) -> None:
    """Register a source through the existing admin-protected Waliya API."""
    payload = {
        "source_id": source_id,
        "name": "Waliya Medical Center Demo",
        "provider_type": "GENERIC",
        "is_enabled": True,
        "auth_type": "HMAC_SHA256",
        "shared_secret": secret,
        "permitted_event_types": ALLOWED_EVENT_TYPES,
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    status_code, response = _request_json(
        f"{api_url}/api/v1/integrations/sources",
        body,
        {"Content-Type": "application/json", "X-Admin-Key": admin_key},
    )
    if status_code != 201 or response.get("source_id") != source_id or not response.get("has_shared_secret"):
        raise IntegrationError("Waliya-IR did not confirm source registration.")
    print(f"Registered inbound source '{source_id}' with HMAC authentication.")


def forward_log(
    api_url: str,
    source_id: str,
    secret: str,
    log_path: Path,
    limit: int | None = None,
) -> tuple[int, int, list[str]]:
    """Forward each JSONL event and require an explicit accepted/duplicate response."""
    accepted = 0
    duplicates = 0
    internal_event_ids = []
    with log_path.open("rb") as handle:
        line_number = 0
        while limit is None or line_number < limit:
            file_offset = handle.tell()
            raw_line = handle.readline()
            if not raw_line:
                break
            line_number += 1
            if not raw_line.strip():
                continue
            try:
                log_event = json.loads(raw_line)
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise IntegrationError(f"Invalid JSON in {log_path} at line {line_number}.") from exc
            if not isinstance(log_event, dict):
                raise IntegrationError(f"Expected a JSON object in {log_path} at line {line_number}.")

            payload = make_payload(log_event, file_offset, raw_line)
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
            status_code, response = _request_json(
                f"{api_url}/api/v1/integrations/inbound/{source_id}/events",
                body,
                signed_request_headers(source_id, secret, body),
            )
            result_status = response.get("status")
            if (
                status_code != 202
                or result_status not in {"ACCEPTED", "DUPLICATE"}
                or response.get("external_event_id") != payload["external_event_id"]
                or not response.get("event_id")
            ):
                raise IntegrationError(
                    f"Waliya-IR did not confirm event on line {line_number}; "
                    f"HTTP {status_code}, status {result_status!r}."
                )
            if result_status == "ACCEPTED":
                accepted += 1
            else:
                duplicates += 1
            internal_event_ids.append(response["event_id"])
    return accepted, duplicates, internal_event_ids


def _required_env(name: str, minimum_length: int = 1) -> str:
    value = os.environ.get(name, "")
    if len(value) < minimum_length:
        raise IntegrationError(f"Set {name} in the environment (minimum {minimum_length} characters).")
    return value


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    register_parser = subparsers.add_parser("register", help="Register the inbound source (admin API key required).")
    register_parser.add_argument("--source-id", default=os.environ.get("WALIYA_SOURCE_ID", DEFAULT_SOURCE_ID))

    forward_parser = subparsers.add_parser("forward", help="Forward hospital JSONL security events.")
    forward_parser.add_argument("--source-id", default=os.environ.get("WALIYA_SOURCE_ID", DEFAULT_SOURCE_ID))
    forward_parser.add_argument("--log", type=Path, default=DEFAULT_LOG_PATH)
    forward_parser.add_argument("--limit", type=int)

    args = parser.parse_args(argv)
    try:
        api_url = validate_api_url(os.environ.get("WALIYA_API_URL", DEFAULT_API_URL))
        secret = _required_env("WALIYA_HMAC_SECRET", 32)
        source_id = normalize_source_id(args.source_id)
        if args.command == "register":
            register_source(
                api_url,
                _required_env("WALIYA_ADMIN_API_KEY", 16),
                source_id,
                secret,
            )
        else:
            if args.limit is not None and args.limit < 1:
                raise IntegrationError("--limit must be a positive integer.")
            accepted, duplicates, _ = forward_log(api_url, source_id, secret, args.log, args.limit)
            print(f"Waliya-IR confirmed accepted={accepted} duplicate={duplicates}.")
    except (IntegrationError, OSError) as exc:
        print(f"Integration failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
