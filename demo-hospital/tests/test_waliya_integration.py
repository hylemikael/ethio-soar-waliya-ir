import hashlib
import hmac
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from waliya_integration import (
    IntegrationError,
    make_payload,
    normalize_source_id,
    signed_request_headers,
    validate_api_url,
)


class WaliyaIntegrationUnitTests(unittest.TestCase):
    def test_failed_login_maps_to_detection_rule_fields(self):
        payload = make_payload(
            {
                "event": "auth.login.failure",
                "timestamp": "2026-10-27T00:00:00Z",
                "outcome": "failure",
                "username": "fictional-user",
                "source_ip": "127.0.0.1",
            },
            12,
            b'{"event":"auth.login.failure"}\n',
        )

        self.assertEqual(payload["event_type"], "AUTHENTICATION")
        self.assertEqual(payload["severity"], "HIGH")
        self.assertEqual(payload["attributes"]["status"], "FAILURE")
        self.assertEqual(payload["attributes"]["src_ip"], "127.0.0.1")

    def test_non_auth_event_is_system_log(self):
        payload = make_payload(
            {"event": "appointment.booked", "outcome": "success"},
            0,
            b'{"event":"appointment.booked"}\n',
        )

        self.assertEqual(payload["event_type"], "SYSTEM_LOG")
        self.assertEqual(payload["attributes"]["status"], "SUCCESS")

    def test_signature_is_over_exact_raw_body(self):
        raw_body = b'{"event_type":"AUTHENTICATION"}'
        headers = signed_request_headers("demo-hospital", "s" * 32, raw_body)
        expected = hmac.new(b"s" * 32, raw_body, hashlib.sha256).hexdigest()

        self.assertEqual(headers["X-Waliya-Signature"], expected)
        self.assertEqual(headers["X-Waliya-Source-Id"], "demo-hospital")
        self.assertTrue(headers["X-Waliya-Timestamp"].endswith("Z"))

    def test_rejects_non_loopback_http_and_invalid_source_ids(self):
        with self.assertRaises(IntegrationError):
            validate_api_url("http://192.0.2.10:8000")
        with self.assertRaises(IntegrationError):
            normalize_source_id("../other-source")
        self.assertEqual(normalize_source_id("Demo-Hospital"), "demo-hospital")


if __name__ == "__main__":
    unittest.main()
