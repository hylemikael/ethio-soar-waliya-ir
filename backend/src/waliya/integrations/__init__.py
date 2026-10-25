"""External integration and notifications module (Inbound & Outbound)."""

from waliya.integrations.delivery_service import NotificationDeliveryService
from waliya.integrations.inbound_service import InboundIngestionService
from waliya.integrations.network_security import (
    SSRFValidationError,
    create_safe_http_client,
    validate_destination_url,
)
from waliya.integrations.normalization import (
    MAX_INBOUND_PAYLOAD_BYTES,
    MAX_NESTING_DEPTH,
    NormalizedExternalEvent,
    map_event_type,
    normalize_inbound_security_event,
    normalize_severity,
    parse_event_timestamp,
)
from waliya.integrations.payloads import (
    NotificationEventType,
    NotificationPayload,
    build_detection_finding_created_payload,
    build_incident_created_payload,
    build_incident_status_changed_payload,
    build_response_plan_state_changed_payload,
    build_test_notification_payload,
    build_threat_intel_matched_payload,
)
from waliya.integrations.signing import (
    build_signed_headers,
    compute_notification_signature,
    decrypt_destination_secret,
    encrypt_destination_secret,
    verify_notification_signature,
)

__all__ = [
    "NotificationDeliveryService",
    "InboundIngestionService",
    "SSRFValidationError",
    "validate_destination_url",
    "create_safe_http_client",
    "NotificationEventType",
    "NotificationPayload",
    "build_incident_created_payload",
    "build_incident_status_changed_payload",
    "build_detection_finding_created_payload",
    "build_threat_intel_matched_payload",
    "build_response_plan_state_changed_payload",
    "build_test_notification_payload",
    "encrypt_destination_secret",
    "decrypt_destination_secret",
    "compute_notification_signature",
    "verify_notification_signature",
    "build_signed_headers",
    "normalize_inbound_security_event",
    "NormalizedExternalEvent",
    "parse_event_timestamp",
    "normalize_severity",
    "map_event_type",
    "MAX_INBOUND_PAYLOAD_BYTES",
    "MAX_NESTING_DEPTH",
]
