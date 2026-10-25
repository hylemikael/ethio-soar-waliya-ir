"""Unit tests for external security event normalization, observable mapping, and bounds checking."""

from datetime import datetime, timezone
from uuid import uuid4

import pytest
from fastapi import HTTPException

from waliya.contracts import EventTypeEnum, SeverityEnum
from waliya.correlation.entity_extractor import EntityExtractor, EntityTypeEnum, RelationTypeEnum
from waliya.db.models import InboundSourceModel
from waliya.integrations.normalization import (
    check_nesting_depth_and_prohibited_keys,
    normalize_inbound_security_event,
    normalize_severity,
    parse_event_timestamp,
)


def _make_source(provider_type: str = "GENERIC") -> InboundSourceModel:
    return InboundSourceModel(
        id=uuid4(),
        source_id="test-source",
        name="Test Security Feed",
        provider_type=provider_type,
        is_enabled=True,
        auth_type="HMAC_SHA256",
        shared_secret_enc="mock-encrypted-secret",
        permitted_event_types=[],
    )


@pytest.mark.unit
def test_normalize_generic_profile():
    """Verify GENERIC profile normalizes standard fields and maps observables."""
    source = _make_source("GENERIC")
    payload = {
        "schema_version": "1.0",
        "external_event_id": "gen-1001",
        "event_type": "EXTERNAL_ALERT",
        "severity": "CRITICAL",
        "title": "Malware Outbreak",
        "description": "Suspicious binary detected across cluster",
        "attributes": {
            "src_ip": "198.51.100.22",
            "dst_ip": "203.0.113.88",
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "hostname": "workstation-01",
        },
    }
    normalized = normalize_inbound_security_event(source, payload)
    assert normalized.external_event_id == "gen-1001"
    assert normalized.source_id == "test-source"
    assert normalized.provider_type == "GENERIC"
    assert normalized.event_type == EventTypeEnum.EXTERNAL_ALERT.value
    assert normalized.severity == SeverityEnum.CRITICAL.value
    assert normalized.title == "Malware Outbreak"
    assert normalized.attributes["src_ip"] == "198.51.100.22"

    dict_out = normalized.to_normalized_payload()
    assert dict_out["is_external"] is True
    assert dict_out["is_simulation"] is False
    assert dict_out["provenance"] == "EXTERNAL"
    assert dict_out["external_source"] == "test-source"


@pytest.mark.unit
def test_normalize_edr_profile():
    """Verify EDR profile maps endpoint detection fields (CrowdStrike/Defender style)."""
    source = _make_source("EDR")
    payload = {
        "detection_id": "cs-alert-9999",
        "created_timestamp": "2026-10-25T14:30:00Z",
        "severity_score": 85,
        "tactic": "Execution",
        "detection_name": "Suspicious PowerShell Invocations",
        "device_name": "fin-srv-02",
        "file_name": "powershell.exe",
        "command_line": "powershell.exe -enc AAAA...",
        "sha256": "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
        "user_name": "svc_accounting",
    }
    normalized = normalize_inbound_security_event(source, payload)
    assert normalized.external_event_id == "cs-alert-9999"
    assert normalized.provider_type == "EDR"
    assert normalized.severity == SeverityEnum.CRITICAL.value
    assert "Execution" in normalized.title
    assert normalized.attributes["hostname"] == "fin-srv-02"
    assert normalized.attributes["process_name"] == "powershell.exe"
    assert normalized.attributes["user"] == "svc_accounting"
    assert normalized.attributes["sha256"] == payload["sha256"]


@pytest.mark.unit
def test_normalize_siem_profile():
    """Verify SIEM profile maps log and network correlation alerts (Splunk/Elastic style)."""
    source = _make_source("SIEM")
    payload = {
        "log_id": "splunk-correl-5555",
        "@timestamp": "2026-10-25T14:00:00.000Z",
        "urgency": "high",
        "search_name": "Port Scan Detected",
        "src_ip": "10.0.5.12",
        "dest_ip": "10.0.5.1",
        "dest_port": 443,
        "protocol": "TCP",
    }
    normalized = normalize_inbound_security_event(source, payload)
    assert normalized.external_event_id == "splunk-correl-5555"
    assert normalized.provider_type == "SIEM"
    assert normalized.severity == SeverityEnum.HIGH.value
    assert "Port Scan Detected" in normalized.title
    assert normalized.attributes["src_ip"] == "10.0.5.12"
    assert normalized.attributes["dst_ip"] == "10.0.5.1"
    assert normalized.attributes["dst_port"] == 443


@pytest.mark.unit
def test_unsupported_provider_rejected():
    """Verify unsupported provider types fail closed with 400 Bad Request."""
    source = _make_source("UNSUPPORTED_VENDOR_XYZ")
    payload = {"id": "123", "title": "Test"}
    with pytest.raises(HTTPException) as exc_info:
        normalize_inbound_security_event(source, payload)
    assert exc_info.value.status_code == 400
    assert "Unsupported inbound provider type" in exc_info.value.detail


@pytest.mark.unit
def test_prohibited_command_keys_rejected():
    """Verify dangerous command injection keys are strictly rejected."""
    source = _make_source("GENERIC")
    dangerous_payload = {
        "external_event_id": "attack-1",
        "__exec__": "import os; os.system('cat /etc/passwd')",
    }
    with pytest.raises(HTTPException) as exc_info:
        normalize_inbound_security_event(source, dangerous_payload)
    assert exc_info.value.status_code == 400
    assert "Prohibited attribute" in exc_info.value.detail


@pytest.mark.unit
def test_internal_reserved_keys_rejected():
    """Verify external events cannot inject platform approval hashes or tokens."""
    source = _make_source("GENERIC")
    spoof_payload = {
        "external_event_id": "spoof-1",
        "approval_hash": "fabricated_sha256_hash",
    }
    with pytest.raises(HTTPException) as exc_info:
        normalize_inbound_security_event(source, spoof_payload)
    assert exc_info.value.status_code == 400
    assert "Forbidden attempt to set internal platform attribute" in exc_info.value.detail


@pytest.mark.unit
def test_nesting_depth_limit_enforced():
    """Verify deeply nested JSON (exceeding depth 5) is rejected."""
    deep_dict = {"a": {"b": {"c": {"d": {"e": {"f": "too deep"}}}}}}
    with pytest.raises(HTTPException) as exc_info:
        check_nesting_depth_and_prohibited_keys(deep_dict)
    assert exc_info.value.status_code == 422
    assert "nesting depth" in exc_info.value.detail


@pytest.mark.unit
def test_severity_normalization_defensive_fallbacks():
    """Verify severity normalizer maps strings and scores safely without crashes."""
    assert normalize_severity("CRITICAL") == "CRITICAL"
    assert normalize_severity("severe") == "CRITICAL"
    assert normalize_severity(90) == "CRITICAL"
    assert normalize_severity("HIGH") == "HIGH"
    assert normalize_severity(65) == "HIGH"
    assert normalize_severity("WARN") == "MEDIUM"
    assert normalize_severity(45) == "MEDIUM"
    assert normalize_severity("LOW") == "LOW"
    assert normalize_severity(25) == "LOW"
    assert normalize_severity("INFO") == "INFORMATIONAL"
    assert normalize_severity(1) == "INFORMATIONAL"
    assert normalize_severity(10) == "CRITICAL"  # 10/10 is critical
    assert normalize_severity(15) == "INFORMATIONAL"  # 15/100 is informational

    # Defensive fallback for unknown or None
    assert normalize_severity(None) == "MEDIUM"
    assert normalize_severity("UNKNOWN_VENDOR_SEV") == "MEDIUM"


@pytest.mark.unit
def test_entity_extraction_from_external_alert():
    """Verify EntityExtractor seamlessly extracts attack graph nodes and edges from EXTERNAL_ALERT observables."""
    event_data = {
        "event_id": "test-ext-event-id",
        "event_type": "EXTERNAL_ALERT",
        "source": "external:crowdstrike-edr-prod",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "attributes": {
            "external_source": "crowdstrike-edr-prod",
            "hostname": "bastion-host",
            "src_ip": "192.168.1.100",
            "dst_ip": "203.0.113.50",
            "dst_port": 443,
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "file_path": "/tmp/malicious.elf",
            "user": "root",
            "process_name": "malicious.elf",
        },
    }

    entities, relationships = EntityExtractor.extract(event_data)
    entity_ids = {e.id for e in entities}

    # Host entity extracted
    assert "host:bastion-host" in entity_ids

    # IP entities extracted
    assert "ip:192.168.1.100" in entity_ids
    assert "ip:203.0.113.50" in entity_ids

    # File entity extracted
    assert "file:hash:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in entity_ids

    # User entity extracted
    assert "user:root" in entity_ids

    # Process entity extracted
    assert "process:external:malicious.elf" in entity_ids

    # Network connection relationship between IPs
    net_rel = [r for r in relationships if r.relation == RelationTypeEnum.CONNECTED_TO]
    assert len(net_rel) > 0
    assert net_rel[0].source_id == "ip:192.168.1.100"
    assert net_rel[0].target_id == "ip:203.0.113.50"
