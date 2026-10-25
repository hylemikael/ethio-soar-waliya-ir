"""Unit tests for telemetry event normalization and semantic validation."""

from datetime import datetime, timezone
from uuid import uuid4
import pytest
from fastapi import HTTPException

from waliya.contracts import EventTypeEnum, SecurityEventEnvelope, SeverityEnum
from waliya.telemetry.normalizer import MAX_PAYLOAD_SIZE_BYTES, normalize_event


def make_envelope(event_type: EventTypeEnum, payload: dict, agent_id=None) -> SecurityEventEnvelope:
    return SecurityEventEnvelope(
        event_id=uuid4(),
        event_type=event_type,
        severity=SeverityEnum.LOW,
        timestamp=datetime.now(timezone.utc),
        source="unit_test_sensor",
        agent_id=agent_id,
        payload=payload,
    )


def test_file_integrity_normalization_success():
    agent_id = uuid4()
    payload = {
        "file_path": "/etc/shadow",
        "action": "modified",
        "sha256": "ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890",
        "size_bytes": 1024,
        "is_executable": False,
    }
    event = make_envelope(EventTypeEnum.FILE_INTEGRITY, payload, agent_id=agent_id)
    normalized = normalize_event(event, agent_id)

    assert normalized["event_type"] == "FILE_INTEGRITY"
    assert normalized["attributes"]["file_path"] == "/etc/shadow"
    assert normalized["attributes"]["action"] == "MODIFIED"
    assert normalized["attributes"]["sha256"] == payload["sha256"].lower()
    assert normalized["attributes"]["size_bytes"] == 1024
    assert normalized["attributes"]["is_executable"] is False


def test_file_integrity_missing_path_fails():
    agent_id = uuid4()
    event = make_envelope(EventTypeEnum.FILE_INTEGRITY, {"file_path": "   "}, agent_id=agent_id)
    with pytest.raises(HTTPException) as exc_info:
        normalize_event(event, agent_id)
    assert exc_info.value.status_code == 422
    assert "file_path" in exc_info.value.detail


def test_process_execution_normalization_success():
    agent_id = uuid4()
    payload = {
        "pid": 1337,
        "ppid": 1,
        "exe": "/usr/bin/curl",
        "cmdline": "curl -s http://example.com",
        "username": "root",
        "sha256": "E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855",
    }
    event = make_envelope(EventTypeEnum.PROCESS_EXECUTION, payload, agent_id=agent_id)
    normalized = normalize_event(event, agent_id)

    assert normalized["event_type"] == "PROCESS_EXECUTION"
    assert normalized["attributes"]["pid"] == 1337
    assert normalized["attributes"]["ppid"] == 1
    assert normalized["attributes"]["exe"] == "/usr/bin/curl"
    assert normalized["attributes"]["username"] == "root"


def test_process_execution_invalid_pid_fails():
    agent_id = uuid4()
    event = make_envelope(EventTypeEnum.PROCESS_EXECUTION, {"pid": -5, "exe": "/bin/sh"}, agent_id=agent_id)
    with pytest.raises(HTTPException) as exc_info:
        normalize_event(event, agent_id)
    assert exc_info.value.status_code == 422
    assert "pid" in exc_info.value.detail


def test_authentication_normalization_success():
    agent_id = uuid4()
    payload = {
        "service": "sshd",
        "user": "ubuntu",
        "status": "SUCCESS",
        "src_ip": "192.168.1.100",
    }
    event = make_envelope(EventTypeEnum.AUTHENTICATION, payload, agent_id=agent_id)
    normalized = normalize_event(event, agent_id)

    assert normalized["event_type"] == "AUTHENTICATION"
    assert normalized["attributes"]["service"] == "sshd"
    assert normalized["attributes"]["user"] == "ubuntu"
    assert normalized["attributes"]["status"] == "SUCCESS"
    assert normalized["attributes"]["src_ip"] == "192.168.1.100"


def test_network_connection_normalization_success():
    agent_id = uuid4()
    payload = {
        "src_ip": "10.0.0.5",
        "src_port": 54321,
        "dst_ip": "1.1.1.1",
        "dst_port": 53,
        "protocol": "udp",
        "direction": "outbound",
    }
    event = make_envelope(EventTypeEnum.NETWORK_CONNECTION, payload, agent_id=agent_id)
    normalized = normalize_event(event, agent_id)

    assert normalized["event_type"] == "NETWORK_CONNECTION"
    assert normalized["attributes"]["dst_port"] == 53
    assert normalized["attributes"]["protocol"] == "UDP"
    assert normalized["attributes"]["direction"] == "OUTBOUND"


def test_network_connection_invalid_port_fails():
    agent_id = uuid4()
    event = make_envelope(EventTypeEnum.NETWORK_CONNECTION, {"dst_port": 70000}, agent_id=agent_id)
    with pytest.raises(HTTPException) as exc_info:
        normalize_event(event, agent_id)
    assert exc_info.value.status_code == 422
    assert "dst_port" in exc_info.value.detail


def test_system_log_normalization_success():
    agent_id = uuid4()
    payload = {
        "facility": "auth",
        "level": "warning",
        "message": "Failed password for invalid user admin",
    }
    event = make_envelope(EventTypeEnum.SYSTEM_LOG, payload, agent_id=agent_id)
    normalized = normalize_event(event, agent_id)

    assert normalized["event_type"] == "SYSTEM_LOG"
    assert normalized["attributes"]["facility"] == "auth"
    assert normalized["attributes"]["level"] == "WARNING"
    assert "Failed password" in normalized["attributes"]["message"]


def test_prohibited_command_injection_keys_rejected():
    agent_id = uuid4()
    prohibited_keys = ["__exec__", "shell_cmd", "eval", "raw_command", "system_exec", "bash_c"]
    for bad_key in prohibited_keys:
        event = make_envelope(
            EventTypeEnum.SYSTEM_LOG,
            {"message": "log", bad_key: "rm -rf /"},
            agent_id=agent_id,
        )
        with pytest.raises(HTTPException) as exc_info:
            normalize_event(event, agent_id)
        assert exc_info.value.status_code == 400
        assert "Prohibited telemetry attribute" in exc_info.value.detail


def test_oversized_payload_rejected():
    agent_id = uuid4()
    large_payload = {"message": "A" * (MAX_PAYLOAD_SIZE_BYTES + 100)}
    event = make_envelope(EventTypeEnum.SYSTEM_LOG, large_payload, agent_id=agent_id)
    with pytest.raises(HTTPException) as exc_info:
        normalize_event(event, agent_id)
    assert exc_info.value.status_code == 422
    assert "exceeds maximum allowed size" in exc_info.value.detail
