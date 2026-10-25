"""Unit tests for defensive response action parameter validation."""

import pytest
from waliya_agent.response.validator import ActionValidator


def test_validator_block_ip_success():
    """Verify valid public and private IP validation."""
    params = {"ip_address": "198.51.100.24", "direction": "IN"}
    validated = ActionValidator.validate_block_ip(params, server_ip="10.0.0.1")
    assert validated["ip_address"] == "198.51.100.24"
    assert validated["direction"] == "IN"

    # Default direction BOTH
    validated_default = ActionValidator.validate_block_ip({"ip_address": "203.0.113.5"})
    assert validated_default["direction"] == "BOTH"


def test_validator_block_ip_rejects_unspecified():
    """Verify rejection of 0.0.0.0 or :: unspecified addresses."""
    with pytest.raises(ValueError, match="unspecified address"):
        ActionValidator.validate_block_ip({"ip_address": "0.0.0.0"})

    with pytest.raises(ValueError, match="unspecified address"):
        ActionValidator.validate_block_ip({"ip_address": "::"})


def test_validator_block_ip_rejects_protected_subnets():
    """Verify rejection of loopback, link-local, multicast, and broadcast IPs."""
    # IPv4 Loopback
    with pytest.raises(ValueError, match="protected network"):
        ActionValidator.validate_block_ip({"ip_address": "127.0.0.1"})

    # IPv4 Loopback range
    with pytest.raises(ValueError, match="protected network"):
        ActionValidator.validate_block_ip({"ip_address": "127.255.0.1"})

    # IPv6 Loopback
    with pytest.raises(ValueError, match="protected network"):
        ActionValidator.validate_block_ip({"ip_address": "::1"})

    # IPv4 Link-Local
    with pytest.raises(ValueError, match="protected network"):
        ActionValidator.validate_block_ip({"ip_address": "169.254.10.20"})

    # IPv4 Multicast
    with pytest.raises(ValueError, match="protected network"):
        ActionValidator.validate_block_ip({"ip_address": "224.0.0.1"})

    # IPv4 Broadcast
    with pytest.raises(ValueError, match="protected network"):
        ActionValidator.validate_block_ip({"ip_address": "255.255.255.255"})


def test_validator_block_ip_rejects_server_ip():
    """Verify refusal to block management server IP to prevent bricking communication."""
    server = "192.168.1.50"
    with pytest.raises(ValueError, match="management server IP"):
        ActionValidator.validate_block_ip({"ip_address": "192.168.1.50"}, server_ip=server)


def test_validator_block_ip_rejects_malformed_inputs():
    """Verify rejection of non-string, missing, or malformed IP addresses."""
    with pytest.raises(ValueError, match="non-empty string"):
        ActionValidator.validate_block_ip({"ip_address": ""})

    with pytest.raises(ValueError, match="non-empty string"):
        ActionValidator.validate_block_ip({"ip_address": None})

    with pytest.raises(ValueError, match="Invalid IP address format"):
        ActionValidator.validate_block_ip({"ip_address": "not-an-ip; rm -rf /"})


def test_validator_unblock_ip():
    """Verify unblock IP parameter checks."""
    valid = ActionValidator.validate_unblock_ip({"ip_address": "198.51.100.25"})
    assert valid["ip_address"] == "198.51.100.25"

    with pytest.raises(ValueError, match="non-empty string"):
        ActionValidator.validate_unblock_ip({"ip_address": ""})


def test_validator_terminate_process_success():
    """Verify valid process termination parameters."""
    res = ActionValidator.validate_terminate_process({"pid": 1234, "process_name": "malware_miner"})
    assert res["pid"] == 1234
    assert res["process_name"] == "malware_miner"
    assert res["kill_tree"] is False


def test_validator_terminate_process_rejects_invalid_pid():
    """Verify rejection of non-positive PID or PID 1."""
    with pytest.raises(ValueError, match="positive integer 'pid' > 1"):
        ActionValidator.validate_terminate_process({"pid": 1, "process_name": "init"})

    with pytest.raises(ValueError, match="positive integer 'pid' > 1"):
        ActionValidator.validate_terminate_process({"pid": 0, "process_name": "kernel"})

    with pytest.raises(ValueError, match="positive integer 'pid' > 1"):
        ActionValidator.validate_terminate_process({"pid": -5, "process_name": "bad"})


def test_validator_terminate_process_rejects_protected_processes():
    """Verify rejection of critical OS system services and the agent itself."""
    for proc in ["systemd", "init", "sshd", "login", "waliya-agent", "dbus-daemon"]:
        with pytest.raises(ValueError, match="protected system process"):
            ActionValidator.validate_terminate_process({"pid": 456, "process_name": proc})


def test_validator_collect_forensic():
    """Verify forensic artifact parameters and path containment."""
    # Valid artifact type
    res = ActionValidator.validate_collect_forensic({"artifact_type": "LOGS"})
    assert res["artifact_type"] == "LOGS"

    # Unsupported artifact type
    with pytest.raises(ValueError, match="Unsupported forensic artifact_type"):
        ActionValidator.validate_collect_forensic({"artifact_type": "ARBITRARY_CODE"})

    # Prohibited directory traversal
    with pytest.raises(ValueError, match="Prohibited forensic destination path traversal"):
        ActionValidator.validate_collect_forensic({"artifact_type": "LOGS", "destination_path": "../../../etc/passwd"})

    with pytest.raises(ValueError, match="Prohibited forensic destination path traversal"):
        ActionValidator.validate_collect_forensic({"artifact_type": "LOGS", "destination_path": "/etc/shadow"})
