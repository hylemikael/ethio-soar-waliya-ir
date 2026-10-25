"""Pre-packaged initial security detection rules for Waliya-IR."""

from typing import List
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import DetectionRuleSchema, EventTypeEnum, RuleCondition, SeverityEnum
from waliya.db.models import RuleModel

BUILTIN_RULES: List[DetectionRuleSchema] = [
    # 1. Web Shell Detection
    DetectionRuleSchema(
        rule_id="RULE-FIM-004-WEBSHELL",
        version=1,
        name="Suspicious Web Shell Script Activity in Web Directory",
        description="Detects newly created or modified executable script files (.php, .phtml, .jsp, .cgi, .sh) in standard web server root paths.",
        severity=SeverityEnum.HIGH,
        event_type=EventTypeEnum.FILE_INTEGRITY,
        conditions=[
            RuleCondition(
                field="attributes.file_path",
                operator="REGEX_MATCH",
                value=r"(?i)/(var/www|usr/share/nginx|srv/http|srv/www)/.*(\.php|\.phtml|\.jsp|\.cgi|\.sh)$",
            ),
            RuleCondition(
                field="attributes.action",
                operator="IN",
                value=["CREATED", "MODIFIED"],
            ),
        ],
        mitre_attack_ids=["T1505.003"],
        dedup_window_seconds=300,
        is_active=True,
    ),
    # 2. Authentication Brute Force
    DetectionRuleSchema(
        rule_id="RULE-AUTH-001-BRUTEFORCE",
        version=1,
        name="Excessive Authentication Failures (Brute Force)",
        description="Detects multiple authentication failures from a single source or account exceeding 5 failures in a 5-minute sliding window.",
        severity=SeverityEnum.HIGH,
        event_type=EventTypeEnum.AUTHENTICATION,
        conditions=[
            RuleCondition(
                field="attributes.status",
                operator="EQUALS",
                value="FAILURE",
            ),
        ],
        mitre_attack_ids=["T1110.001"],
        dedup_window_seconds=300,
        is_active=True,
    ),
    # 3. Port Scanning
    DetectionRuleSchema(
        rule_id="RULE-NET-001-PORTSCAN",
        version=1,
        name="Anomalous Port Scanning Activity",
        description="Detects a single source IP contacting 10 or more distinct destination ports within a 60-second sliding window.",
        severity=SeverityEnum.MEDIUM,
        event_type=EventTypeEnum.NETWORK_CONNECTION,
        conditions=[
            RuleCondition(
                field="attributes.dst_port",
                operator="GREATER_THAN",
                value=0,
            ),
        ],
        mitre_attack_ids=["T1046"],
        dedup_window_seconds=300,
        is_active=True,
    ),
    # 4. Privilege Escalation
    DetectionRuleSchema(
        rule_id="RULE-PROC-001-PRIVILEGE-ESC",
        version=1,
        name="Suspicious Privilege Escalation Execution",
        description="Detects non-root users executing privilege elevation binaries (sudo, su, pkexec, doas) to acquire elevated credentials.",
        severity=SeverityEnum.HIGH,
        event_type=EventTypeEnum.PROCESS_EXECUTION,
        conditions=[
            RuleCondition(
                field="attributes.exe",
                operator="REGEX_MATCH",
                value=r"(?i)/(sudo|su|pkexec|doas)$",
            ),
            RuleCondition(
                field="attributes.username",
                operator="NOT_EQUALS",
                value="root",
            ),
        ],
        mitre_attack_ids=["T1548.003"],
        dedup_window_seconds=300,
        is_active=True,
    ),
]


async def seed_builtin_rules(session: AsyncSession) -> int:
    """Synchronize built-in detection rules with the PostgreSQL database.

    Inserts missing rules and preserves active state and versioning.
    """
    seeded_count = 0
    for rule_schema in BUILTIN_RULES:
        query = select(RuleModel).where(RuleModel.rule_id == rule_schema.rule_id)
        res = await session.execute(query)
        existing_rule = res.scalars().first()

        conditions_dict = [c.model_dump() for c in rule_schema.conditions]

        if not existing_rule:
            db_rule = RuleModel(
                rule_id=rule_schema.rule_id,
                version=rule_schema.version,
                name=rule_schema.name,
                description=rule_schema.description,
                severity=rule_schema.severity.value,
                event_type=rule_schema.event_type.value,
                conditions=conditions_dict,
                mitre_attack_ids=rule_schema.mitre_attack_ids,
                dedup_window_seconds=rule_schema.dedup_window_seconds,
                is_active=rule_schema.is_active,
            )
            session.add(db_rule)
            seeded_count += 1

    if seeded_count > 0:
        await session.commit()

    return seeded_count
