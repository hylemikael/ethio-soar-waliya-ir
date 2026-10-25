"""Safe, configurable detection rule engine with an explicit operator allowlist."""

import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple, Union
from uuid import UUID, uuid4

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import DetectionRuleSchema, RuleCondition, RuleEvaluationResult, SeverityEnum
from waliya.db.models import FindingModel, RuleModel

logger = logging.getLogger("waliya.detection.rule_engine")

ALLOWED_OPERATORS = {
    "EQUALS",
    "NOT_EQUALS",
    "CONTAINS",
    "STARTS_WITH",
    "ENDS_WITH",
    "IN",
    "REGEX_MATCH",
    "GREATER_THAN",
    "LESS_THAN",
}


def extract_field(data: Dict[str, Any], field_path: str) -> Any:
    """Safely extract nested dictionary field values using dot notation.

    Prevents arbitrary attribute traversal and searches in normalized and raw payloads.
    """
    if not field_path or not isinstance(field_path, str):
        return None

    # Prohibit dangerous dunder traversal
    if "__" in field_path:
        return None

    parts = field_path.strip().split(".")
    curr: Any = data

    for part in parts:
        if isinstance(curr, dict) and part in curr:
            curr = curr[part]
        elif curr == data:
            # Check standard nested containers
            for container_name in ("attributes", "normalized", "raw_payload", "payload"):
                sub_dict = data.get(container_name)
                if isinstance(sub_dict, dict) and part in sub_dict:
                    curr = sub_dict[part]
                    break
            else:
                return None
        else:
            return None

    return curr


def evaluate_operator(operator: str, actual: Any, expected: Any) -> bool:
    """Evaluate a single condition using strict allowlisted comparison functions.

    Never uses eval, exec, or shell invocations.
    """
    op = operator.upper()
    if op not in ALLOWED_OPERATORS:
        raise ValueError(f"Disallowed or unknown rule operator: '{operator}'")

    if actual is None:
        return op == "NOT_EQUALS"

    if op == "EQUALS":
        if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
            return float(actual) == float(expected)
        if isinstance(actual, bool) or isinstance(expected, bool):
            return bool(actual) is bool(expected)
        return str(actual).strip().lower() == str(expected).strip().lower()

    if op == "NOT_EQUALS":
        if isinstance(actual, (int, float)) and isinstance(expected, (int, float)):
            return float(actual) != float(expected)
        if isinstance(actual, bool) or isinstance(expected, bool):
            return bool(actual) is not bool(expected)
        return str(actual).strip().lower() != str(expected).strip().lower()

    if op == "CONTAINS":
        if isinstance(actual, (list, tuple, set)):
            return expected in actual
        return str(expected).lower() in str(actual).lower()

    if op == "STARTS_WITH":
        return str(actual).startswith(str(expected))

    if op == "ENDS_WITH":
        return str(actual).endswith(str(expected))

    if op == "IN":
        if isinstance(expected, (list, tuple, set)):
            if isinstance(actual, (int, float)):
                return actual in expected or float(actual) in [float(x) for x in expected if isinstance(x, (int, float))]
            return str(actual).strip().lower() in [str(x).strip().lower() for x in expected]
        return str(actual) in str(expected)

    if op == "REGEX_MATCH":
        try:
            return bool(re.search(str(expected), str(actual)))
        except re.error as re_err:
            logger.warning("Invalid regex pattern '%s': %s", expected, re_err)
            return False

    if op == "GREATER_THAN":
        try:
            return float(actual) > float(expected)
        except (ValueError, TypeError):
            return False

    if op == "LESS_THAN":
        try:
            return float(actual) < float(expected)
        except (ValueError, TypeError):
            return False

    return False


class RuleEngine:
    """Deterministic security detection rule evaluation engine."""

    @staticmethod
    def evaluate_condition(condition: RuleCondition, event_data: Dict[str, Any]) -> Tuple[bool, str]:
        """Evaluate a single RuleCondition against an event dictionary."""
        actual_val = extract_field(event_data, condition.field)
        is_match = evaluate_operator(condition.operator, actual_val, condition.value)

        desc = (
            f"Condition '{condition.field} {condition.operator} {condition.value}' -> "
            f"{'MATCH' if is_match else 'NO_MATCH'} (observed: '{actual_val}')"
        )
        return is_match, desc

    @classmethod
    async def evaluate_rule(
        cls,
        rule: Union[DetectionRuleSchema, RuleModel],
        event_data: Dict[str, Any],
        redis_client: Optional[Redis] = None,
    ) -> RuleEvaluationResult:
        """Evaluate an entire rule against an event dictionary.

        Supports field-based condition matching and sliding window thresholds.
        """
        rule_id = rule.rule_id
        version = rule.version
        event_type = event_data.get("event_type")

        # 1. Event Type Check
        target_event_type = rule.event_type.value if hasattr(rule.event_type, "value") else str(rule.event_type)
        if event_type != target_event_type:
            return RuleEvaluationResult(
                matched=False,
                rule_id=rule_id,
                rule_version=version,
                matched_conditions=[],
                explanation=f"Event type '{event_type}' does not match rule target '{target_event_type}'",
            )

        # 2. Evaluate base conditions (AND logic)
        raw_conditions = rule.conditions
        if not raw_conditions:
            return RuleEvaluationResult(
                matched=False,
                rule_id=rule_id,
                rule_version=version,
                matched_conditions=[],
                explanation=f"Rule '{rule_id}' has no conditions defined",
            )
        matched_descs: List[str] = []

        for cond_item in raw_conditions:
            if isinstance(cond_item, dict):
                cond = RuleCondition(**cond_item)
            elif isinstance(cond_item, RuleCondition):
                cond = cond_item
            else:
                raise ValueError(f"Unrecognized condition format: {cond_item}")

            is_match, desc = cls.evaluate_condition(cond, event_data)
            if not is_match:
                return RuleEvaluationResult(
                    matched=False,
                    rule_id=rule_id,
                    rule_version=version,
                    matched_conditions=matched_descs,
                    explanation=f"Rule '{rule_id}' condition failed: {desc}",
                )
            matched_descs.append(desc)

        # 3. Stateful Window Aggregation Evaluation (for brute force & port scan rules)
        # Check if the rule is a stateful aggregation rule
        if redis_client is not None:
            window_matched, window_desc = await cls._evaluate_stateful_window(rule_id, event_data, redis_client)
            if not window_matched:
                return RuleEvaluationResult(
                    matched=False,
                    rule_id=rule_id,
                    rule_version=version,
                    matched_conditions=matched_descs,
                    explanation=window_desc,
                )
            if window_desc:
                matched_descs.append(window_desc)

        explanation = f"Rule '{rule_id}' matched successfully with {len(matched_descs)} satisfied condition(s)."
        return RuleEvaluationResult(
            matched=True,
            rule_id=rule_id,
            rule_version=version,
            matched_conditions=matched_descs,
            explanation=explanation,
        )

    @classmethod
    async def _evaluate_stateful_window(
        cls,
        rule_id: str,
        event_data: Dict[str, Any],
        redis_client: Redis,
    ) -> Tuple[bool, str]:
        """Sliding-window threshold evaluation using Redis sorted sets."""
        now_ts = datetime.now(timezone.utc).timestamp()

        # Isolate stateful sliding window keys for simulation runs to avoid cross-run & production pollution
        sim_run_id = (
            event_data.get("simulation_run_id")
            or (event_data.get("attributes") or {}).get("simulation_run_id")
            or (event_data.get("normalized", {}).get("attributes") or {}).get("simulation_run_id")
        )
        key_prefix = f"waliya:win:sim:{sim_run_id}" if sim_run_id else "waliya:win"

        if rule_id == "RULE-AUTH-001-BRUTEFORCE":
            # Threshold: >= 5 auth failures within 300 seconds
            window_sec = 300
            threshold = 5

            attrs = event_data.get("attributes") or event_data.get("normalized", {}).get("attributes") or {}
            src_ip = attrs.get("src_ip") or attrs.get("user") or str(event_data.get("agent_id"))
            key = f"{key_prefix}:auth_fail:{src_ip}"

            pipe = redis_client.pipeline()
            pipe.zremrangebyscore(key, 0, now_ts - window_sec)
            pipe.zadd(key, {str(event_data.get("event_id")): now_ts})
            pipe.zcard(key)
            pipe.expire(key, window_sec * 2)
            results = await pipe.execute()

            failure_count = results[2]
            if failure_count >= threshold:
                return True, f"Authentication failure threshold exceeded: {failure_count} failures in {window_sec}s window for entity '{src_ip}'"
            return False, f"Auth failure count {failure_count} is below threshold {threshold} in {window_sec}s"

        elif rule_id == "RULE-NET-001-PORTSCAN":
            # Threshold: >= 10 distinct destination ports within 60 seconds
            window_sec = 60
            threshold = 10

            attrs = event_data.get("attributes") or event_data.get("normalized", {}).get("attributes") or {}
            src_ip = attrs.get("src_ip") or str(event_data.get("agent_id"))
            dst_port = attrs.get("dst_port")
            dst_ip = attrs.get("dst_ip", "0.0.0.0")

            if dst_port is None:
                return False, "No destination port found in event"

            member = f"{dst_port}:{dst_ip}"
            key = f"{key_prefix}:portscan:{src_ip}"

            pipe = redis_client.pipeline()
            pipe.zremrangebyscore(key, 0, now_ts - window_sec)
            pipe.zadd(key, {member: now_ts})
            pipe.zcard(key)
            pipe.expire(key, window_sec * 2)
            results = await pipe.execute()

            distinct_ports = results[2]
            if distinct_ports >= threshold:
                return True, f"Port scan threshold exceeded: {distinct_ports} distinct ports scanned in {window_sec}s window by '{src_ip}'"
            return False, f"Distinct ports count {distinct_ports} is below threshold {threshold} in {window_sec}s"

        return True, ""

    @staticmethod
    async def is_suppressed(
        session: AsyncSession,
        dedup_key: str,
        dedup_window_seconds: int,
    ) -> bool:
        """Check if an active suppression window applies to the deduplication key.

        If a finding with this dedup_key was created within dedup_window_seconds, suppresses duplicate alerts.
        """
        if not dedup_key or dedup_window_seconds <= 0:
            return False

        cutoff = datetime.now(timezone.utc).timestamp() - dedup_window_seconds
        cutoff_dt = datetime.fromtimestamp(cutoff, tz=timezone.utc)

        query = (
            select(FindingModel.timestamp)
            .where(
                FindingModel.dedup_key == dedup_key,
                FindingModel.timestamp >= cutoff_dt,
            )
            .order_by(FindingModel.timestamp.desc())
            .limit(1)
        )
        res = await session.execute(query)
        recent_finding = res.scalars().first()
        return recent_finding is not None
