"""Tests verifying that simulation scenarios accurately satisfy or reject detection rule thresholds."""

import uuid
import pytest
from redis.asyncio import Redis

from waliya.config import settings
from waliya.detection.builtin_rules import BUILTIN_RULES
from waliya.detection.rule_engine import RuleEngine
from waliya_sim.scenarios.brute_force import BruteForceScenario
from waliya_sim.scenarios.port_scan import PortScanScenario
from waliya_sim.scenarios.priv_esc import PrivilegeEscalationScenario
from waliya_sim.scenarios.web_shell import WebShellScenario


def get_builtin_rule(rule_id: str):
    for r in BUILTIN_RULES:
        if r.rule_id == rule_id:
            return r
    raise ValueError(f"Rule {rule_id} not found in BUILTIN_RULES")


@pytest.mark.asyncio
async def test_brute_force_threshold_validation(sample_run_ids):
    scenario = BruteForceScenario()
    rule = get_builtin_rule(scenario.target_rule_id)
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)

    try:
        # Negative scenario: 4 events (below threshold of 5)
        neg_events = scenario.generate_events(
            run_id=sample_run_ids["run_id"] + "-neg",
            trace_id=sample_run_ids["trace_id"],
            agent_id=sample_run_ids["agent_id"],
            is_negative=True,
        )
        assert len(neg_events) == 4
        for ev in neg_events:
            event_dict = {
                "event_id": ev["event_id"],
                "event_type": ev["event_type"],
                "attributes": ev["payload"],
                "payload": ev["payload"],
            }
            res = await RuleEngine.evaluate_rule(rule, event_dict, redis_client=redis)
            assert res.matched is False

        # Positive scenario: 5 events (threshold reached on 5th event)
        pos_events = scenario.generate_events(
            run_id=sample_run_ids["run_id"] + "-pos",
            trace_id=sample_run_ids["trace_id"],
            agent_id=sample_run_ids["agent_id"],
            is_negative=False,
        )
        assert len(pos_events) == 5

        res_final = None
        for i, ev in enumerate(pos_events):
            event_dict = {
                "event_id": ev["event_id"],
                "event_type": ev["event_type"],
                "attributes": ev["payload"],
                "payload": ev["payload"],
            }
            res = await RuleEngine.evaluate_rule(rule, event_dict, redis_client=redis)
            if i < 4:
                assert res.matched is False
            else:
                assert res.matched is True
                res_final = res

        assert res_final is not None
        assert any("Authentication failure threshold exceeded" in c for c in res_final.matched_conditions)

    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_port_scan_threshold_validation(sample_run_ids):
    scenario = PortScanScenario()
    rule = get_builtin_rule(scenario.target_rule_id)
    redis = Redis.from_url(settings.REDIS_URL, decode_responses=True)

    try:
        # Negative scenario: 5 distinct ports (below threshold of 10)
        neg_events = scenario.generate_events(
            run_id=sample_run_ids["run_id"] + "-neg",
            trace_id=sample_run_ids["trace_id"],
            agent_id=sample_run_ids["agent_id"],
            is_negative=True,
        )
        for ev in neg_events:
            event_dict = {
                "event_id": ev["event_id"],
                "event_type": ev["event_type"],
                "attributes": ev["payload"],
                "payload": ev["payload"],
            }
            res = await RuleEngine.evaluate_rule(rule, event_dict, redis_client=redis)
            assert res.matched is False

        # Positive scenario: 10 distinct ports (threshold met on 10th)
        pos_events = scenario.generate_events(
            run_id=sample_run_ids["run_id"] + "-pos",
            trace_id=sample_run_ids["trace_id"],
            agent_id=sample_run_ids["agent_id"],
            is_negative=False,
        )
        for i, ev in enumerate(pos_events):
            event_dict = {
                "event_id": ev["event_id"],
                "event_type": ev["event_type"],
                "attributes": ev["payload"],
                "payload": ev["payload"],
            }
            res = await RuleEngine.evaluate_rule(rule, event_dict, redis_client=redis)
            if i < 9:
                assert res.matched is False
            else:
                assert res.matched is True

    finally:
        await redis.aclose()


@pytest.mark.asyncio
async def test_web_shell_rule_validation(sample_run_ids):
    scenario = WebShellScenario()
    rule = get_builtin_rule(scenario.target_rule_id)

    # Positive event (.php in /var/www)
    pos_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=False,
    )
    res_pos = await RuleEngine.evaluate_rule(
        rule,
        {"event_id": pos_events[0]["event_id"], "event_type": pos_events[0]["event_type"], "attributes": pos_events[0]["payload"]},
    )
    assert res_pos.matched is True

    # Negative event (.png in /var/www)
    neg_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=True,
    )
    res_neg = await RuleEngine.evaluate_rule(
        rule,
        {"event_id": neg_events[0]["event_id"], "event_type": neg_events[0]["event_type"], "attributes": neg_events[0]["payload"]},
    )
    assert res_neg.matched is False


@pytest.mark.asyncio
async def test_privilege_escalation_rule_validation(sample_run_ids):
    scenario = PrivilegeEscalationScenario()
    rule = get_builtin_rule(scenario.target_rule_id)

    # Positive: sudo by non-root operator
    pos_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=False,
    )
    res_pos = await RuleEngine.evaluate_rule(
        rule,
        {"event_id": pos_events[0]["event_id"], "event_type": pos_events[0]["event_type"], "attributes": pos_events[0]["payload"]},
    )
    assert res_pos.matched is True

    # Negative: sudo by root
    neg_events = scenario.generate_events(
        run_id=sample_run_ids["run_id"],
        trace_id=sample_run_ids["trace_id"],
        agent_id=sample_run_ids["agent_id"],
        is_negative=True,
    )
    res_neg = await RuleEngine.evaluate_rule(
        rule,
        {"event_id": neg_events[0]["event_id"], "event_type": neg_events[0]["event_type"], "attributes": neg_events[0]["payload"]},
    )
    assert res_neg.matched is False
