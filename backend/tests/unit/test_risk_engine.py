"""Unit tests for the explainable composite risk scoring engine."""

import pytest
from waliya.incidents.risk_engine import compute_incident_risk


def test_empty_findings_risk():
    score, expl = compute_incident_risk([], [], [])
    assert score == 0.0
    assert "No findings" in expl["explanation"]


def test_base_severity_and_confidence():
    # Single HIGH severity finding with 1.0 confidence
    findings = [{
        "severity": "HIGH",
        "confidence": 1.0,
        "dedup_key": "rule1:ent1",
    }]
    score, expl = compute_incident_risk(findings, ["host:agent1"], ["T1059"])
    assert score == 75.0
    assert expl["base_severity"] == "HIGH"
    assert expl["base_weight"] == 75.0
    assert expl["confidence_factor"] == 1.0

    # Same finding with lower confidence (0.8)
    findings_low_conf = [{
        "severity": "HIGH",
        "confidence": 0.8,
        "dedup_key": "rule1:ent1",
    }]
    score_low, expl_low = compute_incident_risk(findings_low_conf, ["host:agent1"], ["T1059"])
    assert score_low == 60.0  # 75 * 0.8
    assert expl_low["confidence_factor"] == 0.8


def test_multi_entity_correlation_multiplier():
    findings = [{
        "severity": "MEDIUM",
        "confidence": 1.0,
        "dedup_key": "rule1:ent1",
    }]
    # 2 entity types (Host + User): 1.10x multiplier
    score_2, expl_2 = compute_incident_risk(findings, ["host:agent1", "user:admin"], ["T1059"])
    assert score_2 == 55.0  # 50 * 1.10
    assert expl_2["multi_entity_multiplier"] == 1.10

    # 3+ entity types (Host + User + Process + File + IP): 1.20x multiplier
    entities_4 = ["host:agent1", "user:admin", "process:agent1:123:curl", "file:agent1:/tmp/x"]
    score_4, expl_4 = compute_incident_risk(findings, entities_4, ["T1059"])
    assert score_4 == 60.0  # 50 * 1.20
    assert expl_4["multi_entity_multiplier"] == 1.20


def test_multi_stage_progression_bonus():
    findings = [{
        "severity": "MEDIUM",
        "confidence": 1.0,
        "dedup_key": "rule1:ent1",
    }]
    # 2 MITRE ATT&CK techniques: +5 bonus
    score_2t, expl_2t = compute_incident_risk(findings, ["host:agent1"], ["T1046", "T1110"])
    assert score_2t == 55.0  # 50 + 5
    assert expl_2t["multi_stage_bonus"] == 5.0

    # 3+ MITRE ATT&CK techniques: +10 bonus
    score_3t, expl_3t = compute_incident_risk(findings, ["host:agent1"], ["T1046", "T1110", "T1548"])
    assert score_3t == 60.0  # 50 + 10
    assert expl_3t["multi_stage_bonus"] == 10.0


def test_behavioral_anomaly_bonus():
    # Finding from EWMA anomaly with Z-score = 5.0
    findings = [{
        "severity": "HIGH",
        "confidence": 1.0,
        "dedup_key": "anom:auth:10.0.0.1",
        "explanation": {"z_score": 5.0, "metric_name": "auth_velocity"},
    }]
    score, expl = compute_incident_risk(findings, ["host:agent1"], ["T1110"])
    # Base: 75.0, Anomaly bonus: min(15.0, (5.0 - 3.0) * 3.0) = 6.0 -> 81.0
    assert score == 81.0
    assert expl["anomaly_bonus"] == 6.0


def test_deduplication_prevents_score_inflation():
    """Verify that multiple alerts with the same dedup_key do not inflate the risk score."""
    # 5 identical brute-force findings for the same entity
    findings = [
        {"severity": "HIGH", "confidence": 1.0, "dedup_key": "RULE-AUTH-001:10.0.0.1"},
        {"severity": "HIGH", "confidence": 1.0, "dedup_key": "RULE-AUTH-001:10.0.0.1"},
        {"severity": "HIGH", "confidence": 1.0, "dedup_key": "RULE-AUTH-001:10.0.0.1"},
        {"severity": "HIGH", "confidence": 1.0, "dedup_key": "RULE-AUTH-001:10.0.0.1"},
        {"severity": "HIGH", "confidence": 1.0, "dedup_key": "RULE-AUTH-001:10.0.0.1"},
    ]
    score_single, _ = compute_incident_risk([findings[0]], ["host:agent1", "ip:10.0.0.1"], ["T1110"])
    score_multiple, expl_mult = compute_incident_risk(findings, ["host:agent1", "ip:10.0.0.1"], ["T1110"])

    assert score_multiple == score_single
    assert expl_mult["unique_findings_count"] == 1
    assert expl_mult["raw_findings_count"] == 5


def test_score_clamping():
    """Verify that composite risk score never exceeds 100.0."""
    findings = [{
        "severity": "CRITICAL",
        "confidence": 1.0,
        "dedup_key": "crit:1",
        "explanation": {"z_score": 10.0},
    }]
    entities = ["host:agent1", "user:root", "process:1:bash", "file:/etc/shadow", "ip:1.2.3.4"]
    mitre = ["T1", "T2", "T3", "T4"]
    score, expl = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        is_critical_asset=True,
        threat_intel_confidence=90,
    )
    assert score <= 100.0
    assert score == 100.0
    assert "Risk score 100.0/100" in expl["decision_reason"]
