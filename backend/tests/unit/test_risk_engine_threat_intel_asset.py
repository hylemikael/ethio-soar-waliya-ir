"""Unit tests for asset context and threat intelligence risk scoring calculations."""

import pytest

from waliya.incidents.risk_engine import compute_incident_risk


def test_asset_criticality_scaling():
    findings = [{
        "severity": "HIGH",
        "confidence": 1.0,
        "dedup_key": "rule-1:agent-1",
    }]
    entities = ["host:sensor-01"]
    mitre = ["T1110"]

    # 1. CRITICAL asset receives +10.0 bonus
    score_crit, expl_crit = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        asset_criticality="CRITICAL",
    )
    assert expl_crit["asset_criticality"] == "CRITICAL"
    assert expl_crit["asset_importance_bonus"] == 10.0
    assert "asset context [CRITICAL] (+10.0)" in expl_crit["decision_reason"]

    # 2. HIGH asset receives +5.0 bonus
    score_high, expl_high = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        asset_criticality="HIGH",
    )
    assert expl_high["asset_criticality"] == "HIGH"
    assert expl_high["asset_importance_bonus"] == 5.0
    assert score_crit == score_high + 5.0

    # 3. MEDIUM asset receives +2.0 bonus
    score_med, expl_med = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        asset_criticality="MEDIUM",
    )
    assert expl_med["asset_criticality"] == "MEDIUM"
    assert expl_med["asset_importance_bonus"] == 2.0

    # 4. LOW asset receives +0.0 bonus
    score_low, expl_low = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        asset_criticality="LOW",
    )
    assert expl_low["asset_criticality"] == "LOW"
    assert expl_low["asset_importance_bonus"] == 0.0

    # 5. UNASSIGNED (None) asset receives +0.0 bonus and is NOT marked as LOW
    score_unassigned, expl_unassigned = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        asset_criticality=None,
    )
    assert expl_unassigned["asset_criticality"] == "UNASSIGNED"
    assert expl_unassigned["asset_importance_bonus"] == 0.0
    assert score_unassigned == score_low


def test_threat_intelligence_confidence_and_bonus():
    findings = [{
        "severity": "MEDIUM",
        "confidence": 1.0,
        "dedup_key": "rule-2:agent-1",
    }]
    entities = ["ip:198.51.100.25"]
    mitre = ["T1046"]

    # 1. High confidence indicator (100) -> 100 * 0.15 = +15.0 bonus
    matches_high = [{
        "indicator_id": "test-id-1",
        "indicator_type": "IPV4",
        "value": "198.51.100.25",
        "confidence": 100,
        "source": "MISP",
        "threat_category": "C2",
    }]
    score_high, expl_high = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        threat_intel_matches=matches_high,
    )
    assert expl_high["threat_intel_confidence"] == 100
    assert expl_high["threat_intel_bonus"] == 15.0
    assert "threat intel (+15.0, conf=100%)" in expl_high["decision_reason"]

    # 2. Moderate confidence indicator (50) -> 50 * 0.15 = +7.5 bonus
    matches_mod = [{
        "indicator_id": "test-id-2",
        "confidence": 50,
        "source": "OTX",
    }]
    score_mod, expl_mod = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        threat_intel_matches=matches_mod,
    )
    assert expl_mod["threat_intel_confidence"] == 50
    assert expl_mod["threat_intel_bonus"] == 7.5

    # 3. No threat intel match -> +0.0 bonus
    score_none, expl_none = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        threat_intel_matches=[],
    )
    assert expl_none["threat_intel_confidence"] == 0
    assert expl_none["threat_intel_bonus"] == 0.0


def test_repeated_indicator_matches_do_not_inflate_risk_indefinitely():
    findings = [{
        "severity": "MEDIUM",
        "confidence": 1.0,
        "dedup_key": "rule-3:agent-1",
    }]
    entities = ["ip:198.51.100.25"]
    mitre = ["T1046"]

    # 5 matching indicators from multiple feeds
    multi_matches = [
        {"indicator_id": f"id-{i}", "confidence": 90, "source": f"feed-{i}"}
        for i in range(5)
    ]

    score, expl = compute_incident_risk(
        findings=findings,
        affected_entities=entities,
        mitre_attack_ids=mitre,
        threat_intel_matches=multi_matches,
    )

    # Invariant: Bonus must be capped at 15.0, not multiplied by 5!
    assert expl["threat_intel_bonus"] <= 15.0
    assert expl["threat_intel_bonus"] == 13.5  # 90 * 0.15 = 13.5
    assert len(expl["threat_intel_matches"]) == 5
