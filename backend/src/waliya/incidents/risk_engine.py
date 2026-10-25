"""Explainable composite risk scoring engine for security incidents."""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("waliya.incidents.risk_engine")

SEVERITY_WEIGHTS: Dict[str, float] = {
    "INFORMATIONAL": 15.0,
    "LOW": 30.0,
    "MEDIUM": 50.0,
    "HIGH": 75.0,
    "CRITICAL": 90.0,
}


def compute_incident_risk(
    findings: List[Dict[str, Any]],
    affected_entities: List[str],
    mitre_attack_ids: List[str],
    is_critical_asset: bool = False,
    threat_intel_confidence: int = 0,
    asset_criticality: Optional[str] = None,
    threat_intel_matches: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[float, Dict[str, Any]]:
    """Compute a bounded, explainable composite risk score for a correlated incident.

    Guarantees:
    - Bounded to 0.0 - 100.0 range.
    - Prevents double-counting duplicate evidence or repeated alerts.
    - Factors in base severity, confidence, correlation depth, multi-stage kill-chain progression,
      behavioral anomaly deviations, asset business criticality, and threat intelligence.
    - Unknown asset criticality is explicitly distinguished from LOW and receives +0.0 bonus.
    - Repeated threat-indicator matches are bounded and cannot inflate risk indefinitely.
    - Never treats foreign GeoIP alone as proof of maliciousness.

    Returns:
        Tuple of (composite_risk_score, explanation_dictionary).
    """
    if not findings:
        return 0.0, {"final_score": 0.0, "explanation": "No findings associated with incident"}

    # 1. Deduplicate findings to prevent alert-flood inflation
    unique_findings: Dict[str, Dict[str, Any]] = {}
    for f in findings:
        # Deduplication key from finding or fallback
        dkey = f.get("dedup_key") or f"{f.get('rule_id')}:{f.get('agent_id')}"
        if dkey not in unique_findings:
            unique_findings[dkey] = f
        else:
            # Keep highest severity / confidence
            existing = unique_findings[dkey]
            if SEVERITY_WEIGHTS.get(f.get("severity", "LOW"), 30.0) > SEVERITY_WEIGHTS.get(existing.get("severity", "LOW"), 30.0):
                unique_findings[dkey] = f

    deduped_list = list(unique_findings.values())

    # 2. Base Severity: Maximum severity across unique findings
    highest_severity = "INFORMATIONAL"
    highest_weight = 15.0
    for f in deduped_list:
        sev = str(f.get("severity", "LOW")).upper()
        weight = SEVERITY_WEIGHTS.get(sev, 30.0)
        if weight > highest_weight:
            highest_weight = weight
            highest_severity = sev

    # 3. Confidence Factor: Weighted mean confidence of unique findings
    confidences = [float(f.get("confidence", 1.0)) for f in deduped_list]
    avg_confidence = sum(confidences) / len(confidences) if confidences else 1.0
    avg_confidence = max(0.5, min(1.0, avg_confidence))

    # 4. Correlation Strength (Multi-Entity Diversity)
    # Classify entity prefixes: host, user, process, file, ip
    entity_prefixes: Set[str] = set()
    for ent in affected_entities:
        if ":" in ent:
            entity_prefixes.add(ent.split(":")[0].lower())

    multi_entity_multiplier = 1.0
    if len(entity_prefixes) >= 3:
        multi_entity_multiplier = 1.20
    elif len(entity_prefixes) == 2:
        multi_entity_multiplier = 1.10

    # 5. Multi-Stage Kill-Chain Progression (MITRE ATT&CK diversity)
    unique_tactics = set(mitre_attack_ids)
    multi_stage_bonus = 0.0
    if len(unique_tactics) >= 3:
        multi_stage_bonus = 10.0
    elif len(unique_tactics) == 2:
        multi_stage_bonus = 5.0

    # 6. Behavioral Anomaly Bonus (from EWMA Z-score)
    anomaly_bonus = 0.0
    for f in deduped_list:
        expl = f.get("explanation")
        if isinstance(expl, dict) and "z_score" in expl:
            z = float(expl.get("z_score", 0.0))
            if z >= 3.0:
                bonus = min(15.0, (z - 3.0) * 3.0)
                if bonus > anomaly_bonus:
                    anomaly_bonus = bonus

    # 7. Asset Importance
    asset_importance_bonus = 0.0
    asset_crit_str = "UNASSIGNED"
    if asset_criticality:
        asset_crit_str = asset_criticality.strip().upper()
        if asset_crit_str == "CRITICAL":
            asset_importance_bonus = 10.0
        elif asset_crit_str == "HIGH":
            asset_importance_bonus = 5.0
        elif asset_crit_str == "MEDIUM":
            asset_importance_bonus = 2.0
        elif asset_crit_str == "LOW":
            asset_importance_bonus = 0.0
    elif is_critical_asset:
        asset_crit_str = "CRITICAL"
        asset_importance_bonus = 10.0

    # 8. Threat Intelligence Bonus
    if threat_intel_matches:
        threat_intel_confidence = max(
            (
                int(getattr(m, "confidence", 0) if hasattr(m, "confidence") else (m.get("confidence", 0) if isinstance(m, dict) else 0))
                for m in threat_intel_matches
            ),
            default=threat_intel_confidence,
        )

    threat_intel_bonus = 0.0
    if threat_intel_confidence > 0:
        threat_intel_bonus = min(15.0, threat_intel_confidence * 0.15)

    # 9. Raw Calculation & Clamping
    base_component = highest_weight * avg_confidence * multi_entity_multiplier
    raw_score = (
        base_component
        + multi_stage_bonus
        + anomaly_bonus
        + asset_importance_bonus
        + threat_intel_bonus
    )

    final_score = round(max(0.0, min(100.0, raw_score)), 1)

    explanation = {
        "final_score": final_score,
        "base_severity": highest_severity,
        "base_weight": highest_weight,
        "confidence_factor": round(avg_confidence, 2),
        "distinct_entity_types": sorted(list(entity_prefixes)),
        "multi_entity_multiplier": multi_entity_multiplier,
        "mitre_attack_count": len(unique_tactics),
        "multi_stage_bonus": multi_stage_bonus,
        "anomaly_bonus": round(anomaly_bonus, 1),
        "asset_criticality": asset_crit_str,
        "asset_importance_bonus": asset_importance_bonus,
        "threat_intel_confidence": threat_intel_confidence,
        "threat_intel_bonus": round(threat_intel_bonus, 1),
        "threat_intel_matches": threat_intel_matches or [],
        "unique_findings_count": len(deduped_list),
        "raw_findings_count": len(findings),
        "decision_reason": (
            f"Risk score {final_score}/100 derived from {highest_severity} base ({highest_weight}) "
            f"scaled by {avg_confidence:.2f} confidence and {multi_entity_multiplier:.2f}x multi-entity multiplier "
            f"({len(entity_prefixes)} entity types), with bonuses: multi-stage (+{multi_stage_bonus}), "
            f"anomaly (+{anomaly_bonus:.1f}), asset context [{asset_crit_str}] (+{asset_importance_bonus:.1f}), "
            f"threat intel (+{threat_intel_bonus:.1f}, conf={threat_intel_confidence}%)."
        ),
    }

    return final_score, explanation
