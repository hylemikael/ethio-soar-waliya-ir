"""Evidence-backed MITRE ATT&CK mapping and investigation intelligence service.

Provides deterministic, explainable MITRE ATT&CK coverage calculation for
security incidents, strictly backed by stored telemetry events and findings.
Zero LLM hallucination, zero internet dependency, zero speculation.
"""

import logging
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.contracts import (
    IncidentAttackCoverageResponse,
    MitreMappingStateEnum,
    MitreTechniqueMapping,
    UnmappedFindingSummary,
)
from waliya.db.models import FindingModel, IncidentModel
from waliya.detection.mitre_catalog import (
    get_catalog_version,
    lookup_technique_or_fallback,
)

logger = logging.getLogger("waliya.incidents.mitre_service")

# Explicit, honest limitations disclosed to analysts
EXPLICIT_LIMITATIONS: List[str] = [
    "Technique coverage reflects detected and evidence-backed events only, not complete adversary activity across unmonitored systems.",
    "Absence of a technique mapping does not guarantee the absence of adversary activity in that category.",
    "Technique associations do not imply a confirmed chronological or causal attack sequence.",
    "Heuristic and statistical anomaly alerts are reported as unmapped to maintain strict mapping integrity without speculation.",
    "Threat intelligence indicator references without matching telemetry events are classified as having insufficient evidence.",
]


class IncidentMitreService:
    """Authoritative service for computing evidence-backed MITRE ATT&CK coverage."""

    @classmethod
    async def get_incident_mitre_coverage(
        cls,
        session: AsyncSession,
        incident_id: UUID,
    ) -> IncidentAttackCoverageResponse:
        """Compute deterministic, evidence-backed MITRE ATT&CK coverage for an incident.

        Classifies every finding and metadata technique into one of three explicit states:
        1. MAPPED: Backed by specific event evidence and explicit technique IDs.
        2. UNMAPPED: Triggered by heuristic/anomaly rules without explicit technique tags.
        3. INSUFFICIENT_EVIDENCE: Tagged in rule/incident metadata but lacking stored event evidence.
        """
        # 1. Fetch incident
        inc_res = await session.execute(
            select(IncidentModel).where(IncidentModel.id == incident_id)
        )
        incident = inc_res.scalars().first()
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        # 2. Fetch associated findings with events and rules
        findings_res = await session.execute(
            select(FindingModel)
            .options(
                selectinload(FindingModel.event),
                selectinload(FindingModel.rule),
            )
            .where(FindingModel.incident_id == incident_id)
            .order_by(FindingModel.timestamp.asc())
        )
        findings = findings_res.scalars().all()

        raw_mappings: List[MitreTechniqueMapping] = []
        unmapped_findings: List[UnmappedFindingSummary] = []
        mapped_finding_ids: Set[UUID] = set()
        seen_mitre_ids_from_findings: Set[str] = set()

        # 3. Classify each finding
        for finding in findings:
            # Extract technique IDs from explanation or associated rule
            technique_ids: List[str] = []
            if isinstance(finding.explanation, dict) and "mitre_attack_ids" in finding.explanation:
                exp_ids = finding.explanation["mitre_attack_ids"]
                if isinstance(exp_ids, list):
                    technique_ids.extend([str(x).strip().upper() for x in exp_ids if str(x).strip()])
            elif finding.rule and finding.rule.mitre_attack_ids:
                rule_ids = finding.rule.mitre_attack_ids
                if isinstance(rule_ids, list):
                    technique_ids.extend([str(x).strip().upper() for x in rule_ids if str(x).strip()])

            # Extract backing evidence event IDs
            event_evidence_ids: List[UUID] = []
            if finding.event_id and finding.event:
                event_evidence_ids.append(finding.event_id)

            # State Classification
            if not technique_ids:
                # UNMAPPED: Finding lacks explicit MITRE technique tags
                rule_id_str = (
                    finding.rule.rule_id
                    if finding.rule
                    else str(finding.explanation.get("rule_id", "ANOMALY-HEURISTIC"))
                    if isinstance(finding.explanation, dict)
                    else "ANOMALY-HEURISTIC"
                )
                title_str = (
                    finding.rule.name
                    if finding.rule
                    else str(finding.explanation.get("name", "Behavioral Anomaly / Heuristic Alert"))
                    if isinstance(finding.explanation, dict)
                    else "Behavioral Anomaly / Heuristic Alert"
                )
                unmapped_findings.append(
                    UnmappedFindingSummary(
                        finding_id=finding.id,
                        rule_id=rule_id_str,
                        finding_title=title_str,
                        reason="Triggered by behavioral anomaly or heuristic rule without explicit MITRE ATT&CK technique tags.",
                        evidence_event_ids=event_evidence_ids,
                    )
                )
            elif not event_evidence_ids:
                # INSUFFICIENT_EVIDENCE: Technique tagged in metadata but zero event evidence
                for tid in technique_ids:
                    seen_mitre_ids_from_findings.add(tid)
                    entry = lookup_technique_or_fallback(tid)
                    rule_label = finding.rule.rule_id if finding.rule else "metadata"
                    raw_mappings.append(
                        MitreTechniqueMapping(
                            technique_id=entry.technique_id,
                            technique_name=entry.name,
                            tactics=entry.tactics,
                            mapping_state=MitreMappingStateEnum.INSUFFICIENT_EVIDENCE,
                            confidence=int(round(finding.confidence * 100)),
                            finding_ids=[finding.id],
                            evidence_event_ids=[],
                            rationale=f"Technique {entry.technique_id} tagged in rule '{rule_label}', but no underlying telemetry event records were found.",
                            reference_url=entry.reference_url,
                        )
                    )
            else:
                # MAPPED: Valid technique tag backed by stored event evidence
                mapped_finding_ids.add(finding.id)
                for tid in technique_ids:
                    seen_mitre_ids_from_findings.add(tid)
                    entry = lookup_technique_or_fallback(tid)
                    sensor_src = finding.event.source if finding.event else "agent"
                    ev_type = finding.event.event_type if finding.event else "telemetry"
                    rule_label = finding.rule.rule_id if finding.rule else "rule"
                    raw_mappings.append(
                        MitreTechniqueMapping(
                            technique_id=entry.technique_id,
                            technique_name=entry.name,
                            tactics=entry.tactics,
                            mapping_state=MitreMappingStateEnum.MAPPED,
                            confidence=int(round(finding.confidence * 100)),
                            finding_ids=[finding.id],
                            evidence_event_ids=event_evidence_ids,
                            rationale=f"Validated by event evidence from '{sensor_src}' ({ev_type}) under rule '{rule_label}'.",
                            reference_url=entry.reference_url,
                        )
                    )

        # 4. Check for incident-level techniques not covered by any finding
        if isinstance(incident.mitre_attack_ids, list):
            for inc_tid in incident.mitre_attack_ids:
                clean_tid = str(inc_tid).strip().upper()
                if clean_tid and clean_tid not in seen_mitre_ids_from_findings:
                    entry = lookup_technique_or_fallback(clean_tid)
                    raw_mappings.append(
                        MitreTechniqueMapping(
                            technique_id=entry.technique_id,
                            technique_name=entry.name,
                            tactics=entry.tactics,
                            mapping_state=MitreMappingStateEnum.INSUFFICIENT_EVIDENCE,
                            confidence=50,
                            finding_ids=[],
                            evidence_event_ids=[],
                            rationale=f"Technique {entry.technique_id} listed in incident metadata, but not supported by any finding or telemetry event record.",
                            reference_url=entry.reference_url,
                        )
                    )

        # 5. Deduplicate and consolidate techniques across findings
        merged_techniques: Dict[str, MitreTechniqueMapping] = {}
        for mapping in raw_mappings:
            tid = mapping.technique_id
            if tid not in merged_techniques:
                merged_techniques[tid] = mapping
            else:
                existing = merged_techniques[tid]
                # If either finding has MAPPED with evidence, consolidated state is MAPPED
                if (
                    mapping.mapping_state == MitreMappingStateEnum.MAPPED
                    or existing.mapping_state == MitreMappingStateEnum.MAPPED
                ):
                    resolved_state = MitreMappingStateEnum.MAPPED
                else:
                    resolved_state = MitreMappingStateEnum.INSUFFICIENT_EVIDENCE

                # Union finding IDs and evidence IDs
                combined_finding_ids = list(dict.fromkeys(existing.finding_ids + mapping.finding_ids))
                combined_evidence_ids = list(dict.fromkeys(existing.evidence_event_ids + mapping.evidence_event_ids))
                max_confidence = max(existing.confidence, mapping.confidence)

                # Merge rationales cleanly
                rationales = [existing.rationale]
                if mapping.rationale not in rationales:
                    rationales.append(mapping.rationale)
                merged_rationale = "; ".join(rationales)

                merged_techniques[tid] = MitreTechniqueMapping(
                    technique_id=tid,
                    technique_name=existing.technique_name,
                    tactics=existing.tactics,
                    mapping_state=resolved_state,
                    confidence=max_confidence,
                    finding_ids=combined_finding_ids,
                    evidence_event_ids=combined_evidence_ids,
                    rationale=merged_rationale,
                    reference_url=existing.reference_url,
                )

        # 6. Sort deterministically by technique ID
        sorted_techniques = sorted(merged_techniques.values(), key=lambda t: t.technique_id)

        # 7. Group techniques by tactic
        tactics_map: Dict[str, List[MitreTechniqueMapping]] = {}
        for t in sorted_techniques:
            for tactic in t.tactics:
                if tactic not in tactics_map:
                    tactics_map[tactic] = []
                tactics_map[tactic].append(t)

        # 8. Compute counts
        distinct_count = len(sorted_techniques)
        mapped_count = len(mapped_finding_ids)
        unmapped_count = len(unmapped_findings)
        insufficient_count = sum(
            1 for t in sorted_techniques if t.mapping_state == MitreMappingStateEnum.INSUFFICIENT_EVIDENCE
        )

        return IncidentAttackCoverageResponse(
            incident_id=incident.id,
            catalog_version=get_catalog_version(),
            distinct_techniques_count=distinct_count,
            mapped_findings_count=mapped_count,
            unmapped_findings_count=unmapped_count,
            insufficient_evidence_count=insufficient_count,
            tactics=tactics_map,
            techniques=sorted_techniques,
            unmapped_findings=unmapped_findings,
            limitations=list(EXPLICIT_LIMITATIONS),
        )
