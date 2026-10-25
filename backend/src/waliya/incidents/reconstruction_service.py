"""Unified incident reconstruction service combining entity graphs, ATT&CK, and forensic evidence.

Synthesizes stored evidence, detection findings, graph topology, and technique mappings
into a traceable investigation experience without false causality or speculative fabrication.
"""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.contracts import (
    CrossLayerConsistencyReport,
    GraphSnapshot,
    IncidentAttackCoverageResponse,
    IncidentReconstructionResponse,
    MitreTechniqueMapping,
    ReconstructionAttackProgression,
    ReconstructionCoverageSummary,
    ReconstructionIncompleteEvidence,
    ReconstructionItemTypeEnum,
    ReconstructionObservationItem,
    SeverityEnum,
)
from waliya.correlation.entity_extractor import EntityExtractor
from waliya.db.models import EventModel, FindingModel, IncidentModel
from waliya.incidents.consistency_validator import IncidentConsistencyValidator
from waliya.incidents.graph_service import IncidentGraphService
from waliya.incidents.mitre_service import IncidentMitreService

logger = logging.getLogger("waliya.incidents.reconstruction_service")

RECONSTRUCTION_LIMITATIONS: List[str] = [
    "Observed Chronology reflects timestamps recorded by monitored agents; clock skew or delayed ingestion may alter apparent arrival order.",
    "Candidate Attack Progressions indicate graph reachability across correlated entities and do not by themselves prove a single causal execution sequence.",
    "MITRE ATT&CK technique mappings represent defensive rule classifications grounded in evidence, not adversary attribution or exhaustive kill-chain proof.",
    "Unmonitored systems, encrypted payload contents, or network hops outside agent visibility are omitted from reconstruction rather than hypothesized.",
    "Analytic findings are marked as interpretations (is_interpretation=True) to strictly separate detection conclusions from raw telemetry events.",
]


class IncidentReconstructionService:
    """Authoritative service for reconstructing an incident from verified evidence."""

    @classmethod
    async def reconstruct_incident(
        cls,
        session: AsyncSession,
        incident_id: UUID,
        max_timeline_items: int = 200,
    ) -> IncidentReconstructionResponse:
        """Deterministically reconstruct incident timeline, graph associations, and ATT&CK coverage."""
        # 1. Fetch incident
        inc_res = await session.execute(
            select(IncidentModel).where(IncidentModel.id == incident_id)
        )
        incident = inc_res.scalars().first()
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        # 2. Fetch findings associated with this incident (bounded to prevent unbounded memory allocation)
        max_fetch = max(max_timeline_items * 2, 500)
        findings_res = await session.execute(
            select(FindingModel)
            .options(
                selectinload(FindingModel.event),
                selectinload(FindingModel.rule),
            )
            .where(FindingModel.incident_id == incident_id)
            .order_by(FindingModel.timestamp.asc())
            .limit(max_fetch)
        )
        findings = list(findings_res.scalars().all())

        # Collect backing events
        events_dict: Dict[UUID, EventModel] = {}
        for f in findings:
            if f.event:
                events_dict[f.event.id] = f.event

        # In case some events are associated with incident but not directly preloaded
        event_list = list(events_dict.values())

        # 3. Obtain Graph Snapshot (use persisted snapshot if valid; rebuild if missing)
        graph_snapshot: Optional[GraphSnapshot] = None
        if incident.entity_graph_snapshot:
            try:
                graph_snapshot = GraphSnapshot(**incident.entity_graph_snapshot)
            except Exception as exc:
                logger.warning("Failed parsing persisted graph snapshot for incident %s: %s", incident.id, exc)

        if not graph_snapshot or not graph_snapshot.nodes:
            try:
                graph_snapshot = await IncidentGraphService.build_incident_attack_graph(
                    session=session,
                    incident_id=incident.id,
                    persist=False,
                )
            except Exception as exc:
                logger.warning("Could not reconstruct graph for incident %s: %s", incident.id, exc)
                graph_snapshot = GraphSnapshot(incident_id=incident.id, nodes=[], edges=[])

        # 4. Obtain MITRE ATT&CK coverage
        try:
            mitre_coverage = await IncidentMitreService.get_incident_mitre_coverage(
                session=session,
                incident_id=incident.id,
            )
        except Exception as exc:
            logger.warning("Could not compute MITRE coverage for incident %s: %s", incident.id, exc)
            mitre_coverage = None

        # Build lookup tables for MITRE technique mappings by event_id and finding_id
        techniques_by_event: Dict[str, List[MitreTechniqueMapping]] = {}
        techniques_by_finding: Dict[str, List[MitreTechniqueMapping]] = {}
        if mitre_coverage:
            for tech in mitre_coverage.techniques:
                for eid in tech.evidence_event_ids:
                    techniques_by_event.setdefault(str(eid), []).append(tech)
                for fid in tech.finding_ids:
                    techniques_by_finding.setdefault(str(fid), []).append(tech)

        # Build lookup for graph edges containing event_id in evidence_event_ids
        edges_by_event: Dict[str, List[str]] = {}
        if graph_snapshot and graph_snapshot.edges:
            for edge in graph_snapshot.edges:
                edge_desc = f"{edge.source} -[{edge.relation.value}]-> {edge.target}"
                for ev_id in edge.evidence_event_ids:
                    edges_by_event.setdefault(str(ev_id), []).append(edge_desc)

        # 5. Build Chronological Timeline Items
        timeline_items: List[ReconstructionObservationItem] = []
        findings_without_events: List[str] = []
        events_without_mitre = 0

        # A. Process Telemetry Events (Direct Evidence)
        for ev in event_list:
            ev_id_str = str(ev.id)
            # Associated entities extracted from event
            ev_payload = {
                "event_id": ev_id_str,
                "agent_id": str(ev.agent_id) if ev.agent_id else None,
                "event_type": ev.event_type,
                "severity": ev.severity,
                "timestamp": ev.timestamp,
                "source": ev.source,
                "attributes": ev.normalized_payload.get("attributes") or ev.normalized_payload,
                "normalized": ev.normalized_payload,
            }
            extracted_ents, _ = EntityExtractor.extract(ev_payload)
            associated_entity_ids = sorted(list({e.id for e in extracted_ents}))

            # Associated findings referencing this event
            referencing_findings = [
                str(f.id) for f in findings if f.event_id and f.event_id == ev.id
            ]

            # Technique mappings
            mapped_techs = techniques_by_event.get(ev_id_str, [])
            if not mapped_techs:
                events_without_mitre += 1

            associated_edges = sorted(list(set(edges_by_event.get(ev_id_str, []))))

            # Check for data gaps
            data_gaps: List[str] = []
            if not ev.timestamp:
                data_gaps.append("Missing recorded event timestamp")
            if not mapped_techs:
                data_gaps.append("No explicit MITRE ATT&CK technique mapped to this telemetry event")
            if not associated_edges:
                data_gaps.append("Event is isolated from correlated graph edges")

            clean_attrs = dict(ev.normalized_payload.get("attributes") or ev.normalized_payload or {})
            # Truncate overly long fields in attributes for safety
            safe_attrs = {}
            for k, v in clean_attrs.items():
                if isinstance(v, (str, int, float, bool)):
                    safe_attrs[k] = str(v)[:256]

            timeline_items.append(
                ReconstructionObservationItem(
                    item_id=ev_id_str,
                    item_type=ReconstructionItemTypeEnum.EVENT,
                    timestamp=ev.timestamp,
                    title=f"Telemetry: {ev.event_type}",
                    severity=SeverityEnum(ev.severity) if ev.severity in SeverityEnum.__members__ else SeverityEnum.MEDIUM,
                    source=ev.source or "telemetry",
                    is_interpretation=False,
                    associated_entity_ids=associated_entity_ids,
                    associated_graph_edges=associated_edges,
                    mitre_techniques=mapped_techs,
                    evidence_event_ids=[ev_id_str],
                    finding_ids=referencing_findings,
                    explanation=f"Recorded telemetry event of type '{ev.event_type}' from source '{ev.source}'",
                    raw_attributes=safe_attrs,
                    data_gaps=data_gaps,
                )
            )

        # B. Process Findings (Detection Rule Interpretation)
        for f in findings:
            f_id_str = str(f.id)
            rule_title = (
                f.rule.name
                if f.rule
                else f.explanation.get("rule_name")
                or f.explanation.get("rule_id")
                or "Correlated Detection Finding"
            )
            rule_source = (
                f.rule.rule_id
                if f.rule
                else str(f.explanation.get("rule_id", "DETECTION_RULE"))
            )

            associated_entities: List[str] = []
            if f.agent_id:
                associated_entities.append(f"host:{f.agent_id}")
            if incident.affected_entities:
                for aff in incident.affected_entities:
                    if aff not in associated_entities:
                        associated_entities.append(aff)

            f_ev_ids = [str(f.event_id)] if f.event_id else []
            f_techs = techniques_by_finding.get(f_id_str, [])

            f_gaps: List[str] = []
            if not f.event_id or not f.event:
                findings_without_events.append(f"{f_id_str} ({rule_title})")
                f_gaps.append("Finding lacks direct underlying raw telemetry event record")
            if not f_techs:
                f_gaps.append("Finding triggered by anomaly or heuristic without MITRE ATT&CK tag")

            f_explanation = (
                f.explanation.get("description")
                if isinstance(f.explanation, dict) and "description" in f.explanation
                else f"Detection rule matched with confidence {f.confidence:.1f}"
            )

            timeline_items.append(
                ReconstructionObservationItem(
                    item_id=f_id_str,
                    item_type=ReconstructionItemTypeEnum.FINDING,
                    timestamp=f.timestamp,
                    title=f"Finding: {rule_title}",
                    severity=SeverityEnum(f.severity) if f.severity in SeverityEnum.__members__ else SeverityEnum.MEDIUM,
                    source=rule_source,
                    is_interpretation=True,
                    associated_entity_ids=associated_entities,
                    associated_graph_edges=[],
                    mitre_techniques=f_techs,
                    evidence_event_ids=f_ev_ids,
                    finding_ids=[f_id_str],
                    explanation=f_explanation,
                    raw_attributes={"confidence": f.confidence},
                    data_gaps=f_gaps,
                )
            )

        # 6. Deterministic Chronological Sorting
        # Sort by timestamp (None placed first or last deterministically; here using datetime.min),
        # with item_id as stable secondary tie-breaker.
        min_dt = datetime.min.replace(tzinfo=timezone.utc)

        def sort_key(item: ReconstructionObservationItem) -> Tuple[datetime, str]:
            ts = item.timestamp
            if ts is None:
                return (min_dt, item.item_id)
            if ts.tzinfo is None:
                ts = ts.replace(tzinfo=timezone.utc)
            return (ts, item.item_id)

        timeline_items.sort(key=sort_key)

        # Apply bounding limit
        bounded_timeline = timeline_items[:max_timeline_items]

        # Determine overall observed range
        valid_timestamps = [it.timestamp for it in bounded_timeline if it.timestamp is not None]
        first_observed_at = min(valid_timestamps) if valid_timestamps else incident.first_seen
        last_observed_at = max(valid_timestamps) if valid_timestamps else incident.last_seen

        # 7. Candidate Attack Progressions (Separate from Chronology)
        candidate_progressions: List[ReconstructionAttackProgression] = []
        if graph_snapshot and graph_snapshot.attack_paths:
            for p in graph_snapshot.attack_paths:
                candidate_progressions.append(
                    ReconstructionAttackProgression(
                        path_id=p.path_id,
                        entry_node=p.entry_node,
                        target_node=p.target_node,
                        hop_count=p.hop_count,
                        risk_severity=p.risk_severity,
                        confidence=p.confidence,
                        disclaimer=(
                            "Candidate graph traversal connecting entry to target entity; "
                            "indicates structural reachability but does not prove a single causal execution sequence."
                        ),
                        steps=p.steps,
                    )
                )

        # 8. Unconnected Entities
        path_nodes: Set[str] = set()
        for cp in candidate_progressions:
            path_nodes.add(cp.entry_node)
            path_nodes.add(cp.target_node)
            for st in cp.steps:
                path_nodes.add(st.source)
                path_nodes.add(st.target)

        unconnected_entities: List[str] = []
        if graph_snapshot and graph_snapshot.nodes:
            for nd in graph_snapshot.nodes:
                if nd.id not in path_nodes:
                    unconnected_entities.append(nd.id)

        # 9. Incomplete Evidence & Uncertainties
        uncertainties: List[str] = []
        if findings_without_events:
            uncertainties.append(
                f"{len(findings_without_events)} finding(s) were generated from aggregated or external telemetry without individual event payloads."
            )
        if events_without_mitre > 0:
            uncertainties.append(
                f"{events_without_mitre} telemetry event(s) reflect baseline system activity without direct adversary technique mapping."
            )
        if unconnected_entities:
            uncertainties.append(
                f"{len(unconnected_entities)} graph entity(ies) were observed in incident telemetry but do not participate in candidate attack paths."
            )

        incomplete_evidence = ReconstructionIncompleteEvidence(
            findings_without_events=findings_without_events,
            events_without_mitre=events_without_mitre,
            unconnected_entities=unconnected_entities,
            uncertainties=uncertainties,
        )

        # 10. Coverage Summary
        coverage_summary = ReconstructionCoverageSummary(
            total_observations=len(bounded_timeline),
            chronological_events_count=len(event_list),
            correlated_findings_count=len(findings),
            threat_intel_matches_count=sum(
                len(f.explanation.get("threat_intel_matches", []))
                for f in findings
                if isinstance(f.explanation, dict)
            ),
            mapped_techniques_count=mitre_coverage.mapped_findings_count if mitre_coverage else 0,
            unmapped_findings_count=mitre_coverage.unmapped_findings_count if mitre_coverage else 0,
            insufficient_evidence_count=mitre_coverage.insufficient_evidence_count if mitre_coverage else 0,
            graph_entities_count=len(graph_snapshot.nodes) if graph_snapshot else 0,
            graph_edges_count=len(graph_snapshot.edges) if graph_snapshot else 0,
            candidate_attack_paths_count=len(candidate_progressions),
        )

        # 11. Cross-Layer Consistency Validation
        consistency_report = IncidentConsistencyValidator.validate_incident_reconstruction(
            incident=incident,
            findings=findings,
            events=event_list,
            graph_snapshot=graph_snapshot,
            mitre_coverage=mitre_coverage,
            reconstruction_items=bounded_timeline,
        )

        return IncidentReconstructionResponse(
            incident_id=incident.id,
            incident_number=incident.incident_number,
            incident_title=incident.title,
            severity=incident.severity,
            status=incident.status,
            first_observed_at=first_observed_at,
            last_observed_at=last_observed_at,
            timeline=bounded_timeline,
            candidate_progressions=candidate_progressions,
            coverage_summary=coverage_summary,
            incomplete_evidence=incomplete_evidence,
            consistency_report=consistency_report,
            limitations=RECONSTRUCTION_LIMITATIONS,
        )
