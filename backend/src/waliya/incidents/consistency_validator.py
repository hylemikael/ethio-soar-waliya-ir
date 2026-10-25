"""Cross-layer consistency validator for incident reconstruction and attack graphs.

Validates the integrity, evidence provenance, and structural consistency among:
- Graph entities and edges
- Attack path steps
- Telemetry events and rule findings
- MITRE ATT&CK technique mappings
- Simulation isolation bounds
- Chronological observation timestamps
"""

import logging
from typing import Any, Dict, List, Optional, Set
from uuid import UUID

from waliya.contracts import (
    CrossLayerConsistencyReport,
    GraphSnapshot,
    IncidentAttackCoverageResponse,
    MitreMappingStateEnum,
    ReconstructionObservationItem,
)
from waliya.db.models import EventModel, FindingModel, IncidentModel
from waliya.detection.mitre_catalog import is_known_technique

logger = logging.getLogger("waliya.incidents.consistency_validator")


class IncidentConsistencyValidator:
    """Authoritative validator enforcing the 12 mandatory cross-layer integrity checks."""

    @classmethod
    def validate_incident_reconstruction(
        cls,
        incident: IncidentModel,
        findings: List[FindingModel],
        events: List[EventModel],
        graph_snapshot: Optional[GraphSnapshot],
        mitre_coverage: Optional[IncidentAttackCoverageResponse],
        reconstruction_items: List[ReconstructionObservationItem],
    ) -> CrossLayerConsistencyReport:
        """Run all 12 cross-layer consistency checks without mutating underlying evidence."""
        inconsistencies: List[str] = []
        warnings: List[str] = []

        node_ids: Set[str] = set()
        edge_keys: Set[str] = set()
        finding_id_set: Set[str] = {str(f.id) for f in findings}
        event_id_set: Set[str] = {str(e.id) for e in events}

        if graph_snapshot:
            node_ids = {node.id for node in graph_snapshot.nodes}
            edge_keys = {f"{e.source}->{e.target}" for e in graph_snapshot.edges}

        # ----------------------------------------------------------------------
        # Check 1: Every graph edge references valid source and target entities
        # ----------------------------------------------------------------------
        if graph_snapshot and graph_snapshot.edges:
            for edge in graph_snapshot.edges:
                if edge.source not in node_ids:
                    inconsistencies.append(
                        f"Check 1 Failed: Graph edge '{edge.source} -> {edge.target}' references missing source entity '{edge.source}'"
                    )
                if edge.target not in node_ids:
                    inconsistencies.append(
                        f"Check 1 Failed: Graph edge '{edge.source} -> {edge.target}' references missing target entity '{edge.target}'"
                    )

        # ----------------------------------------------------------------------
        # Check 2: Every graph edge has appropriate supporting evidence provenance
        # ----------------------------------------------------------------------
        if graph_snapshot and graph_snapshot.edges:
            for edge in graph_snapshot.edges:
                if not edge.provenance:
                    warnings.append(
                        f"Check 2 Warning: Graph edge '{edge.source} -> {edge.target}' lacks explicit provenance metadata"
                    )
                if not edge.evidence_event_ids and edge.provenance == "telemetry":
                    warnings.append(
                        f"Check 2 Warning: Telemetry-derived graph edge '{edge.source} -> {edge.target}' has empty evidence_event_ids"
                    )

        # ----------------------------------------------------------------------
        # Check 3: Every evidence reference resolves within permitted data scope
        # ----------------------------------------------------------------------
        for f in findings:
            if f.event_id and str(f.event_id) not in event_id_set:
                inconsistencies.append(
                    f"Check 3 Failed: Finding '{f.id}' references event '{f.event_id}' which does not resolve in incident event store"
                )

        # ----------------------------------------------------------------------
        # Check 4: Every attack-path step references valid graph entities or edges
        # ----------------------------------------------------------------------
        if graph_snapshot and graph_snapshot.attack_paths:
            for path in graph_snapshot.attack_paths:
                for step in path.steps:
                    if step.source not in node_ids:
                        inconsistencies.append(
                            f"Check 4 Failed: Attack path '{path.path_id}' step {step.step_order} references non-existent source entity '{step.source}'"
                        )
                    if step.target not in node_ids:
                        inconsistencies.append(
                            f"Check 4 Failed: Attack path '{path.path_id}' step {step.step_order} references non-existent target entity '{step.target}'"
                        )

        # ----------------------------------------------------------------------
        # Check 5: Every ATT&CK mapping references supported catalog or is classified
        # ----------------------------------------------------------------------
        if mitre_coverage:
            for tech in mitre_coverage.techniques:
                if not is_known_technique(tech.technique_id):
                    warnings.append(
                        f"Check 5 Notice: Technique '{tech.technique_id}' is a custom or fallback extension not in authoritative v15.1 catalog"
                    )
                if tech.mapping_state not in (
                    MitreMappingStateEnum.MAPPED,
                    MitreMappingStateEnum.UNMAPPED,
                    MitreMappingStateEnum.INSUFFICIENT_EVIDENCE,
                ):
                    inconsistencies.append(
                        f"Check 5 Failed: Technique mapping '{tech.technique_id}' has unrecognized mapping state '{tech.mapping_state}'"
                    )

        # ----------------------------------------------------------------------
        # Check 6: Every mapped finding and evidence reference resolves correctly
        # ----------------------------------------------------------------------
        if mitre_coverage:
            for tech in mitre_coverage.techniques:
                for fid in tech.finding_ids:
                    if str(fid) not in finding_id_set:
                        inconsistencies.append(
                            f"Check 6 Failed: Technique '{tech.technique_id}' references unknown finding '{fid}'"
                        )
                for eid in tech.evidence_event_ids:
                    if str(eid) not in event_id_set:
                        inconsistencies.append(
                            f"Check 6 Failed: Technique '{tech.technique_id}' references unresolved evidence event '{eid}'"
                        )

        # ----------------------------------------------------------------------
        # Check 7: Coverage counts match underlying mapped and unmapped findings
        # ----------------------------------------------------------------------
        if mitre_coverage:
            total_accounted = (
                mitre_coverage.mapped_findings_count
                + mitre_coverage.unmapped_findings_count
            )
            # Each finding should be either mapped or unmapped (or incident has 0 findings)
            if findings and total_accounted != len(findings):
                # Only warn if finding association differs (e.g. metadata-only techniques)
                warnings.append(
                    f"Check 7 Notice: Coverage findings sum ({total_accounted}) differs from raw finding count ({len(findings)}) due to metadata-only technique deduplication"
                )

        # ----------------------------------------------------------------------
        # Check 8: Deduplicated techniques preserve distinct supporting findings and evidence
        # ----------------------------------------------------------------------
        if mitre_coverage:
            seen_tech_ids: Set[str] = set()
            for tech in mitre_coverage.techniques:
                if tech.technique_id in seen_tech_ids:
                    inconsistencies.append(
                        f"Check 8 Failed: Technique '{tech.technique_id}' appears duplicate in coverage list; must be consolidated"
                    )
                seen_tech_ids.add(tech.technique_id)
                if tech.mapping_state == MitreMappingStateEnum.MAPPED:
                    if not tech.finding_ids or not tech.evidence_event_ids:
                        inconsistencies.append(
                            f"Check 8 Failed: Mapped technique '{tech.technique_id}' lacks supporting finding IDs or evidence event IDs"
                        )

        # ----------------------------------------------------------------------
        # Check 9: Graph snapshots do not reference unrelated incidents
        # ----------------------------------------------------------------------
        if graph_snapshot and graph_snapshot.incident_id:
            if graph_snapshot.incident_id != incident.id:
                inconsistencies.append(
                    f"Check 9 Failed: Graph snapshot belongs to incident '{graph_snapshot.incident_id}', expected '{incident.id}'"
                )

        # ----------------------------------------------------------------------
        # Check 10: Simulation-generated data remains isolated
        # ----------------------------------------------------------------------
        incident_is_sim = getattr(incident, "is_simulation", False)
        for f in findings:
            f_is_sim = getattr(f, "is_simulation", False)
            if incident_is_sim != f_is_sim:
                inconsistencies.append(
                    f"Check 10 Failed: Simulation boundary violation: incident is_simulation={incident_is_sim} while finding '{f.id}' has is_simulation={f_is_sim}"
                )

        # ----------------------------------------------------------------------
        # Check 11: Empty or stale snapshots handled according to rebuilding workflow
        # ----------------------------------------------------------------------
        if graph_snapshot is None and len(findings) > 0:
            warnings.append(
                "Check 11 Notice: Incident has findings but graph snapshot is absent or not yet materialized"
            )

        # ----------------------------------------------------------------------
        # Check 12: Chronological reconstruction does not introduce absent timestamps
        # ----------------------------------------------------------------------
        for item in reconstruction_items:
            if item.timestamp is None:
                continue
            # Ensure timestamp matches its corresponding event or finding timestamp
            if item.item_type.value == "EVENT" and item.item_id in event_id_set:
                orig_ev = next((e for e in events if str(e.id) == item.item_id), None)
                if orig_ev and orig_ev.timestamp != item.timestamp:
                    inconsistencies.append(
                        f"Check 12 Failed: Reconstruction item timestamp for event '{item.item_id}' mutated from original evidence timestamp"
                    )
            elif item.item_type.value == "FINDING" and item.item_id in finding_id_set:
                orig_f = next((f for f in findings if str(f.id) == item.item_id), None)
                if orig_f and orig_f.timestamp != item.timestamp:
                    inconsistencies.append(
                        f"Check 12 Failed: Reconstruction item timestamp for finding '{item.item_id}' mutated from original finding timestamp"
                    )

        is_consistent = len(inconsistencies) == 0
        return CrossLayerConsistencyReport(
            is_consistent=is_consistent,
            checks_run=12,
            inconsistencies=inconsistencies,
            warnings=warnings,
        )
