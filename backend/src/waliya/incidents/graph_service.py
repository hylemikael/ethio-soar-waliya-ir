"""Incident attack graph reconstruction and traversal service."""

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID

import networkx as nx
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from waliya.contracts import (
    AttackPath,
    AttackPathStep,
    EntityTypeEnum,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    RelationTypeEnum,
    SeverityEnum,
)
from waliya.correlation.entity_extractor import EntityExtractor, ExtractedEntity, ExtractedRelationship
from waliya.correlation.graph_engine import EntityGraphManager, get_graph_manager
from waliya.db.models import EventModel, FindingModel, IncidentModel

logger = logging.getLogger("waliya.incidents.graph_service")

# Explicit resource ceilings for incident attack graphs to prevent unbounded memory usage
MAX_GRAPH_NODES = 500
MAX_GRAPH_EDGES = 1000


class IncidentGraphService:
    """Reconstructs and analyzes attack graphs directly from authoritative PostgreSQL events and findings."""

    @classmethod
    async def build_incident_attack_graph(
        cls,
        session: AsyncSession,
        incident_id: UUID,
        graph_manager: Optional[EntityGraphManager] = None,
        persist: bool = True,
        max_depth: int = 4,
        max_paths: int = 10,
    ) -> GraphSnapshot:
        """Deterministically reconstruct incident attack graph from stored events, findings, and threat intel.

        Guarantees:
        - 100% evidence backed: relationships cite specific event IDs.
        - Provenance tracked for each edge (telemetry, detection_rule, threat_intel).
        - Deterministic node and edge ordering.
        - Discovers directed attack paths from entry nodes to impacted assets.
        """
        # 1. Load incident
        inc_res = await session.execute(
            select(IncidentModel).where(IncidentModel.id == incident_id)
        )
        incident = inc_res.scalars().first()
        if not incident:
            raise ValueError(f"Incident '{incident_id}' not found")

        # 2. Load findings with events and rules (bounded to 500 findings)
        findings_res = await session.execute(
            select(FindingModel)
            .options(
                selectinload(FindingModel.event),
                selectinload(FindingModel.rule),
            )
            .where(FindingModel.incident_id == incident_id)
            .order_by(FindingModel.timestamp.asc())
            .limit(500)
        )
        findings = findings_res.scalars().all()

        # 3. Build local directed graph with explicit resource ceilings
        g = nx.DiGraph()

        def upsert_node(ent: ExtractedEntity) -> None:
            if g.has_node(ent.id):
                ndata = g.nodes[ent.id]
                ndata["last_seen"] = ent.timestamp
                ndata["properties"].update(ent.properties)
                ndata["observation_count"] = ndata.get("observation_count", 1) + 1
            elif g.number_of_nodes() < MAX_GRAPH_NODES:
                g.add_node(
                    ent.id,
                    entity_type=ent.type,
                    label=ent.label,
                    properties=dict(ent.properties),
                    first_seen=ent.timestamp,
                    last_seen=ent.timestamp,
                    observation_count=1,
                )

        def upsert_edge(rel: ExtractedRelationship) -> None:
            u, v = rel.source_id, rel.target_id
            if not g.has_node(u) or not g.has_node(v):
                return
            if g.has_edge(u, v):
                edata = g[u][v]
                edata["weight"] = edata.get("weight", 1.0) + rel.weight
                edata["last_seen"] = rel.timestamp
                edata["properties"].update(rel.properties)
                edata["confidence"] = max(edata.get("confidence", 0.0), getattr(rel, "confidence", 1.0))
                evs = edata.setdefault("evidence_event_ids", [])
                if rel.evidence_event_id and rel.evidence_event_id not in evs:
                    evs.append(rel.evidence_event_id)
                    if len(evs) > 20:
                        evs.pop(0)
            elif g.number_of_edges() < MAX_GRAPH_EDGES:
                ev_list = [rel.evidence_event_id] if rel.evidence_event_id else []
                g.add_edge(
                    u,
                    v,
                    relation=rel.relation,
                    weight=rel.weight,
                    confidence=getattr(rel, "confidence", 1.0),
                    provenance=getattr(rel, "provenance", "telemetry"),
                    description=getattr(rel, "description", None),
                    first_seen=rel.timestamp,
                    last_seen=rel.timestamp,
                    properties=dict(rel.properties),
                    evidence_event_ids=ev_list,
                )

        # 4. Ingest underlying events
        processed_event_ids: Set[str] = set()
        for f in findings:
            if f.event and str(f.event.id) not in processed_event_ids:
                processed_event_ids.add(str(f.event.id))
                ev_dict = {
                    "event_id": str(f.event.id),
                    "agent_id": str(f.event.agent_id) if f.event.agent_id else None,
                    "event_type": f.event.event_type,
                    "severity": f.event.severity,
                    "timestamp": f.event.timestamp,
                    "source": f.event.source,
                    "attributes": f.event.normalized_payload.get("attributes") or f.event.normalized_payload,
                    "normalized": f.event.normalized_payload,
                }
                ents, rels = EntityExtractor.extract(ev_dict)
                for ent in ents:
                    upsert_node(ent)
                for rel in rels:
                    upsert_edge(rel)

        # 5. Ingest findings as Alert entities and TRIGGERED relations
        for f in findings:
            rule_name = f.rule.name if f.rule else f.explanation.get("rule_name") or f.explanation.get("rule_id") or "Alert"
            mitre_ids = list(f.explanation.get("mitre_attack_ids") or [])

            # Determine target entity to attach alert to
            target_entity_id = None
            if f.agent_id:
                target_entity_id = f"host:{f.agent_id}"
            if not target_entity_id and incident.affected_entities:
                target_entity_id = incident.affected_entities[0]

            if target_entity_id and g.has_node(target_entity_id):
                alert_ents, alert_rels = EntityExtractor.extract_from_finding(
                    finding_id=str(f.id),
                    rule_name=rule_name,
                    severity=str(f.severity),
                    confidence=float(f.confidence),
                    mitre_ids=mitre_ids,
                    target_entity_id=target_entity_id,
                    event_id=str(f.event_id) if f.event_id else "",
                    timestamp=f.timestamp,
                )
                for a_ent in alert_ents:
                    upsert_node(a_ent)
                for a_rel in alert_rels:
                    upsert_edge(a_rel)

            # Ingest attached threat intel matches
            if f.explanation and isinstance(f.explanation, dict):
                ti_matches = f.explanation.get("threat_intel_matches") or []
                for tm in ti_matches:
                    if isinstance(tm, dict) and tm.get("value"):
                        ti_ents, ti_rels = EntityExtractor.extract_from_threat_intel(
                            indicator_id=str(tm.get("indicator_id") or tm.get("id") or ""),
                            indicator_type=str(tm.get("indicator_type") or "IPV4"),
                            indicator_value=str(tm.get("value")),
                            source=str(tm.get("source") or "Feed"),
                            confidence=int(tm.get("confidence") or 50),
                            threat_category=tm.get("threat_category"),
                            threat_actor=tm.get("threat_actor"),
                            target_entity_id=target_entity_id or f"host:{incident.affected_entities[0]}",
                            evidence_event_id=str(f.event_id) if f.event_id else "",
                            timestamp=f.timestamp,
                        )
                        for t_ent in ti_ents:
                            upsert_node(t_ent)
                        for t_rel in ti_rels:
                            upsert_edge(t_rel)

        # 6. Ensure all affected_entities exist in the graph
        for aff_raw in (incident.affected_entities or []):
            if isinstance(aff_raw, dict):
                aff = aff_raw.get("id") or f"{str(aff_raw.get('type', 'host')).lower()}:{aff_raw.get('value', 'unknown')}"
            else:
                aff = str(aff_raw)

            if not g.has_node(aff):
                aff_type = EntityTypeEnum.HOST if aff.startswith("host:") else (
                    EntityTypeEnum.USER if aff.startswith("user:") else (
                        EntityTypeEnum.IP_ADDRESS if aff.startswith("ip:") else (
                            EntityTypeEnum.PROCESS if aff.startswith("process:") else (
                                EntityTypeEnum.FILE if aff.startswith("file:") else EntityTypeEnum.HOST
                            )
                        )
                    )
                )
                g.add_node(
                    aff,
                    entity_type=aff_type,
                    label=aff.split(":")[-1],
                    properties={"affected_by_incident": True},
                    first_seen=incident.first_seen,
                    last_seen=incident.last_seen,
                    observation_count=1,
                )

        # 7. Format exported nodes deterministically
        exported_nodes: List[GraphNode] = []
        for n_id, data in sorted(list(g.nodes(data=True)), key=lambda x: str(x[0])):
            etype = data.get("entity_type", EntityTypeEnum.HOST)
            if isinstance(etype, str):
                try:
                    etype = EntityTypeEnum(etype)
                except ValueError:
                    etype = EntityTypeEnum.HOST

            exported_nodes.append(GraphNode(
                id=n_id,
                type=etype,
                label=data.get("label", n_id),
                properties=data.get("properties", {}),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                observation_count=data.get("observation_count", 1),
            ))

        # 8. Format exported edges deterministically
        exported_edges: List[GraphEdge] = []
        for u, v, data in sorted(list(g.edges(data=True)), key=lambda x: (str(x[0]), str(x[1]))):
            rtype = data.get("relation", RelationTypeEnum.CONNECTED_TO)
            if isinstance(rtype, str):
                try:
                    rtype = RelationTypeEnum(rtype)
                except ValueError:
                    rtype = RelationTypeEnum.CONNECTED_TO

            exported_edges.append(GraphEdge(
                source=u,
                target=v,
                relation=rtype,
                weight=float(data.get("weight", 1.0)),
                confidence=float(data.get("confidence", 1.0)),
                provenance=str(data.get("provenance", "telemetry")),
                timestamp=data.get("last_seen", datetime.now(timezone.utc)),
                evidence_event_ids=list(data.get("evidence_event_ids", [])),
                properties=dict(data.get("properties", {})),
            ))

        # 9. Compute incident attack paths
        mgr = graph_manager or get_graph_manager()
        attack_paths = mgr._compute_subgraph_attack_paths_sync(
            g,
            max_depth=max_depth,
            max_paths=max_paths,
        )

        is_graph_truncated = (
            len(findings) >= 500
            or len(exported_nodes) >= MAX_GRAPH_NODES
            or len(exported_edges) >= MAX_GRAPH_EDGES
        )

        snapshot = GraphSnapshot(
            incident_id=incident.id,
            nodes=exported_nodes,
            edges=exported_edges,
            attack_paths=attack_paths,
            generated_at=datetime.now(timezone.utc),
            stats={
                "total_nodes": len(exported_nodes),
                "total_edges": len(exported_edges),
                "total_attack_paths": len(attack_paths),
                "events_reconstructed": len(processed_event_ids),
                "findings_correlated": len(findings),
                "is_truncated": is_graph_truncated,
                "node_ceiling": MAX_GRAPH_NODES,
                "edge_ceiling": MAX_GRAPH_EDGES,
            },
        )

        # 10. Persist back to incident model if requested
        if persist:
            incident.entity_graph_snapshot = snapshot.model_dump(mode="json")
            history = list(incident.update_history or [])
            history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "GRAPH_REBUILT",
                "nodes_count": len(exported_nodes),
                "edges_count": len(exported_edges),
                "attack_paths_count": len(attack_paths),
            })
            incident.update_history = history
            await session.commit()
            logger.info(
                "Persisted refreshed attack graph for Incident %s (%d nodes, %d edges, %d paths)",
                incident.id, len(exported_nodes), len(exported_edges), len(attack_paths)
            )

        return snapshot
