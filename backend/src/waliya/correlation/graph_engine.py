"""Bounded in-memory entity relationship correlation graph powered by NetworkX."""

import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

import networkx as nx

from waliya.contracts import (
    AttackPath,
    AttackPathStep,
    EntityNeighborsResponse,
    EntityTypeEnum,
    GraphEdge,
    GraphNode,
    GraphSnapshot,
    MitreMappingStateEnum,
    MitreTechniqueMapping,
    RelationTypeEnum,
    SeverityEnum,
)
from waliya.correlation.entity_extractor import EntityExtractor, ExtractedEntity, ExtractedRelationship
from waliya.detection.mitre_catalog import lookup_technique_or_fallback

logger = logging.getLogger("waliya.correlation.graph_engine")

DEFAULT_RETENTION_SECONDS = 3600  # 1 hour correlation sliding window
DEFAULT_MAX_NODES = 5000
DEFAULT_MAX_EDGES = 25000


class EntityGraphManager:
    """Thread-safe, bounded NetworkX graph manager maintaining correlated security entities and relationships."""

    def __init__(
        self,
        retention_seconds: int = DEFAULT_RETENTION_SECONDS,
        max_nodes: int = DEFAULT_MAX_NODES,
        max_edges: int = DEFAULT_MAX_EDGES,
    ):
        self.retention_seconds = retention_seconds
        self.max_nodes = max_nodes
        self.max_edges = max_edges
        self.graph = nx.DiGraph()
        self._lock = asyncio.Lock()

    async def ingest_event(self, event_data: Dict[str, Any]) -> Tuple[int, int]:
        """Extract entities and relationships from a normalized event and update the graph.

        Updates existing nodes and edges in-place with incremented weights and latest evidence.

        Returns:
            Tuple of (new_or_updated_nodes_count, new_or_updated_edges_count).
        """
        entities, relationships = EntityExtractor.extract(event_data)
        if not entities and not relationships:
            return 0, 0

        async with self._lock:
            # 1. Update / Add Nodes
            for entity in entities:
                self._upsert_node(entity)

            # 2. Update / Add Edges
            for rel in relationships:
                self._upsert_edge(rel)

            # 3. Enforce retention and capacity bounds
            self._enforce_bounds()

            return len(entities), len(relationships)

    def _upsert_node(self, entity: ExtractedEntity) -> None:
        """Insert or update an entity node."""
        node_id = entity.id
        if self.graph.has_node(node_id):
            node_data = self.graph.nodes[node_id]
            node_data["last_seen"] = entity.timestamp
            # Merge properties without clobbering existing ones
            node_data["properties"].update(entity.properties)
            node_data["observation_count"] = node_data.get("observation_count", 1) + 1
        else:
            self.graph.add_node(
                node_id,
                entity_type=entity.type,
                label=entity.label,
                properties=dict(entity.properties),
                first_seen=entity.timestamp,
                last_seen=entity.timestamp,
                observation_count=1,
            )

    def _upsert_edge(self, rel: ExtractedRelationship) -> None:
        """Insert or update a directed relationship between two existing nodes."""
        u, v = rel.source_id, rel.target_id
        if not self.graph.has_node(u) or not self.graph.has_node(v):
            return

        rel_conf = getattr(rel, "confidence", 1.0)
        rel_prov = getattr(rel, "provenance", "telemetry")
        rel_desc = getattr(rel, "description", None)

        if self.graph.has_edge(u, v):
            edge_data = self.graph[u][v]
            edge_data["weight"] = edge_data.get("weight", 1.0) + rel.weight
            edge_data["last_seen"] = rel.timestamp
            edge_data["properties"].update(rel.properties)
            edge_data["confidence"] = max(edge_data.get("confidence", 0.0), rel_conf)
            if rel_prov:
                edge_data["provenance"] = rel_prov
            if rel_desc:
                edge_data["description"] = rel_desc
            ev_list = edge_data.setdefault("evidence_event_ids", [])
            if rel.evidence_event_id and rel.evidence_event_id not in ev_list:
                ev_list.append(rel.evidence_event_id)
                if len(ev_list) > 20:
                    ev_list.pop(0)
        else:
            ev_list = [rel.evidence_event_id] if rel.evidence_event_id else []
            self.graph.add_edge(
                u,
                v,
                relation=rel.relation,
                weight=rel.weight,
                confidence=rel_conf,
                provenance=rel_prov,
                description=rel_desc,
                first_seen=rel.timestamp,
                last_seen=rel.timestamp,
                properties=dict(rel.properties),
                evidence_event_ids=ev_list,
            )

    def _enforce_bounds(self) -> None:
        """Prune expired items and enforce hard capacity limits to keep memory bounded."""
        now_ts = datetime.now(timezone.utc).timestamp()
        cutoff_ts = now_ts - self.retention_seconds

        # 1. Prune edges older than the retention window
        expired_edges = [
            (u, v) for u, v, data in self.graph.edges(data=True)
            if data.get("last_seen", datetime.now(timezone.utc)).timestamp() < cutoff_ts
        ]
        for u, v in expired_edges:
            self.graph.remove_edge(u, v)

        # 2. Prune orphaned nodes older than the retention window
        expired_nodes = [
            n for n, data in self.graph.nodes(data=True)
            if self.graph.degree(n) == 0
            and data.get("last_seen", datetime.now(timezone.utc)).timestamp() < cutoff_ts
        ]
        for n in expired_nodes:
            self.graph.remove_node(n)

        # 3. Capacity limit enforcement (LRU eviction if edge count exceeds limit)
        if self.graph.number_of_edges() > self.max_edges:
            edges_by_time = sorted(
                self.graph.edges(data=True),
                key=lambda x: x[2].get("last_seen", datetime.now(timezone.utc)).timestamp()
            )
            excess = len(edges_by_time) - self.max_edges
            for u, v, _ in edges_by_time[:excess]:
                self.graph.remove_edge(u, v)

        # 4. Capacity limit enforcement for nodes
        if self.graph.number_of_nodes() > self.max_nodes:
            # Prefer removing degree 0 nodes first, then oldest
            nodes_by_time = sorted(
                self.graph.nodes(data=True),
                key=lambda x: (self.graph.degree(x[0]), x[1].get("last_seen", datetime.now(timezone.utc)).timestamp())
            )
            excess = len(nodes_by_time) - self.max_nodes
            for n, _ in nodes_by_time[:excess]:
                self.graph.remove_node(n)

    async def prune_expired(self) -> Tuple[int, int]:
        """Manually trigger sliding-window expiration and pruning."""
        async with self._lock:
            before_nodes = self.graph.number_of_nodes()
            before_edges = self.graph.number_of_edges()
            self._enforce_bounds()
            pruned_nodes = before_nodes - self.graph.number_of_nodes()
            pruned_edges = before_edges - self.graph.number_of_edges()
            return pruned_nodes, pruned_edges

    async def export_snapshot(
        self,
        incident_id: Optional[UUID] = None,
        max_nodes: int = 200,
        max_edges: int = 500,
        include_attack_paths: bool = True,
    ) -> GraphSnapshot:
        """Export the current graph as a deterministic validated Pydantic GraphSnapshot."""
        async with self._lock:
            exported_nodes: List[GraphNode] = []
            exported_edges: List[GraphEdge] = []

            # Sort nodes deterministically by ID
            sorted_nodes = sorted(list(self.graph.nodes(data=True)), key=lambda x: str(x[0]))[:max_nodes]
            selected_node_ids = {n[0] for n in sorted_nodes}

            for node_id, data in sorted_nodes:
                entity_type = data.get("entity_type", EntityTypeEnum.HOST)
                if isinstance(entity_type, str):
                    try:
                        entity_type = EntityTypeEnum(entity_type)
                    except ValueError:
                        entity_type = EntityTypeEnum.HOST

                exported_nodes.append(GraphNode(
                    id=node_id,
                    type=entity_type,
                    label=data.get("label", node_id),
                    properties=data.get("properties", {}),
                    first_seen=data.get("first_seen"),
                    last_seen=data.get("last_seen"),
                    observation_count=data.get("observation_count", 1),
                    evidence_count=len(data.get("properties", {}).get("evidence_event_ids", [])),
                ))

            # Filter and sort edges deterministically
            candidate_edges = [
                (u, v, data) for u, v, data in self.graph.edges(data=True)
                if u in selected_node_ids and v in selected_node_ids
            ]
            sorted_edges = sorted(
                candidate_edges,
                key=lambda x: (str(x[0]), str(x[1]), str(x[2].get("relation", "")))
            )[:max_edges]

            for u, v, data in sorted_edges:
                rel_type = data.get("relation", RelationTypeEnum.CONNECTED_TO)
                if isinstance(rel_type, str):
                    try:
                        rel_type = RelationTypeEnum(rel_type)
                    except ValueError:
                        rel_type = RelationTypeEnum.CONNECTED_TO

                exported_edges.append(GraphEdge(
                    source=u,
                    target=v,
                    relation=rel_type,
                    weight=float(data.get("weight", 1.0)),
                    confidence=float(data.get("confidence", 1.0)),
                    provenance=str(data.get("provenance", "telemetry")),
                    timestamp=data.get("last_seen", datetime.now(timezone.utc)),
                    evidence_event_ids=list(data.get("evidence_event_ids", [])),
                    properties=dict(data.get("properties", {})),
                ))

            attack_paths: List[AttackPath] = []
            if include_attack_paths and len(exported_nodes) > 1:
                attack_paths = self._compute_attack_paths_sync(max_depth=4, max_paths=10)

            return GraphSnapshot(
                incident_id=incident_id,
                nodes=exported_nodes,
                edges=exported_edges,
                attack_paths=attack_paths,
                generated_at=datetime.now(timezone.utc),
                stats={
                    "total_nodes": len(exported_nodes),
                    "total_edges": len(exported_edges),
                    "total_attack_paths": len(attack_paths),
                },
            )

    async def export_subgraph(
        self,
        center_node_id: str,
        depth: int = 2,
        incident_id: Optional[UUID] = None,
        max_nodes: int = 200,
        max_edges: int = 500,
    ) -> GraphSnapshot:
        """Extract and export an ego subgraph around a specific entity up to depth hops."""
        async with self._lock:
            if not self.graph.has_node(center_node_id):
                return GraphSnapshot(incident_id=incident_id, nodes=[], edges=[])

            bounded_depth = min(max(1, depth), 6)
            sub_nodes: Set[str] = {center_node_id}
            frontier: Set[str] = {center_node_id}

            for _ in range(bounded_depth):
                next_frontier: Set[str] = set()
                for n in frontier:
                    next_frontier.update(self.graph.successors(n))
                    next_frontier.update(self.graph.predecessors(n))
                sub_nodes.update(next_frontier)
                frontier = next_frontier
                if len(sub_nodes) >= max_nodes:
                    break

            subgraph = self.graph.subgraph(sub_nodes)

            nodes_out: List[GraphNode] = []
            for n in sorted(list(subgraph.nodes()), key=lambda x: str(x))[:max_nodes]:
                data = self.graph.nodes[n]
                entity_type = data.get("entity_type", EntityTypeEnum.HOST)
                if isinstance(entity_type, str):
                    try:
                        entity_type = EntityTypeEnum(entity_type)
                    except ValueError:
                        entity_type = EntityTypeEnum.HOST

                nodes_out.append(GraphNode(
                    id=n,
                    type=entity_type,
                    label=data.get("label", n),
                    properties=data.get("properties", {}),
                    first_seen=data.get("first_seen"),
                    last_seen=data.get("last_seen"),
                    observation_count=data.get("observation_count", 1),
                ))

            node_id_set = {n.id for n in nodes_out}
            edges_out: List[GraphEdge] = []
            sorted_sub_edges = sorted(
                [(u, v) for u, v in subgraph.edges() if u in node_id_set and v in node_id_set],
                key=lambda x: (str(x[0]), str(x[1]))
            )[:max_edges]

            for u, v in sorted_sub_edges:
                data = self.graph[u][v]
                rel_type = data.get("relation", RelationTypeEnum.CONNECTED_TO)
                if isinstance(rel_type, str):
                    try:
                        rel_type = RelationTypeEnum(rel_type)
                    except ValueError:
                        rel_type = RelationTypeEnum.CONNECTED_TO

                edges_out.append(GraphEdge(
                    source=u,
                    target=v,
                    relation=rel_type,
                    weight=float(data.get("weight", 1.0)),
                    confidence=float(data.get("confidence", 1.0)),
                    provenance=str(data.get("provenance", "telemetry")),
                    timestamp=data.get("last_seen", datetime.now(timezone.utc)),
                    evidence_event_ids=list(data.get("evidence_event_ids", [])),
                    properties=dict(data.get("properties", {})),
                ))

            attack_paths = self._compute_subgraph_attack_paths_sync(subgraph, max_depth=bounded_depth, max_paths=5)

            return GraphSnapshot(
                incident_id=incident_id,
                nodes=nodes_out,
                edges=edges_out,
                attack_paths=attack_paths,
                generated_at=datetime.now(timezone.utc),
                stats={
                    "total_nodes": len(nodes_out),
                    "total_edges": len(edges_out),
                    "total_attack_paths": len(attack_paths),
                },
            )

    def _compute_attack_paths_sync(
        self,
        max_depth: int = 4,
        max_paths: int = 10,
        candidate_sources: Optional[List[str]] = None,
        candidate_targets: Optional[List[str]] = None,
    ) -> List[AttackPath]:
        """Compute directed attack paths on current graph synchronously within lock."""
        return self._compute_subgraph_attack_paths_sync(
            self.graph,
            max_depth=max_depth,
            max_paths=max_paths,
            candidate_sources=candidate_sources,
            candidate_targets=candidate_targets,
        )

    def _compute_subgraph_attack_paths_sync(
        self,
        g: nx.DiGraph,
        max_depth: int = 4,
        max_paths: int = 10,
        candidate_sources: Optional[List[str]] = None,
        candidate_targets: Optional[List[str]] = None,
    ) -> List[AttackPath]:
        """Deterministic, bounded attack path discovery using NetworkX."""
        depth_limit = min(max(1, max_depth), 6)
        path_limit = min(max(1, max_paths), 20)

        # 1. Resolve Sources (Entry Points)
        sources: Set[str] = set()
        if candidate_sources:
            sources = {s for s in candidate_sources if g.has_node(s)}
        if not sources:
            for n, data in g.nodes(data=True):
                etype = str(data.get("entity_type", ""))
                # Entry points: External IPs, indicators, users with outbound activity
                if "IPAddress" in etype or "Indicator" in etype:
                    sources.add(n)
                elif "User" in etype and g.out_degree(n) > 0:
                    sources.add(n)
                elif g.in_degree(n) == 0 and g.out_degree(n) > 0:
                    sources.add(n)

        # 2. Resolve Targets (Impacted Assets)
        targets: Set[str] = set()
        if candidate_targets:
            targets = {t for t in candidate_targets if g.has_node(t)}
        if not targets:
            for n, data in g.nodes(data=True):
                etype = str(data.get("entity_type", ""))
                # Impact points: Files, processes, triggered alerts
                if "File" in etype or "Alert" in etype:
                    targets.add(n)
                elif "Process" in etype and g.in_degree(n) > 0:
                    targets.add(n)
                elif g.out_degree(n) == 0 and g.in_degree(n) > 0:
                    targets.add(n)

        discovered_paths: List[AttackPath] = []
        seen_paths: Set[Tuple[str, ...]] = set()

        sorted_sources = sorted(list(sources))
        sorted_targets = sorted(list(targets))

        for s in sorted_sources:
            for t in sorted_targets:
                if s == t:
                    continue
                try:
                    # Bounded simple path search
                    paths = nx.all_simple_paths(g, source=s, target=t, cutoff=depth_limit)
                    for path in paths:
                        path_tuple = tuple(path)
                        if path_tuple in seen_paths:
                            continue
                        seen_paths.add(path_tuple)

                        # Assemble steps
                        steps: List[AttackPathStep] = []
                        step_confidences: List[float] = []

                        for i in range(len(path) - 1):
                            u_node = path[i]
                            v_node = path[i + 1]
                            edge_data = g[u_node][v_node]
                            r_type = edge_data.get("relation", RelationTypeEnum.CONNECTED_TO)
                            if isinstance(r_type, str):
                                try:
                                    r_type = RelationTypeEnum(r_type)
                                except ValueError:
                                    r_type = RelationTypeEnum.CONNECTED_TO

                            conf = float(edge_data.get("confidence", 1.0))
                            step_confidences.append(conf)

                            ev_ids = list(edge_data.get("evidence_event_ids", []))
                            step_mitre_techniques: List[MitreTechniqueMapping] = []
                            u_props = g.nodes[u_node].get("properties", {}) if g.has_node(u_node) else {}
                            v_props = g.nodes[v_node].get("properties", {}) if g.has_node(v_node) else {}
                            e_props = edge_data.get("properties", {})
                            raw_mitre = (
                                u_props.get("mitre_attack_ids")
                                or u_props.get("mitre_ids")
                                or v_props.get("mitre_attack_ids")
                                or v_props.get("mitre_ids")
                                or e_props.get("mitre_attack_ids")
                                or []
                            )
                            if isinstance(raw_mitre, list):
                                for tid in raw_mitre:
                                    clean_tid = str(tid).strip().upper()
                                    if clean_tid:
                                        entry = lookup_technique_or_fallback(clean_tid)
                                        parsed_ev_ids: List[UUID] = []
                                        for eid in ev_ids:
                                            try:
                                                parsed_ev_ids.append(UUID(str(eid)))
                                            except (ValueError, TypeError):
                                                pass
                                        step_mitre_techniques.append(
                                            MitreTechniqueMapping(
                                                technique_id=entry.technique_id,
                                                technique_name=entry.name,
                                                tactics=entry.tactics,
                                                mapping_state=MitreMappingStateEnum.MAPPED if parsed_ev_ids else MitreMappingStateEnum.INSUFFICIENT_EVIDENCE,
                                                confidence=int(round(conf * 100)),
                                                finding_ids=[],
                                                evidence_event_ids=parsed_ev_ids,
                                                rationale=f"Step {u_node} -> {v_node} associated with {entry.name}.",
                                                reference_url=entry.reference_url,
                                            )
                                        )

                            steps.append(AttackPathStep(
                                step_order=i + 1,
                                source=u_node,
                                target=v_node,
                                relation=r_type,
                                confidence=conf,
                                timestamp=edge_data.get("last_seen"),
                                evidence_event_ids=ev_ids,
                                description=edge_data.get("description") or f"{u_node} -> {r_type} -> {v_node}",
                                mitre_techniques=step_mitre_techniques,
                            ))

                        avg_conf = sum(step_confidences) / len(step_confidences) if step_confidences else 0.8
                        target_type = str(g.nodes[t].get("entity_type", ""))
                        if "File" in target_type or "CRITICAL" in str(g.nodes[t].get("properties", {})):
                            sev = SeverityEnum.CRITICAL
                        elif "Process" in target_type or "HIGH" in str(g.nodes[t].get("properties", {})):
                            sev = SeverityEnum.HIGH
                        else:
                            sev = SeverityEnum.MEDIUM

                        summary = " -> ".join(path)

                        discovered_paths.append(AttackPath(
                            entry_node=s,
                            target_node=t,
                            hop_count=len(path) - 1,
                            risk_severity=sev,
                            confidence=round(avg_conf, 2),
                            steps=steps,
                            summary=f"Attack path ({len(path) - 1} hops): {summary}",
                        ))

                        if len(discovered_paths) >= path_limit:
                            break
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

                if len(discovered_paths) >= path_limit:
                    break
            if len(discovered_paths) >= path_limit:
                break

        # Sort paths deterministically by severity desc, hop count asc
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        return sorted(
            discovered_paths,
            key=lambda p: (sev_order.get(p.risk_severity.value, 5), p.hop_count, p.summary)
        )

    async def find_attack_paths(
        self,
        max_depth: int = 4,
        max_paths: int = 10,
        candidate_sources: Optional[List[str]] = None,
        candidate_targets: Optional[List[str]] = None,
    ) -> List[AttackPath]:
        """Asynchronously compute directed attack paths across active correlation graph."""
        async with self._lock:
            return self._compute_attack_paths_sync(
                max_depth=max_depth,
                max_paths=max_paths,
                candidate_sources=candidate_sources,
                candidate_targets=candidate_targets,
            )

    async def find_paths_between(
        self,
        source_id: str,
        target_id: str,
        max_depth: int = 4,
        max_paths: int = 5,
    ) -> List[AttackPath]:
        """Find simple directed paths between two specific entity nodes."""
        async with self._lock:
            if not self.graph.has_node(source_id) or not self.graph.has_node(target_id):
                return []
            return self._compute_attack_paths_sync(
                max_depth=max_depth,
                max_paths=max_paths,
                candidate_sources=[source_id],
                candidate_targets=[target_id],
            )

    async def get_entity_neighbors(
        self,
        entity_id: str,
        depth: int = 1,
        max_neighbors: int = 50,
    ) -> Optional[EntityNeighborsResponse]:
        """Retrieve bounded k-hop neighborhood and supporting edges for an entity."""
        async with self._lock:
            if not self.graph.has_node(entity_id):
                return None

            data = self.graph.nodes[entity_id]
            entity_type = data.get("entity_type", EntityTypeEnum.HOST)
            if isinstance(entity_type, str):
                try:
                    entity_type = EntityTypeEnum(entity_type)
                except ValueError:
                    entity_type = EntityTypeEnum.HOST

            center_node = GraphNode(
                id=entity_id,
                type=entity_type,
                label=data.get("label", entity_id),
                properties=data.get("properties", {}),
                first_seen=data.get("first_seen"),
                last_seen=data.get("last_seen"),
                observation_count=data.get("observation_count", 1),
            )

            # Discover neighbors within depth
            sub_nodes: Set[str] = {entity_id}
            frontier: Set[str] = {entity_id}
            bounded_depth = min(max(1, depth), 4)

            for _ in range(bounded_depth):
                next_frontier: Set[str] = set()
                for n in frontier:
                    next_frontier.update(self.graph.successors(n))
                    next_frontier.update(self.graph.predecessors(n))
                sub_nodes.update(next_frontier)
                frontier = next_frontier
                if len(sub_nodes) >= max_neighbors:
                    break

            neighbor_nodes: List[GraphNode] = []
            for n in sorted(list(sub_nodes - {entity_id}))[:max_neighbors]:
                ndata = self.graph.nodes[n]
                ntype = ndata.get("entity_type", EntityTypeEnum.HOST)
                if isinstance(ntype, str):
                    try:
                        ntype = EntityTypeEnum(ntype)
                    except ValueError:
                        ntype = EntityTypeEnum.HOST
                neighbor_nodes.append(GraphNode(
                    id=n,
                    type=ntype,
                    label=ndata.get("label", n),
                    properties=ndata.get("properties", {}),
                    first_seen=ndata.get("first_seen"),
                    last_seen=ndata.get("last_seen"),
                    observation_count=ndata.get("observation_count", 1),
                ))

            relevant_ids = {entity_id}.union({n.id for n in neighbor_nodes})
            edges: List[GraphEdge] = []
            for u, v in self.graph.edges():
                if u in relevant_ids and v in relevant_ids:
                    edata = self.graph[u][v]
                    r_type = edata.get("relation", RelationTypeEnum.CONNECTED_TO)
                    if isinstance(r_type, str):
                        try:
                            r_type = RelationTypeEnum(r_type)
                        except ValueError:
                            r_type = RelationTypeEnum.CONNECTED_TO
                    edges.append(GraphEdge(
                        source=u,
                        target=v,
                        relation=r_type,
                        weight=float(edata.get("weight", 1.0)),
                        confidence=float(edata.get("confidence", 1.0)),
                        provenance=str(edata.get("provenance", "telemetry")),
                        timestamp=edata.get("last_seen", datetime.now(timezone.utc)),
                        evidence_event_ids=list(edata.get("evidence_event_ids", [])),
                        properties=dict(edata.get("properties", {})),
                    ))

            return EntityNeighborsResponse(
                entity=center_node,
                neighbors=neighbor_nodes,
                edges=edges,
                degree=self.graph.degree(entity_id),
                in_degree=self.graph.in_degree(entity_id),
                out_degree=self.graph.out_degree(entity_id),
            )

    def stats(self) -> Dict[str, Any]:
        """Return structural graph statistics, type breakdowns, and density."""
        type_counts: Dict[str, int] = {}
        for _, data in self.graph.nodes(data=True):
            t = str(data.get("entity_type", "Unknown"))
            type_counts[t] = type_counts.get(t, 0) + 1

        rel_counts: Dict[str, int] = {}
        for _, _, data in self.graph.edges(data=True):
            r = str(data.get("relation", "Unknown"))
            rel_counts[r] = rel_counts.get(r, 0) + 1

        density = nx.density(self.graph) if self.graph.number_of_nodes() > 1 else 0.0

        return {
            "node_count": self.graph.number_of_nodes(),
            "edge_count": self.graph.number_of_edges(),
            "density": round(density, 4),
            "retention_seconds": self.retention_seconds,
            "max_nodes": self.max_nodes,
            "max_edges": self.max_edges,
            "nodes_by_type": type_counts,
            "edges_by_relation": rel_counts,
        }


# Global graph manager singleton
_global_graph_manager: Optional[EntityGraphManager] = None


def get_graph_manager() -> EntityGraphManager:
    """Access the application-wide entity correlation graph manager."""
    global _global_graph_manager
    if _global_graph_manager is None:
        _global_graph_manager = EntityGraphManager()
    return _global_graph_manager
