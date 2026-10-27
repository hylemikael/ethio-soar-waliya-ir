"""Correlated incident generation and evidence linking service."""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import UUID, uuid4

import networkx as nx
from sqlalchemy import func, or_, select, String
from sqlalchemy.ext.asyncio import AsyncSession

from waliya.contracts import EntityTypeEnum, GraphSnapshot, RelationTypeEnum, SeverityEnum
from waliya.correlation.entity_extractor import EntityExtractor
from waliya.correlation.graph_engine import EntityGraphManager
from waliya.db.models import AssetContextModel, EventModel, FindingModel, IncidentModel
from waliya.incidents.risk_engine import compute_incident_risk
from waliya.threat_intel.matcher import ThreatIntelMatcher

logger = logging.getLogger("waliya.incidents.correlation")

DEFAULT_CORRELATION_WINDOW_SECONDS = 3600  # 1 hour temporal window
SEVERITY_HIERARCHY = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


class IncidentCorrelationService:
    """Correlates security findings and entity graph relationships into persistent incidents."""

    def __init__(self, correlation_window_seconds: int = DEFAULT_CORRELATION_WINDOW_SECONDS):
        self.correlation_window_seconds = correlation_window_seconds

    async def correlate_findings(
        self,
        session: AsyncSession,
        findings: List[FindingModel],
        event_data: Dict[str, Any],
        graph_manager: EntityGraphManager,
    ) -> List[IncidentModel]:
        """Correlate a batch of newly generated findings with active incidents or spawn new ones.

        Correlation Criteria:
        1. Shared non-host entity (user, IP, process, file).
        2. Graph path connectivity (within 2 hops in in-memory entity graph).
        3. Temporal proximity within correlation_window_seconds.
        4. Rejects grouping unrelated events that merely share a host without behavioral connection.

        Returns:
            List of created or updated IncidentModel instances.
        """
        if not findings:
            return []

        # Extract entities associated with this event/finding
        extracted_entities, _ = EntityExtractor.extract(event_data)
        event_entity_ids = {e.id for e in extracted_entities}

        # Also extract any explicit entity from finding explanations
        for f in findings:
            expl = f.explanation or {}
            obs_ent = expl.get("observed_entity")
            if obs_ent:
                event_entity_ids.add(str(obs_ent))

        event_ts_raw = event_data.get("timestamp")
        if isinstance(event_ts_raw, datetime):
            event_ts = event_ts_raw if event_ts_raw.tzinfo else event_ts_raw.replace(tzinfo=timezone.utc)
        elif isinstance(event_ts_raw, str):
            try:
                event_ts = datetime.fromisoformat(event_ts_raw)
                if event_ts.tzinfo is None:
                    event_ts = event_ts.replace(tzinfo=timezone.utc)
            except Exception:
                event_ts = datetime.now(timezone.utc)
        else:
            event_ts = datetime.now(timezone.utc)

        # Query active candidate incidents within the temporal correlation window (bounded to 100 recent candidates)
        cutoff_dt = event_ts - timedelta(seconds=self.correlation_window_seconds)
        active_query = (
            select(IncidentModel)
            .where(
                IncidentModel.status.in_(["OPEN", "INVESTIGATING"]),
                IncidentModel.last_seen >= cutoff_dt,
            )
            .order_by(IncidentModel.last_seen.desc())
            .limit(100)
        )
        res = await session.execute(active_query)
        candidate_incidents = list(res.scalars().all())
        candidate_ids = {c.id for c in candidate_incidents}

        # Targeted query: if recency limit (100) was saturated, older active incidents within the temporal
        # window sharing non-host entities might have been omitted; fetch them to guarantee correctness
        if len(candidate_incidents) >= 100:
            non_host_ents = [e for e in event_entity_ids if isinstance(e, str) and not e.startswith("host:")]
            if non_host_ents:
                entity_predicates = [
                    func.cast(IncidentModel.affected_entities, String).like(f"%{e}%")
                    for e in non_host_ents[:10]
                ]
                targeted_query = (
                    select(IncidentModel)
                    .where(
                        IncidentModel.status.in_(["OPEN", "INVESTIGATING"]),
                        IncidentModel.last_seen >= cutoff_dt,
                        or_(*entity_predicates),
                    )
                    .order_by(IncidentModel.last_seen.desc())
                    .limit(50)
                )
                t_res = await session.execute(targeted_query)
                for t_inc in t_res.scalars().all():
                    if t_inc.id not in candidate_ids:
                        candidate_incidents.append(t_inc)
                        candidate_ids.add(t_inc.id)

        modified_incidents: List[IncidentModel] = []

        for finding in findings:
            if finding.incident_id is not None:
                continue

            matched_incident: Optional[IncidentModel] = None

            # Attempt to match against candidate active incidents
            for candidate in candidate_incidents:
                if self._should_merge(candidate, finding, event_entity_ids, graph_manager):
                    matched_incident = candidate
                    break

            if matched_incident:
                # Merge finding into existing active incident
                await self._merge_into_incident(
                    session,
                    matched_incident,
                    finding,
                    event_entity_ids,
                    event_ts,
                    graph_manager,
                    event_data=event_data,
                )
                if matched_incident not in modified_incidents:
                    modified_incidents.append(matched_incident)
            else:
                # Create a new correlated incident
                new_incident = await self._create_incident(session, finding, event_data, event_entity_ids, event_ts, graph_manager)
                candidate_incidents.append(new_incident)
                modified_incidents.append(new_incident)

        return modified_incidents

    def _should_merge(
        self,
        candidate: IncidentModel,
        arg2: Any,
        arg3: Any,
        arg4: Optional[EntityGraphManager] = None,
    ) -> bool:
        """Determine whether a finding belongs to an existing candidate incident.

        Strictly enforces:
        1. Real findings NEVER merge into simulation incidents.
        2. Simulation findings NEVER merge into real incidents.
        3. Simulation findings from different simulation runs NEVER merge together.
        4. Sharing only a host entity is NOT enough to merge.
        """
        if isinstance(arg2, FindingModel):
            finding: Optional[FindingModel] = arg2
            finding_entity_ids: Set[str] = set(arg3)
            graph_manager: Optional[EntityGraphManager] = arg4
        else:
            finding = None
            finding_entity_ids = set(arg2)
            graph_manager = arg3

        is_sim_finding = bool(
            finding is not None
            and (
                getattr(finding, "is_simulation", False)
                or (finding.explanation and finding.explanation.get("is_simulation"))
            )
        )
        is_sim_candidate = bool(
            getattr(candidate, "is_simulation", False)
            or (candidate.title and candidate.title.startswith("[SIMULATION]"))
        )

        # Invariant 1 & 2: Complete isolation between simulation and real activity
        if is_sim_finding != is_sim_candidate:
            return False

        # Invariant 3: Complete cross-run isolation among simulations
        if is_sim_finding and finding is not None:
            finding_run_id = getattr(finding, "simulation_run_id", None) or (
                finding.explanation.get("simulation_run_id") if finding.explanation else None
            )
            candidate_run_id = getattr(candidate, "simulation_run_id", None)
            if finding_run_id and candidate_run_id and finding_run_id != candidate_run_id:
                return False

        candidate_entities: Set[str] = set()
        for ent in (candidate.affected_entities or []):
            if isinstance(ent, dict):
                ent_str = ent.get("id") or f"{str(ent.get('type', 'entity')).lower()}:{ent.get('value', 'unknown')}"
                candidate_entities.add(ent_str)
            elif isinstance(ent, str):
                candidate_entities.add(ent)

        # 1. Non-host entity intersection (user, IP, process, file)
        non_host_finding_ents = {e for e in finding_entity_ids if not e.startswith("host:")}
        non_host_candidate_ents = {e for e in candidate_entities if not e.startswith("host:")}

        direct_overlap = non_host_finding_ents.intersection(non_host_candidate_ents)
        if direct_overlap:
            logger.debug("Incident %s matched via entity overlap: %s", candidate.id, direct_overlap)
            return True

        # 2. Graph path connectivity (within 2 hops in in-memory correlation graph)
        if graph_manager and hasattr(graph_manager, "graph"):
            non_host_nodes = [n for n in graph_manager.graph.nodes if not n.startswith("host:")]
            ug = graph_manager.graph.subgraph(non_host_nodes).to_undirected(as_view=True)
            for f_ent in non_host_finding_ents:
                if ug.has_node(f_ent):
                    for c_ent in non_host_candidate_ents:
                        if ug.has_node(c_ent):
                            try:
                                dist = nx.shortest_path_length(ug, f_ent, c_ent)
                                if dist <= 2:
                                    logger.debug("Incident %s matched via graph path (dist=%d) between %s and %s", candidate.id, dist, f_ent, c_ent)
                                    return True
                            except (nx.NetworkXNoPath, nx.NodeNotFound):
                                continue

        return False

    async def _merge_into_incident(
        self,
        session: AsyncSession,
        incident: IncidentModel,
        finding: FindingModel,
        finding_entity_ids: Set[str],
        event_ts: datetime,
        graph_manager: EntityGraphManager,
        event_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Attach finding to existing incident and update timestamps, risk, and entities."""
        finding.incident_id = incident.id

        # Update temporal bounds
        if incident.first_seen is None or event_ts < incident.first_seen:
            incident.first_seen = event_ts
        if incident.last_seen is None or event_ts > incident.last_seen:
            incident.last_seen = event_ts

        # Merge affected entities
        current_ents = set(incident.affected_entities or [])
        current_ents.update(finding_entity_ids)
        incident.affected_entities = sorted(list(current_ents))

        # Merge MITRE ATT&CK IDs
        current_mitre = set(incident.mitre_attack_ids or [])
        finding_mitre = finding.explanation.get("mitre_attack_ids") or []
        current_mitre.update(finding_mitre)
        incident.mitre_attack_ids = sorted(list(current_mitre))

        # Preserve simulation provenance invariants during merges
        if getattr(finding, "is_simulation", False):
            incident.is_simulation = True
            if not getattr(incident, "simulation_run_id", None):
                incident.simulation_run_id = getattr(finding, "simulation_run_id", None)

        # Elevate severity if finding has higher severity
        finding_sev = str(finding.severity).upper()
        if SEVERITY_HIERARCHY.index(finding_sev) > SEVERITY_HIERARCHY.index(str(incident.severity).upper()):
            incident.severity = finding_sev

        # Recalculate composite risk score across all findings attached to this incident
        findings_query = select(FindingModel).where(FindingModel.incident_id == incident.id)
        res = await session.execute(findings_query)
        attached_findings = res.scalars().all()

        findings_data = [
            {
                "severity": f.severity,
                "confidence": f.confidence,
                "dedup_key": f.dedup_key,
                "explanation": f.explanation,
                "rule_id": f.rule_id,
                "agent_id": f.agent_id,
            }
            for f in attached_findings
        ]
        # Include current finding
        findings_data.append({
            "severity": finding.severity,
            "confidence": finding.confidence,
            "dedup_key": finding.dedup_key,
            "explanation": finding.explanation,
            "rule_id": finding.rule_id,
            "agent_id": finding.agent_id,
        })

        asset_crit, threat_matches = await self._resolve_context(session, finding.agent_id, event_data)

        # Merge and deduplicate existing incident threat matches with newly observed matches
        existing_matches = []
        if incident.risk_explanation and isinstance(incident.risk_explanation, dict):
            existing_matches = incident.risk_explanation.get("threat_intel_matches", [])

        merged_matches = list(existing_matches)
        seen_keys = {
            (m.get("indicator_type"), m.get("value"), m.get("source"))
            for m in existing_matches if isinstance(m, dict)
        }

        # Include newly resolved event matches
        for tm in threat_matches:
            k = (tm.get("indicator_type"), tm.get("value"), tm.get("source"))
            if k not in seen_keys:
                seen_keys.add(k)
                merged_matches.append(tm)

        # Include any matches directly on the attached finding
        if finding.explanation and isinstance(finding.explanation, dict):
            for tm in finding.explanation.get("threat_intel_matches", []):
                k = (tm.get("indicator_type"), tm.get("value"), tm.get("source"))
                if k not in seen_keys:
                    seen_keys.add(k)
                    merged_matches.append(tm)

        score, risk_expl = compute_incident_risk(
            findings=findings_data,
            affected_entities=incident.affected_entities,
            mitre_attack_ids=incident.mitre_attack_ids,
            asset_criticality=asset_crit,
            threat_intel_matches=merged_matches,
        )
        incident.composite_risk_score = score
        incident.risk_explanation = risk_expl

        # Update entity graph snapshot
        primary_entity = next((e for e in incident.affected_entities if not e.startswith("host:")), incident.affected_entities[0])
        subgraph = await graph_manager.export_subgraph(primary_entity, depth=2, incident_id=incident.id)
        incident.entity_graph_snapshot = subgraph.model_dump(mode="json")

        # Record auditable update entry
        history = list(incident.update_history or [])
        history.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "FINDING_ATTACHED",
            "finding_id": str(finding.id),
            "rule_id": finding.explanation.get("rule_id"),
            "risk_score": score,
        })
        if len(merged_matches) > len(existing_matches):
            history.append({
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "action": "THREAT_INTEL_ENRICHED",
                "finding_id": str(finding.id),
                "matches_count": len(merged_matches),
                "risk_score": score,
            })
        incident.update_history = history

    async def _create_incident(
        self,
        session: AsyncSession,
        finding: FindingModel,
        event_data: Dict[str, Any],
        finding_entity_ids: Set[str],
        event_ts: datetime,
        graph_manager: EntityGraphManager,
    ) -> IncidentModel:
        """Spawn and persist a new security incident for an unassociated finding."""
        incident_id = uuid4()
        finding.incident_id = incident_id

        is_sim = bool(
            getattr(finding, "is_simulation", False)
            or (finding.explanation and finding.explanation.get("is_simulation"))
        )
        sim_run_id = getattr(finding, "simulation_run_id", None) or (
            finding.explanation.get("simulation_run_id") if finding.explanation else None
        )

        rule_name = finding.explanation.get("rule_name") or finding.explanation.get("rule_id") or "Security Alert"
        entity_label = next((e for e in finding_entity_ids if not e.startswith("host:")), str(finding.agent_id or "Host"))
        title = f"{rule_name} on {entity_label}"
        if is_sim:
            title = f"[SIMULATION] {title}"
        description = finding.explanation.get("explanation") or f"Detected security finding from {finding.severity} alert."

        mitre_ids = list(finding.explanation.get("mitre_attack_ids") or [])
        affected_list = sorted(list(finding_entity_ids))

        findings_data = [{
            "severity": finding.severity,
            "confidence": finding.confidence,
            "dedup_key": finding.dedup_key,
            "explanation": finding.explanation,
            "rule_id": finding.rule_id,
            "agent_id": finding.agent_id,
        }]

        asset_crit, threat_matches = await self._resolve_context(session, finding.agent_id, event_data)

        # Merge finding matches with event matches
        merged_matches = list(threat_matches)
        seen_keys = {
            (m.get("indicator_type"), m.get("value"), m.get("source"))
            for m in threat_matches if isinstance(m, dict)
        }
        if finding.explanation and isinstance(finding.explanation, dict):
            for tm in finding.explanation.get("threat_intel_matches", []):
                k = (tm.get("indicator_type"), tm.get("value"), tm.get("source"))
                if k not in seen_keys:
                    seen_keys.add(k)
                    merged_matches.append(tm)

        score, risk_expl = compute_incident_risk(
            findings=findings_data,
            affected_entities=affected_list,
            mitre_attack_ids=mitre_ids,
            asset_criticality=asset_crit,
            threat_intel_matches=merged_matches,
        )

        # Graph snapshot
        subgraph = GraphSnapshot(incident_id=incident_id, nodes=[], edges=[])
        if affected_list:
            primary_entity = next((e for e in affected_list if not e.startswith("host:")), affected_list[0])
            subgraph = await graph_manager.export_subgraph(primary_entity, depth=2, incident_id=incident_id)

        history = [{
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "CREATED",
            "finding_id": str(finding.id),
            "rule_id": finding.explanation.get("rule_id"),
            "initial_score": score,
        }]

        new_incident = IncidentModel(
            id=incident_id,
            title=title[:255],
            description=description,
            severity=finding.severity,
            status="OPEN",
            composite_risk_score=score,
            risk_explanation=risk_expl,
            first_seen=event_ts,
            last_seen=event_ts,
            affected_entities=affected_list,
            mitre_attack_ids=mitre_ids,
            entity_graph_snapshot=subgraph.model_dump(mode="json"),
            update_history=history,
            is_simulation=is_sim,
            simulation_run_id=sim_run_id,
        )

        session.add(new_incident)
        await session.flush()
        logger.info("Created new Incident %s (num=%s): '%s' (score=%.1f)", new_incident.id, new_incident.incident_number, title, score)

        # Queue outbound notification for non-simulation incidents
        if not is_sim:
            try:
                from waliya.integrations.delivery_service import NotificationDeliveryService
                from waliya.integrations.payloads import NotificationEventType, build_incident_created_payload
                notif_payload = build_incident_created_payload(
                    incident_id=new_incident.id,
                    title=new_incident.title,
                    severity=new_incident.severity,
                    composite_risk_score=new_incident.composite_risk_score,
                    status=new_incident.status,
                    first_seen=new_incident.first_seen,
                    last_seen=new_incident.last_seen,
                    affected_entities=new_incident.affected_entities or [],
                    mitre_attack_ids=new_incident.mitre_attack_ids or [],
                )
                await NotificationDeliveryService.queue_notification(
                    session=session,
                    event_type=NotificationEventType.INCIDENT_CREATED.value,
                    event_id=str(new_incident.id),
                    payload=notif_payload,
                )
            except Exception as notif_err:
                logger.warning("Failed queuing incident created notification for %s: %s", new_incident.id, notif_err)

        return new_incident

    async def _resolve_context(
        self,
        session: AsyncSession,
        agent_id: Optional[UUID],
        event_data: Optional[Dict[str, Any]],
    ) -> Tuple[Optional[str], List[Dict[str, Any]]]:
        """Safely resolve asset criticality and threat intelligence matches."""
        asset_crit = None
        if agent_id:
            try:
                res = await session.execute(
                    select(AssetContextModel.criticality).where(AssetContextModel.agent_id == agent_id)
                )
                asset_crit = res.scalar()
            except Exception as e:
                logger.debug("Failed querying asset context: %s", e)

        threat_matches = []
        if event_data:
            try:
                threat_matches = await ThreatIntelMatcher.match_event_observables(session, event_data)
            except Exception as e:
                logger.debug("Failed matching threat indicators: %s", e)

        return asset_crit, threat_matches


# Rebuild graph from durable storage
async def rebuild_graph_from_events(
    session: AsyncSession,
    graph_manager: EntityGraphManager,
    hours: int = 24,
) -> int:
    """Rebuild in-memory NetworkX correlation graph from authoritative PostgreSQL events.

    Provides a clean, bounded recovery mechanism across application restarts.
    """
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    query = (
        select(EventModel)
        .where(EventModel.timestamp >= cutoff)
        .order_by(EventModel.timestamp.asc())
    )
    res = await session.execute(query)
    events = res.scalars().all()

    rebuilt_count = 0
    for ev in events:
        event_dict = {
            "event_id": str(ev.id),
            "agent_id": str(ev.agent_id) if ev.agent_id else None,
            "event_type": ev.event_type,
            "severity": ev.severity,
            "timestamp": ev.timestamp,
            "source": ev.source,
            "attributes": ev.normalized_payload.get("attributes") or ev.normalized_payload,
            "normalized": ev.normalized_payload,
        }
        await graph_manager.ingest_event(event_dict)
        rebuilt_count += 1

    logger.info("Rebuilt in-memory correlation graph with %d events from the past %d hours", rebuilt_count, hours)
    return rebuilt_count
