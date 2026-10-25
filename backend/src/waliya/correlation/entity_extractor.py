"""Entity and relationship extraction from normalized security telemetry events."""

import ipaddress
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID

from waliya.contracts import EntityTypeEnum, RelationTypeEnum

logger = logging.getLogger("waliya.correlation.entity_extractor")


@dataclass
class ExtractedEntity:
    """Normalized security entity to be stored in the correlation graph."""
    id: str
    type: EntityTypeEnum
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    observation_count: int = 1


@dataclass
class ExtractedRelationship:
    """Normalized directed relationship between two entities."""
    source_id: str
    target_id: str
    relation: RelationTypeEnum
    weight: float = 1.0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    properties: Dict[str, Any] = field(default_factory=dict)
    evidence_event_id: str = ""
    confidence: float = 1.0
    provenance: str = "telemetry"
    description: Optional[str] = None


def is_valid_ip(ip_str: Optional[str]) -> bool:
    """Check if a string is a valid IPv4 or IPv6 address."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    clean_ip = ip_str.strip()
    if clean_ip in ("0.0.0.0", "::", "127.0.0.1", "localhost", "none", "unknown"):
        return False
    try:
        ipaddress.ip_address(clean_ip)
        return True
    except ValueError:
        return False


class EntityExtractor:
    """Extracts typed entities and directed relationships from validated security events.

    Strictly creates relationships supported by verifiable event evidence.
    """

    @classmethod
    def extract(cls, event_data: Dict[str, Any]) -> Tuple[List[ExtractedEntity], List[ExtractedRelationship]]:
        """Extract entities and relationships from a normalized event dictionary.

        Args:
            event_data: Event dictionary containing event_type, agent_id, timestamp, and attributes.

        Returns:
            Tuple of (entities, relationships).
        """
        entities: Dict[str, ExtractedEntity] = {}
        relationships: List[ExtractedRelationship] = []

        event_id = str(event_data.get("event_id", ""))
        event_type = event_data.get("event_type", "")
        agent_id_str = str(event_data.get("agent_id") or "")
        source = event_data.get("source", "sensor")

        # Parse event timestamp
        ts_raw = event_data.get("timestamp")
        if isinstance(ts_raw, datetime):
            event_ts = ts_raw if ts_raw.tzinfo else ts_raw.replace(tzinfo=timezone.utc)
        elif isinstance(ts_raw, str):
            try:
                event_ts = datetime.fromisoformat(ts_raw)
                if event_ts.tzinfo is None:
                    event_ts = event_ts.replace(tzinfo=timezone.utc)
            except Exception:
                event_ts = datetime.now(timezone.utc)
        else:
            event_ts = datetime.now(timezone.utc)

        # Extract attributes from either top-level attributes or normalized container
        attrs = event_data.get("attributes")
        if not attrs or not isinstance(attrs, dict):
            norm = event_data.get("normalized")
            if isinstance(norm, dict) and isinstance(norm.get("attributes"), dict):
                attrs = norm["attributes"]
            else:
                attrs = event_data.get("payload") or {}

        # 1. Base Host Entity (if agent_id or host source exists)
        host_entity_id: Optional[str] = None
        if agent_id_str:
            host_entity_id = f"host:{agent_id_str}"
            entities[host_entity_id] = ExtractedEntity(
                id=host_entity_id,
                type=EntityTypeEnum.HOST,
                label=f"Host-{agent_id_str[:8]}",
                properties={"agent_id": agent_id_str, "source": source},
                timestamp=event_ts,
            )

        # 2. Event-Type Specific Extraction
        if event_type == "AUTHENTICATION":
            user_name = str(attrs.get("user") or attrs.get("username") or "").strip()
            src_ip = str(attrs.get("src_ip") or "").strip()
            service = str(attrs.get("service") or "pam").strip()
            auth_status = str(attrs.get("status") or "FAILURE").upper()

            user_id: Optional[str] = None
            if user_name and user_name.lower() not in ("unknown", "none", ""):
                user_id = f"user:{user_name.lower()}"
                entities[user_id] = ExtractedEntity(
                    id=user_id,
                    type=EntityTypeEnum.USER,
                    label=user_name,
                    properties={"username": user_name},
                    timestamp=event_ts,
                )

            ip_id: Optional[str] = None
            if is_valid_ip(src_ip):
                ip_id = f"ip:{src_ip}"
                entities[ip_id] = ExtractedEntity(
                    id=ip_id,
                    type=EntityTypeEnum.IP_ADDRESS,
                    label=src_ip,
                    properties={"ip_address": src_ip},
                    timestamp=event_ts,
                )

            # Relationships: User -> AUTHENTICATED_TO -> Host
            if user_id and host_entity_id:
                relationships.append(ExtractedRelationship(
                    source_id=user_id,
                    target_id=host_entity_id,
                    relation=RelationTypeEnum.AUTHENTICATED_TO,
                    weight=1.0 if auth_status == "SUCCESS" else 0.5,
                    timestamp=event_ts,
                    properties={"service": service, "status": auth_status},
                    evidence_event_id=event_id,
                    confidence=1.0 if auth_status == "SUCCESS" else 0.7,
                    provenance=f"telemetry:{service}",
                    description=f"User '{user_name}' authentication via {service} ({auth_status})",
                ))

            # IP -> CONNECTED_TO -> Host
            if ip_id and host_entity_id:
                relationships.append(ExtractedRelationship(
                    source_id=ip_id,
                    target_id=host_entity_id,
                    relation=RelationTypeEnum.CONNECTED_TO,
                    weight=1.0,
                    timestamp=event_ts,
                    properties={"service": service, "auth_status": auth_status},
                    evidence_event_id=event_id,
                    confidence=1.0,
                    provenance=f"telemetry:{service}",
                    description=f"Connection from {src_ip} ({service})",
                ))

        elif event_type == "PROCESS_EXECUTION":
            pid = attrs.get("pid")
            ppid = attrs.get("ppid")
            exe = str(attrs.get("exe") or attrs.get("process_name") or "").strip()
            username = str(attrs.get("username") or attrs.get("user") or "").strip()
            cmdline = str(attrs.get("cmdline") or "").strip()
            sha256 = attrs.get("sha256")

            if pid and isinstance(pid, int) and pid > 0:
                scope = agent_id_str or "host"
                proc_name = exe.split("/")[-1] if exe else "proc"
                proc_id = f"process:{scope}:{pid}:{proc_name}"

                entities[proc_id] = ExtractedEntity(
                    id=proc_id,
                    type=EntityTypeEnum.PROCESS,
                    label=f"{proc_name} (PID {pid})",
                    properties={
                        "pid": pid,
                        "ppid": ppid,
                        "exe": exe,
                        "cmdline": cmdline[:512],
                        "username": username,
                        "sha256": sha256,
                    },
                    timestamp=event_ts,
                )

                # Process -> Host relationship (Host spawned process)
                if host_entity_id:
                    relationships.append(ExtractedRelationship(
                        source_id=host_entity_id,
                        target_id=proc_id,
                        relation=RelationTypeEnum.SPAWNED,
                        weight=1.0,
                        timestamp=event_ts,
                        properties={"cmdline": cmdline[:256]},
                        evidence_event_id=event_id,
                        confidence=1.0,
                        provenance=f"telemetry:{source}",
                        description=f"Host executed process {proc_name} (PID {pid})",
                    ))

                # User -> Process relationship (User spawned process)
                if username and username.lower() not in ("unknown", "none", ""):
                    user_id = f"user:{username.lower()}"
                    entities[user_id] = ExtractedEntity(
                        id=user_id,
                        type=EntityTypeEnum.USER,
                        label=username,
                        properties={"username": username},
                        timestamp=event_ts,
                    )
                    relationships.append(ExtractedRelationship(
                        source_id=user_id,
                        target_id=proc_id,
                        relation=RelationTypeEnum.SPAWNED,
                        weight=1.0,
                        timestamp=event_ts,
                        properties={"cmdline": cmdline[:256]},
                        evidence_event_id=event_id,
                        confidence=0.95,
                        provenance=f"telemetry:{source}",
                        description=f"User '{username}' spawned {proc_name} (PID {pid})",
                    ))

                # Parent Process -> Process relationship
                if ppid and isinstance(ppid, int) and ppid > 0 and ppid != pid:
                    parent_proc_id = f"process:{scope}:{ppid}:parent"
                    if parent_proc_id not in entities:
                        entities[parent_proc_id] = ExtractedEntity(
                            id=parent_proc_id,
                            type=EntityTypeEnum.PROCESS,
                            label=f"Parent (PID {ppid})",
                            properties={"pid": ppid},
                            timestamp=event_ts,
                        )
                    relationships.append(ExtractedRelationship(
                        source_id=parent_proc_id,
                        target_id=proc_id,
                        relation=RelationTypeEnum.SPAWNED,
                        weight=1.0,
                        timestamp=event_ts,
                        properties={"pid": pid, "ppid": ppid},
                        evidence_event_id=event_id,
                        confidence=0.90,
                        provenance=f"telemetry:{source}",
                        description=f"Parent process PID {ppid} spawned PID {pid} ({proc_name})",
                    ))

        elif event_type == "FILE_INTEGRITY":
            file_path = str(attrs.get("file_path") or "").strip()
            action = str(attrs.get("action") or "MODIFIED").upper()
            sha256 = attrs.get("sha256")
            size_bytes = attrs.get("size_bytes")
            is_executable = bool(attrs.get("is_executable", False))

            if file_path:
                scope = agent_id_str or "host"
                file_name = file_path.split("/")[-1] or file_path
                file_id = f"file:{scope}:{file_path}"

                entities[file_id] = ExtractedEntity(
                    id=file_id,
                    type=EntityTypeEnum.FILE,
                    label=file_name,
                    properties={
                        "file_path": file_path,
                        "action": action,
                        "sha256": sha256,
                        "size_bytes": size_bytes,
                        "is_executable": is_executable,
                    },
                    timestamp=event_ts,
                )

                # Host -> MODIFIED -> File
                if host_entity_id:
                    relationships.append(ExtractedRelationship(
                        source_id=host_entity_id,
                        target_id=file_id,
                        relation=RelationTypeEnum.MODIFIED,
                        weight=1.0,
                        timestamp=event_ts,
                        properties={"action": action, "sha256": sha256},
                        evidence_event_id=event_id,
                        confidence=1.0,
                        provenance=f"telemetry:{source}",
                        description=f"Host modified file '{file_path}' ({action})",
                    ))

            # User -> MODIFIED -> File
            user_name = str(attrs.get("user") or attrs.get("username") or "").strip()
            if user_name and user_name.lower() not in ("unknown", "none", ""):
                user_id = f"user:{user_name.lower()}"
                entities[user_id] = ExtractedEntity(
                    id=user_id,
                    type=EntityTypeEnum.USER,
                    label=user_name,
                    properties={"username": user_name},
                    timestamp=event_ts,
                )
                if file_path:
                    scope = agent_id_str or "host"
                    target_file_id = f"file:{scope}:{file_path}"
                    relationships.append(ExtractedRelationship(
                        source_id=user_id,
                        target_id=target_file_id,
                        relation=RelationTypeEnum.MODIFIED,
                        weight=1.0,
                        timestamp=event_ts,
                        properties={"action": action, "file_path": file_path},
                        evidence_event_id=event_id,
                        confidence=0.85,
                        provenance=f"telemetry:{source}",
                        description=f"User '{user_name}' modified file '{file_path}'",
                    ))

        elif event_type == "NETWORK_CONNECTION":
            src_ip = str(attrs.get("src_ip") or attrs.get("source_ip") or "").strip()
            dst_ip = str(attrs.get("dst_ip") or attrs.get("dest_ip") or "").strip()
            dst_port = attrs.get("dst_port") or attrs.get("dest_port")
            protocol = str(attrs.get("protocol") or "TCP").upper()
            direction = str(attrs.get("direction") or "OUTBOUND").upper()
            pid = attrs.get("pid")

            src_ip_id: Optional[str] = None
            if is_valid_ip(src_ip):
                src_ip_id = f"ip:{src_ip}"
                entities[src_ip_id] = ExtractedEntity(
                    id=src_ip_id,
                    type=EntityTypeEnum.IP_ADDRESS,
                    label=src_ip,
                    properties={"ip_address": src_ip},
                    timestamp=event_ts,
                )

            dst_ip_id: Optional[str] = None
            if is_valid_ip(dst_ip):
                dst_ip_id = f"ip:{dst_ip}"
                entities[dst_ip_id] = ExtractedEntity(
                    id=dst_ip_id,
                    type=EntityTypeEnum.IP_ADDRESS,
                    label=f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                    properties={"ip_address": dst_ip, "port": dst_port},
                    timestamp=event_ts,
                )

            # Process entity and Process -> CONNECTED_TO -> Dest IP
            if pid and isinstance(pid, int) and pid > 0:
                scope = agent_id_str or "host"
                proc_name = str(attrs.get("process_name") or attrs.get("exe") or "proc").split("/")[-1]
                proc_id = f"process:{scope}:{pid}:{proc_name}"
                if proc_id not in entities:
                    entities[proc_id] = ExtractedEntity(
                        id=proc_id,
                        type=EntityTypeEnum.PROCESS,
                        label=f"{proc_name} (PID {pid})",
                        properties={"pid": pid},
                        timestamp=event_ts,
                    )
                if dst_ip_id:
                    relationships.append(ExtractedRelationship(
                        source_id=proc_id,
                        target_id=dst_ip_id,
                        relation=RelationTypeEnum.CONNECTED_TO,
                        weight=1.0,
                        timestamp=event_ts,
                        properties={"dst_port": dst_port, "protocol": protocol, "direction": direction},
                        evidence_event_id=event_id,
                        confidence=0.95,
                        provenance="telemetry:network",
                        description=f"Process {proc_name} connected to {dst_ip}:{dst_port}",
                    ))
            if is_valid_ip(dst_ip) and dst_ip_id not in entities:
                dst_ip_id = f"ip:{dst_ip}"
                entities[dst_ip_id] = ExtractedEntity(
                    id=dst_ip_id,
                    type=EntityTypeEnum.IP_ADDRESS,
                    label=f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                    properties={"ip_address": dst_ip, "port": dst_port},
                    timestamp=event_ts,
                )

            # Host -> CONNECTED_TO -> Dest IP
            if host_entity_id and dst_ip_id:
                relationships.append(ExtractedRelationship(
                    source_id=host_entity_id,
                    target_id=dst_ip_id,
                    relation=RelationTypeEnum.CONNECTED_TO,
                    weight=1.0,
                    timestamp=event_ts,
                    properties={"dst_port": dst_port, "protocol": protocol, "direction": direction},
                    evidence_event_id=event_id,
                    confidence=1.0,
                    provenance="telemetry:network",
                    description=f"Host connected to {dst_ip}:{dst_port}",
                ))

            # Src IP -> CONNECTED_TO -> Dest IP
            if src_ip_id and dst_ip_id and src_ip_id != dst_ip_id:
                relationships.append(ExtractedRelationship(
                    source_id=src_ip_id,
                    target_id=dst_ip_id,
                    relation=RelationTypeEnum.CONNECTED_TO,
                    weight=1.0,
                    timestamp=event_ts,
                    properties={"dst_port": dst_port, "protocol": protocol, "direction": direction},
                    evidence_event_id=event_id,
                    confidence=0.90,
                    provenance="telemetry:network",
                    description=f"Network flow {src_ip} -> {dst_ip}:{dst_port}",
                ))

        elif event_type == "SYSTEM_LOG":
            # Host entity is recorded with source and log context
            if host_entity_id:
                facility = attrs.get("facility", "daemon")
                level = attrs.get("level", "INFO")
                entities[host_entity_id].properties.update({
                    "last_facility": facility,
                    "last_log_level": level,
                })

        elif event_type in ("EXTERNAL_ALERT", "ALERT"):
            ext_source = attrs.get("external_source") or source
            ext_host = attrs.get("hostname") or attrs.get("device_name")
            if ext_host:
                host_entity_id = f"host:{str(ext_host).lower()}"
                entities[host_entity_id] = ExtractedEntity(
                    id=host_entity_id,
                    type=EntityTypeEnum.HOST,
                    label=f"Host-{ext_host}",
                    properties={"hostname": ext_host, "source": ext_source},
                    timestamp=event_ts,
                )

            # IP Addresses (src_ip, dst_ip)
            src_ip = str(attrs.get("src_ip") or attrs.get("source_ip") or "").strip()
            dst_ip = str(attrs.get("dst_ip") or attrs.get("dest_ip") or "").strip()
            dst_port = attrs.get("dst_port") or attrs.get("dest_port")

            src_ip_id: Optional[str] = None
            if is_valid_ip(src_ip):
                src_ip_id = f"ip:{src_ip}"
                entities[src_ip_id] = ExtractedEntity(
                    id=src_ip_id,
                    type=EntityTypeEnum.IP_ADDRESS,
                    label=src_ip,
                    properties={"ip_address": src_ip},
                    timestamp=event_ts,
                )

            dst_ip_id: Optional[str] = None
            if is_valid_ip(dst_ip):
                dst_ip_id = f"ip:{dst_ip}"
                entities[dst_ip_id] = ExtractedEntity(
                    id=dst_ip_id,
                    type=EntityTypeEnum.IP_ADDRESS,
                    label=f"{dst_ip}:{dst_port}" if dst_port else dst_ip,
                    properties={"ip_address": dst_ip, "port": dst_port},
                    timestamp=event_ts,
                )

            if src_ip_id and dst_ip_id and src_ip_id != dst_ip_id:
                relationships.append(ExtractedRelationship(
                    source_id=src_ip_id,
                    target_id=dst_ip_id,
                    relation=RelationTypeEnum.CONNECTED_TO,
                    weight=1.0,
                    timestamp=event_ts,
                    properties={"dst_port": dst_port},
                    evidence_event_id=event_id,
                    confidence=0.85,
                    provenance=f"external:{ext_source}",
                    description=f"External alert network connection {src_ip} -> {dst_ip}",
                ))

            # File Hash / SHA256
            sha256 = str(attrs.get("sha256") or attrs.get("file_hash") or "").strip().lower()
            file_path = str(attrs.get("file_path") or attrs.get("filepath") or "").strip()
            if sha256 and len(sha256) == 64:
                file_id = f"file:hash:{sha256}"
                file_label = file_path.split("/")[-1] if file_path else sha256[:12]
                entities[file_id] = ExtractedEntity(
                    id=file_id,
                    type=EntityTypeEnum.FILE,
                    label=file_label,
                    properties={"sha256": sha256, "file_path": file_path},
                    timestamp=event_ts,
                )
                if host_entity_id:
                    relationships.append(ExtractedRelationship(
                        source_id=host_entity_id,
                        target_id=file_id,
                        relation=RelationTypeEnum.MODIFIED,
                        weight=1.0,
                        timestamp=event_ts,
                        properties={"sha256": sha256},
                        evidence_event_id=event_id,
                        confidence=0.85,
                        provenance=f"external:{ext_source}",
                        description=f"External alert reported file hash {sha256[:12]} on {ext_host or 'host'}",
                    ))

            # User
            user_name = str(attrs.get("user") or attrs.get("username") or "").strip()
            if user_name and user_name.lower() not in ("unknown", "none", ""):
                user_id = f"user:{user_name.lower()}"
                entities[user_id] = ExtractedEntity(
                    id=user_id,
                    type=EntityTypeEnum.USER,
                    label=user_name,
                    properties={"username": user_name},
                    timestamp=event_ts,
                )

            # Process
            proc_name = str(attrs.get("process_name") or attrs.get("file_name") or "").strip()
            if proc_name:
                proc_id = f"process:external:{proc_name.lower()}"
                entities[proc_id] = ExtractedEntity(
                    id=proc_id,
                    type=EntityTypeEnum.PROCESS,
                    label=proc_name,
                    properties={"process_name": proc_name, "cmdline": attrs.get("cmdline")},
                    timestamp=event_ts,
                )
                if host_entity_id:
                    relationships.append(ExtractedRelationship(
                        source_id=host_entity_id,
                        target_id=proc_id,
                        relation=RelationTypeEnum.SPAWNED,
                        weight=1.0,
                        timestamp=event_ts,
                        evidence_event_id=event_id,
                        confidence=0.85,
                        provenance=f"external:{ext_source}",
                        description=f"External alert reported process {proc_name}",
                    ))

        return list(entities.values()), relationships

    @classmethod
    def extract_from_finding(
        cls,
        finding_id: str,
        rule_name: str,
        severity: str,
        confidence: float,
        mitre_ids: List[str],
        target_entity_id: str,
        event_id: str = "",
        timestamp: Optional[datetime] = None,
    ) -> Tuple[List[ExtractedEntity], List[ExtractedRelationship]]:
        """Extract Alert entity and TRIGGERED relationship linking finding to target entity."""
        ts = timestamp or datetime.now(timezone.utc)
        alert_id = f"alert:{finding_id}"
        alert_entity = ExtractedEntity(
            id=alert_id,
            type=EntityTypeEnum.ALERT,
            label=f"Alert: {rule_name}",
            properties={
                "finding_id": finding_id,
                "rule_name": rule_name,
                "severity": severity,
                "mitre_attack_ids": mitre_ids,
            },
            timestamp=ts,
            first_seen=ts,
            last_seen=ts,
            observation_count=1,
        )
        relationship = ExtractedRelationship(
            source_id=alert_id,
            target_id=target_entity_id,
            relation=RelationTypeEnum.TRIGGERED,
            weight=1.5,
            timestamp=ts,
            properties={"severity": severity, "rule_name": rule_name},
            evidence_event_id=event_id,
            confidence=confidence,
            provenance="detection_rule",
            description=f"Detection rule '{rule_name}' ({severity}) triggered on {target_entity_id}",
        )
        return [alert_entity], [relationship]

    @classmethod
    def extract_from_threat_intel(
        cls,
        indicator_id: str,
        indicator_type: str,
        indicator_value: str,
        source: str,
        confidence: int,
        threat_category: Optional[str],
        threat_actor: Optional[str],
        target_entity_id: str,
        evidence_event_id: str = "",
        timestamp: Optional[datetime] = None,
    ) -> Tuple[List[ExtractedEntity], List[ExtractedRelationship]]:
        """Extract Indicator entity and ASSOCIATED_WITH relationship linking threat intel match to target entity."""
        ts = timestamp or datetime.now(timezone.utc)
        ti_entity_id = f"indicator:{indicator_type.lower()}:{indicator_value}"
        ti_entity = ExtractedEntity(
            id=ti_entity_id,
            type=EntityTypeEnum.INDICATOR,
            label=f"{indicator_type}: {indicator_value}",
            properties={
                "indicator_id": indicator_id,
                "indicator_type": indicator_type,
                "value": indicator_value,
                "source": source,
                "confidence": confidence,
                "threat_category": threat_category,
                "threat_actor": threat_actor,
            },
            timestamp=ts,
            first_seen=ts,
            last_seen=ts,
            observation_count=1,
        )
        relationship = ExtractedRelationship(
            source_id=ti_entity_id,
            target_id=target_entity_id,
            relation=RelationTypeEnum.ASSOCIATED_WITH,
            weight=2.0,
            timestamp=ts,
            properties={
                "source": source,
                "threat_category": threat_category,
                "threat_actor": threat_actor,
            },
            evidence_event_id=evidence_event_id,
            confidence=min(1.0, max(0.1, confidence / 100.0)),
            provenance=f"threat_intel:{source}",
            description=f"Verified threat indicator ({indicator_type} from {source}) associated with {target_entity_id}",
        )
        return [ti_entity], [relationship]
