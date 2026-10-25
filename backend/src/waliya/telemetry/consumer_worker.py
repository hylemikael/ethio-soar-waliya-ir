"""Reliable Redis Streams consumer worker for detection rules and behavioral analytics."""

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from redis.asyncio import Redis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import make_transient

from waliya.analytics.ewma_engine import EWMAAnalyticsEngine
from waliya.config import settings
from waliya.correlation.graph_engine import EntityGraphManager, get_graph_manager
from waliya.db.models import FindingModel, RuleModel
from waliya.db.session import async_session_factory
from waliya.detection.builtin_rules import seed_builtin_rules
from waliya.detection.rule_engine import RuleEngine
from waliya.incidents.correlation_service import IncidentCorrelationService
from waliya.observability.metrics import get_metrics_collector
from waliya.observability.worker_monitor import record_worker_heartbeat

logger = logging.getLogger("waliya.telemetry.consumer_worker")

STREAM_NAME = "stream:telemetry:raw"
CONSUMER_GROUP = "waliya_detection_group"
DLQ_STREAM = "stream:telemetry:dlq"
MAX_DELIVERIES = 5
MIN_IDLE_TIME_MS = 60000  # 1 minute idle before reclaiming abandoned messages


class TelemetryConsumerWorker:
    """Consumes telemetry from Redis Streams, evaluates detection rules and analytics,

    and durably persists findings with at-least-once processing guarantees and idempotent deduplication.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        consumer_name: Optional[str] = None,
        group_name: str = CONSUMER_GROUP,
        stream_name: str = STREAM_NAME,
        graph_manager: Optional[EntityGraphManager] = None,
        correlation_service: Optional[IncidentCorrelationService] = None,
    ):
        self.redis_url = redis_url or settings.REDIS_URL
        self.consumer_name = consumer_name or f"worker_{uuid4().hex[:8]}"
        self.group_name = group_name
        self.stream_name = stream_name
        self.graph_manager = graph_manager or get_graph_manager()
        self.correlation_service = correlation_service or IncidentCorrelationService()
        self._is_running = False
        self._redis: Optional[Redis] = None
        self.processed_total: int = 0
        self.errors_total: int = 0
        self._rules_cached_at: float = 0.0
        self._cached_rules: List[RuleModel] = []
        self._rules_cache_ttl: float = 60.0
        self._rules_seeded: bool = False

    async def get_active_rules(self, session: AsyncSession) -> List[RuleModel]:
        """Return active rules with bounded in-memory caching to eliminate redundant DB roundtrips."""
        now = time.monotonic()
        if not self._rules_seeded:
            await seed_builtin_rules(session)
            self._rules_seeded = True

        if not self._cached_rules or (now - self._rules_cached_at) > self._rules_cache_ttl:
            rules_query = select(RuleModel).where(RuleModel.is_active == True)
            rules_res = await session.execute(rules_query)
            rules = list(rules_res.scalars().all())
            for r in rules:
                # Eagerly load all attributes so they remain populated across session boundaries
                _ = (r.id, r.rule_id, r.name, r.description, r.version, r.severity, r.event_type, r.conditions, r.mitre_attack_ids, r.dedup_window_seconds, r.is_active)
                session.expunge(r)
                make_transient(r)
            self._cached_rules = rules
            self._rules_cached_at = now

        return self._cached_rules

    async def send_heartbeat(self, last_batch_size: int = 0) -> None:
        """Record worker heartbeat in Redis for operational health monitoring."""
        try:
            redis = await self.get_redis()
            await record_worker_heartbeat(
                redis=redis,
                group_name=self.group_name,
                consumer_name=self.consumer_name,
                stream_name=self.stream_name,
                processed_count=self.processed_total,
                error_count=self.errors_total,
                last_batch_size=last_batch_size,
            )
        except Exception as hb_err:
            logger.debug("Failed sending worker heartbeat: %s", hb_err)

    async def get_redis(self) -> Redis:
        """Create or return an active Redis client."""
        if self._redis is None:
            self._redis = Redis.from_url(self.redis_url, socket_timeout=5.0, decode_responses=True)
        return self._redis

    async def close(self) -> None:
        """Close active Redis connection."""
        if self._redis is not None:
            await self._redis.aclose()
            self._redis = None

    async def init_consumer_group(self, id: str = "0") -> None:
        """Ensure the target stream and consumer group exist in Redis."""
        redis = await self.get_redis()
        try:
            await redis.xgroup_create(self.stream_name, self.group_name, id=id, mkstream=True)
            logger.info("Initialized Redis consumer group '%s' on stream '%s' at id '%s'", self.group_name, self.stream_name, id)
        except Exception as exc:
            if "BUSYGROUP" in str(exc):
                logger.debug("Consumer group '%s' already exists", self.group_name)
            else:
                logger.error("Failed to initialize consumer group: %s", exc)
                raise

    async def recover_abandoned_messages(self, count: int = 50) -> int:
        """Claim abandoned messages from failed consumers using XAUTOCLAIM."""
        redis = await self.get_redis()
        try:
            claim_res = await redis.xautoclaim(
                self.stream_name,
                self.group_name,
                self.consumer_name,
                min_idle_time=MIN_IDLE_TIME_MS,
                start_id="0-0",
                count=count,
            )
            # xautoclaim returns (next_start_id, messages, [deleted_message_ids])
            messages = claim_res[1] if len(claim_res) > 1 else []
            if messages:
                logger.info("Reclaimed %d abandoned messages for consumer '%s'", len(messages), self.consumer_name)
                processed = await self._process_messages(messages)
                return processed
            return 0
        except Exception as exc:
            logger.warning("Error recovering abandoned messages: %s", exc)
            return 0

    async def process_batch(self, count: int = 10, block_ms: int = 500) -> int:
        """Read and process a batch of telemetry messages from the stream.

        Returns:
            Number of successfully processed and acknowledged messages.
        """
        redis = await self.get_redis()
        await self.init_consumer_group()

        # 1. Read new messages assigned to this consumer group
        read_res = await redis.xreadgroup(
            groupname=self.group_name,
            consumername=self.consumer_name,
            streams={self.stream_name: ">"},
            count=count,
            block=block_ms,
        )

        if not read_res:
            await self.send_heartbeat(last_batch_size=0)
            return 0

        # read_res format: [[stream_name, [(msg_id, fields), ...]]]
        stream_data = read_res[0]
        messages = stream_data[1]
        processed = await self._process_messages(messages)
        self.processed_total += processed
        get_metrics_collector().record_telemetry_processed(processed)
        await self.send_heartbeat(last_batch_size=len(messages))
        return processed

    async def _process_messages(self, messages: List[Any]) -> int:
        """Process a list of (msg_id, fields) stream entries."""
        redis = await self.get_redis()
        analytics_engine = EWMAAnalyticsEngine(redis)
        acknowledged_count = 0

        async with async_session_factory() as session:
            # Synchronize and cache active rules with TTL to prevent redundant DB roundtrips
            active_rules = await self.get_active_rules(session)

            # Query delivery counts for the entire batch in a single Redis roundtrip
            delivery_counts: Dict[str, int] = {}
            if messages:
                try:
                    first_id = messages[0][0]
                    last_id = messages[-1][0]
                    p_info = await redis.xpending_range(
                        self.stream_name,
                        self.group_name,
                        min=first_id,
                        max=last_id,
                        count=len(messages),
                    )
                    for item in (p_info or []):
                        m_id = item.get("message_id")
                        if m_id:
                            delivery_counts[str(m_id)] = int(item.get("times_delivered", 1))
                except Exception as p_err:
                    logger.debug("Batch xpending_range lookup fallback: %s", p_err)

            for msg_item in messages:
                msg_id = msg_item[0]
                fields = msg_item[1]

                # Check retry / delivery count for bounded failure handling from batch map
                delivery_count = delivery_counts.get(str(msg_id), 1)

                if delivery_count > MAX_DELIVERIES:
                    # Message has permanently failed MAX_DELIVERIES: route to Dead Letter Queue (DLQ)
                    logger.error("Message %s exceeded %d deliveries; routing to DLQ", msg_id, MAX_DELIVERIES)
                    await redis.xadd(DLQ_STREAM, {"data": json.dumps(fields), "error": "MAX_DELIVERIES_EXCEEDED", "original_id": str(msg_id)})
                    await redis.xack(self.stream_name, self.group_name, msg_id)
                    acknowledged_count += 1
                    continue

                # Parse event data from stream entry
                raw_data_str = fields.get("data")
                if not raw_data_str:
                    logger.warning("Empty data field in message %s; routing to DLQ", msg_id)
                    await redis.xadd(DLQ_STREAM, {"data": json.dumps(fields), "error": "EMPTY_PAYLOAD", "original_id": str(msg_id)})
                    await redis.xack(self.stream_name, self.group_name, msg_id)
                    acknowledged_count += 1
                    continue

                try:
                    event_data = json.loads(raw_data_str)
                except Exception as json_err:
                    logger.error("Corrupt JSON in message %s: %s; routing to DLQ", msg_id, json_err)
                    await redis.xadd(DLQ_STREAM, {"data": str(raw_data_str), "error": f"JSON_DECODE_ERROR: {json_err}", "original_id": str(msg_id)})
                    await redis.xack(self.stream_name, self.group_name, msg_id)
                    acknowledged_count += 1
                    continue

                if isinstance(event_data, dict):
                    norm = event_data.get("normalized")
                    if isinstance(norm, dict) and "attributes" in norm and "attributes" not in event_data:
                        event_data["attributes"] = norm["attributes"]

                event_id_str = event_data.get("event_id")
                if not event_id_str:
                    logger.warning("Missing event_id in message %s; routing to DLQ", msg_id)
                    await redis.xadd(DLQ_STREAM, {"data": raw_data_str, "error": "MISSING_EVENT_ID", "original_id": str(msg_id)})
                    await redis.xack(self.stream_name, self.group_name, msg_id)
                    acknowledged_count += 1
                    continue

                try:
                    event_id = UUID(event_id_str)
                except ValueError:
                    logger.warning("Invalid event_id format '%s' in message %s; routing to DLQ", event_id_str, msg_id)
                    await redis.xadd(DLQ_STREAM, {"data": raw_data_str, "error": "INVALID_EVENT_ID_UUID", "original_id": str(msg_id)})
                    await redis.xack(self.stream_name, self.group_name, msg_id)
                    acknowledged_count += 1
                    continue

                agent_id_str = event_data.get("agent_id")
                agent_id = UUID(agent_id_str) if agent_id_str else None

                # Detect simulation provenance upfront
                is_sim_event = bool(
                    event_data.get("is_simulation")
                    or event_data.get("attributes", {}).get("is_simulation")
                )
                sim_run_id = (
                    event_data.get("simulation_run_id")
                    or event_data.get("attributes", {}).get("simulation_run_id")
                )
                trace_id = (
                    event_data.get("trace_id")
                    or event_data.get("attributes", {}).get("trace_id")
                )

                try:
                    # 1. Rule Engine Evaluation
                    generated_findings: List[FindingModel] = []

                    for rule in active_rules:
                        eval_res = await RuleEngine.evaluate_rule(rule, event_data, redis_client=redis)
                        if eval_res.matched:
                            entity = (
                                event_data.get("attributes", {}).get("src_ip")
                                or event_data.get("attributes", {}).get("user")
                                or event_data.get("attributes", {}).get("username")
                                or event_data.get("attributes", {}).get("file_path")
                                or str(agent_id or "host")
                            )
                            # Simulation dedup_key includes simulation_run_id to prevent suppressing real alerts
                            dedup_key = (
                                f"sim:{sim_run_id}:{rule.rule_id}:{entity}"
                                if is_sim_event and sim_run_id
                                else f"{rule.rule_id}:{entity}"
                            )

                            # Check suppression window
                            is_supp = await RuleEngine.is_suppressed(session, dedup_key, rule.dedup_window_seconds)
                            if not is_supp:
                                explanation_data: Dict[str, Any] = {
                                    "rule_id": rule.rule_id,
                                    "rule_name": rule.name,
                                    "rule_version": rule.version,
                                    "matched_conditions": eval_res.matched_conditions,
                                    "explanation": eval_res.explanation,
                                    "mitre_attack_ids": rule.mitre_attack_ids,
                                    "observed_entity": entity,
                                }
                                if is_sim_event:
                                    explanation_data["is_simulation"] = True
                                    explanation_data["simulation_run_id"] = sim_run_id
                                    explanation_data["trace_id"] = trace_id

                                finding = FindingModel(
                                    id=uuid4(),
                                    rule_id=rule.id,
                                    event_id=event_id,
                                    agent_id=agent_id,
                                    severity=rule.severity,
                                    confidence=1.0,
                                    explanation=explanation_data,
                                    dedup_key=dedup_key,
                                    is_simulation=is_sim_event,
                                    simulation_run_id=sim_run_id,
                                )
                                generated_findings.append(finding)

                    # 2. Behavioral Analytics (EWMA) Evaluation
                    # Synthetic simulation events never corrupt production online baselines
                    if not is_sim_event:
                        analytics_res = await analytics_engine.process_event(event_data)
                        if analytics_res is not None:
                            anom_dedup_key, anomaly_expl, anom_severity = analytics_res
                            finding = FindingModel(
                                id=uuid4(),
                                rule_id=None,
                                event_id=event_id,
                                agent_id=agent_id,
                                severity=anom_severity.value,
                                confidence=min(1.0, round(0.7 + 0.05 * (anomaly_expl.z_score - anomaly_expl.threshold), 2)),
                                explanation=anomaly_expl.model_dump(),
                                dedup_key=anom_dedup_key,
                                is_simulation=False,
                                simulation_run_id=None,
                            )
                            generated_findings.append(finding)

                    # 3. Threat Intelligence Observable Matching
                    # Telemetry observables are matched offline against active local threat indicators
                    if not is_sim_event:
                        try:
                            from waliya.threat_intel.matcher import ThreatIntelMatcher
                            ti_matches = await ThreatIntelMatcher.match_event_observables(session, event_data)
                            if ti_matches:
                                # Enrich existing rule/EWMA findings on this event with threat intel context
                                for gf in generated_findings:
                                    if isinstance(gf.explanation, dict):
                                        gf.explanation["threat_intel_matches"] = ti_matches

                                # If no rule or EWMA finding was produced, generate a dedicated confirmed threat intel finding
                                for match in ti_matches:
                                    ti_dedup_key = f"ti:{match['indicator_type']}:{match['value']}:{agent_id or 'global'}"
                                    is_supp = await RuleEngine.is_suppressed(session, ti_dedup_key, 300)
                                    if not is_supp:
                                        ti_finding = FindingModel(
                                            id=uuid4(),
                                            rule_id=None,
                                            event_id=event_id,
                                            agent_id=agent_id,
                                            severity=match.get("severity", "HIGH"),
                                            confidence=min(1.0, max(0.5, float(match.get("confidence", 50)) / 100.0)),
                                            explanation={
                                                "finding_type": "THREAT_INTEL_MATCH",
                                                "rule_name": f"Known Malicious {match['indicator_type']} ({match['source']})",
                                                "indicator_id": match["indicator_id"],
                                                "indicator_type": match["indicator_type"],
                                                "observable": match["observable"],
                                                "value": match["value"],
                                                "source": match["source"],
                                                "threat_category": match.get("threat_category"),
                                                "threat_actor": match.get("threat_actor"),
                                                "confidence": match["confidence"],
                                                "explanation": match["investigative_note"],
                                                "threat_intel_matches": [match],
                                                "mitre_attack_ids": ["T1071", "T1105"] if match["indicator_type"] in ("IPV4", "DOMAIN", "URL") else ["T1027", "T1204"],
                                            },
                                            dedup_key=ti_dedup_key,
                                            is_simulation=False,
                                            simulation_run_id=None,
                                        )
                                        generated_findings.append(ti_finding)
                        except Exception as ti_err:
                            logger.error("Threat intel matching error for event %s: %s", event_id, ti_err)

                    # 4. Ingest into bounded entity correlation graph
                    try:
                        await self.graph_manager.ingest_event(event_data)
                    except Exception as graph_err:
                        logger.error("Graph ingestion error for event %s: %s", event_id, graph_err)
                        raise

                    # 4. Idempotent Database Persistence with Constraint Check
                    for finding in generated_findings:
                        # Check if duplicate (event_id, dedup_key) already exists in DB
                        dup_query = select(FindingModel.id).where(
                            FindingModel.event_id == finding.event_id,
                            FindingModel.dedup_key == finding.dedup_key,
                        )
                        dup_res = await session.execute(dup_query)
                        if dup_res.scalars().first() is None:
                            session.add(finding)

                    # 5. Correlate findings into persistent security incidents
                    if generated_findings:
                        await self.correlation_service.correlate_findings(
                            session=session,
                            findings=generated_findings,
                            event_data=event_data,
                            graph_manager=self.graph_manager,
                        )

                    # 5b. Queue outbound notifications for detection findings and threat intel matches
                    if not is_sim_event and generated_findings:
                        try:
                            from waliya.integrations.delivery_service import NotificationDeliveryService
                            from waliya.integrations.payloads import (
                                NotificationEventType,
                                build_detection_finding_created_payload,
                                build_threat_intel_matched_payload,
                            )
                            for gf in generated_findings:
                                expl = gf.explanation if isinstance(gf.explanation, dict) else {}
                                if expl.get("finding_type") == "THREAT_INTEL_MATCH":
                                    ti_matches = expl.get("threat_intel_matches", [])
                                    ti_match = ti_matches[0] if ti_matches else {}
                                    ti_notif = build_threat_intel_matched_payload(
                                        indicator_type=str(ti_match.get("indicator_type", "OBSERVABLE")),
                                        observable=str(ti_match.get("value") or ti_match.get("observable", "unknown")),
                                        source=str(ti_match.get("source", "ThreatIntel")),
                                        severity=str(gf.severity),
                                        confidence=int(gf.confidence * 100),
                                        threat_category=ti_match.get("threat_category"),
                                    )
                                    await NotificationDeliveryService.queue_notification(
                                        session=session,
                                        event_type=NotificationEventType.THREAT_INTEL_MATCHED.value,
                                        event_id=str(gf.id),
                                        payload=ti_notif,
                                    )
                                else:
                                    finding_notif = build_detection_finding_created_payload(
                                        finding_id=gf.id,
                                        rule_id=str(gf.rule_id) if gf.rule_id else None,
                                        rule_name=str(expl.get("rule_name") or expl.get("rule_id") or "Security Alert"),
                                        severity=str(gf.severity),
                                        confidence=float(gf.confidence),
                                        observed_entity=expl.get("observed_entity"),
                                    )
                                    await NotificationDeliveryService.queue_notification(
                                        session=session,
                                        event_type=NotificationEventType.DETECTION_FINDING_CREATED.value,
                                        event_id=str(gf.id),
                                        payload=finding_notif,
                                    )
                        except Exception as notif_err:
                            logger.warning("Failed queuing finding notifications for event %s: %s", event_id, notif_err)

                    # Commit transaction: findings and incidents are durably saved together
                    await session.commit()

                    # 6. Acknowledge Stream Message ONLY AFTER successful database commit
                    await redis.xack(self.stream_name, self.group_name, msg_id)
                    acknowledged_count += 1
                    logger.debug("Acknowledged stream message %s (findings=%d)", msg_id, len(generated_findings))

                except Exception as proc_err:
                    await session.rollback()
                    self.errors_total += 1
                    get_metrics_collector().record_telemetry_error(1)
                    logger.error("Processing failed for message %s (will retry): %s", msg_id, proc_err)
                    # Do NOT xack: message remains in PEL for retry or abandoned-claim recovery

        return acknowledged_count

    async def run_forever(self, poll_interval_ms: int = 500) -> None:
        """Run worker loop indefinitely until cancelled with backpressure and periodic recovery."""
        self._is_running = True
        logger.info("Starting detection consumer worker '%s'", self.consumer_name)
        last_recovery_time = 0.0
        consecutive_errors = 0

        while self._is_running:
            try:
                now_mono = time.monotonic()
                # Recover abandoned messages periodically (every 30s) rather than on every 500ms loop
                if now_mono - last_recovery_time >= 30.0:
                    await self.recover_abandoned_messages(count=20)
                    last_recovery_time = now_mono

                await self.send_heartbeat(last_batch_size=0)
                # Consume new batch
                await self.process_batch(count=20, block_ms=poll_interval_ms)
                consecutive_errors = 0
            except asyncio.CancelledError:
                break
            except Exception as loop_err:
                consecutive_errors += 1
                backoff = min(10.0, 1.0 * (1.5 ** min(consecutive_errors, 5)))
                logger.error("Worker loop error (retrying in %.1fs): %s", backoff, loop_err)
                await asyncio.sleep(backoff)

        logger.info("Detection consumer worker '%s' stopped", self.consumer_name)
