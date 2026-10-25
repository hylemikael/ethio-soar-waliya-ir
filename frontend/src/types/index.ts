/**
 * API Contract types for Waliya-IR.
 * Aligned with backend/src/waliya/contracts.py
 */

export type Severity = 'INFORMATIONAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type EventType =
  | 'FILE_INTEGRITY'
  | 'PROCESS_EXECUTION'
  | 'AUTHENTICATION'
  | 'NETWORK_CONNECTION'
  | 'SYSTEM_LOG';

export type AgentStatus = 'ONLINE' | 'DEGRADED' | 'OFFLINE' | 'REVOKED';

export type IncidentStatus = 'OPEN' | 'INVESTIGATING' | 'CONTAINED' | 'RESOLVED' | 'CLOSED';

export type ResponseState =
  | 'REQUESTED'
  | 'PENDING_APPROVAL'
  | 'QUEUED'
  | 'RECEIVED'
  | 'EXECUTED'
  | 'VERIFYING'
  | 'VERIFIED_CONTAINED'
  | 'VERIFICATION_INCONCLUSIVE'
  | 'FAILED'
  | 'TIMED_OUT'
  | 'OUTCOME_UNCERTAIN'
  | 'EXPIRED'
  | 'REJECTED';

export interface LivenessResponse {
  status: 'UP';
  timestamp: string;
  version: string;
}

export interface ReadinessResponse {
  status: 'READY' | 'NOT_READY';
  timestamp: string;
  checks: {
    database: 'CONNECTED' | 'DISCONNECTED' | 'DEGRADED';
    redis: 'CONNECTED' | 'DISCONNECTED' | 'DEGRADED';
  };
}

export type DependencyHealthStatus = 'HEALTHY' | 'DEGRADED' | 'UNHEALTHY' | 'UNKNOWN' | 'UNAVAILABLE';

export interface DependencyHealthItem {
  name: string;
  status: DependencyHealthStatus;
  latency_ms?: number | null;
  message?: string | null;
  details?: Record<string, unknown> | null;
}

export interface WorkerHealthItem {
  worker_id: string;
  group_name: string;
  status: DependencyHealthStatus;
  last_heartbeat?: string | null;
  heartbeat_age_seconds?: number | null;
  processed_count: number;
  error_count: number;
  stream_lag?: number | null;
  pending_pel_count?: number | null;
}

export interface OperationalBacklogsSummary {
  telemetry_stream_length: number;
  telemetry_stream_lag: number;
  telemetry_pel_size: number;
  outbound_notifications_pending: number;
  outbound_notifications_retrying: number;
  outbound_notifications_dead_letter: number;
  inbound_events_dedup_cached: number;
}

export interface StalledOperationsSummary {
  stalled_executing_plans_count: number;
  uncertain_actions_count: number;
  stalled_outbox_notifications_count: number;
  stale_threat_intel_feeds_count: number;
  details?: Array<Record<string, unknown>> | null;
}

export interface SystemDiagnosticsResponse {
  status: DependencyHealthStatus;
  timestamp: string;
  uptime_seconds: number;
  dependencies: Record<string, DependencyHealthItem>;
  telemetry_workers: WorkerHealthItem[];
  backlogs: OperationalBacklogsSummary;
  stalled_operations: StalledOperationsSummary;
}

export interface OperationalMetricsResponse {
  timestamp: string;
  http_requests_total: Record<string, number>;
  avg_request_duration_ms: number;
  telemetry_processed_total: number;
  telemetry_errors_total: number;
  inbound_events_total: Record<string, number>;
  outbound_deliveries_total: Record<string, number>;
}

export interface SecurityEventEnvelope {
  event_id: string;
  event_type: EventType;
  severity: Severity;
  timestamp: string;
  source: string;
  agent_id?: string;
  payload: Record<string, unknown>;
}

export interface IncidentSummary {
  incident_id: string;
  incident_number: number;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  composite_risk_score: number;
  findings_count: number;
  first_seen?: string | null;
  last_seen?: string | null;
  created_at: string;
  updated_at: string;
  is_simulation?: boolean;
  simulation_run_id?: string | null;
}

export interface RiskExplanation {
  final_score: number;
  base_severity: string;
  base_weight: number;
  confidence_factor: number;
  distinct_entity_types: string[];
  multi_entity_multiplier: number;
  mitre_attack_count: number;
  multi_stage_bonus: number;
  anomaly_bonus: number;
  asset_criticality?: string;
  asset_importance_bonus: number;
  threat_intel_confidence?: number;
  threat_intel_bonus: number;
  threat_intel_matches?: Array<Record<string, unknown>>;
  unique_findings_count: number;
  raw_findings_count: number;
  decision_reason: string;
}

export type EntityType = 'Host' | 'User' | 'IPAddress' | 'Process' | 'File' | 'Alert' | 'Indicator' | string;

export type RelationType =
  | 'AUTHENTICATED_TO'
  | 'SPAWNED'
  | 'MODIFIED'
  | 'CONNECTED_TO'
  | 'ACCESSED'
  | 'TRIGGERED'
  | 'ASSOCIATED_WITH'
  | string;

export interface GraphNode {
  id: string;
  type: EntityType;
  label: string;
  properties: Record<string, unknown>;
  first_seen?: string | null;
  last_seen?: string | null;
  observation_count?: number;
  evidence_count?: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: RelationType;
  weight: number;
  confidence?: number;
  provenance?: string;
  timestamp: string;
  evidence_event_ids?: string[];
  description?: string;
  properties?: Record<string, unknown>;
}

export type MitreMappingState = 'MAPPED' | 'UNMAPPED' | 'INSUFFICIENT_EVIDENCE';

export interface MitreTechniqueMapping {
  technique_id: string;
  technique_name: string;
  tactics: string[];
  mapping_state: MitreMappingState;
  confidence: number;
  finding_ids: string[];
  evidence_event_ids: string[];
  rationale: string;
  reference_url?: string | null;
}

export interface UnmappedFindingSummary {
  finding_id: string;
  rule_id: string;
  finding_title: string;
  reason: string;
  evidence_event_ids: string[];
}

export interface IncidentAttackCoverageResponse {
  incident_id: string;
  catalog_version: string;
  distinct_techniques_count: number;
  mapped_findings_count: number;
  unmapped_findings_count: number;
  insufficient_evidence_count: number;
  tactics: Record<string, MitreTechniqueMapping[]>;
  techniques: MitreTechniqueMapping[];
  unmapped_findings: UnmappedFindingSummary[];
  limitations: string[];
}

export interface AttackPathStep {
  step_order: number;
  source: string;
  target: string;
  relation: RelationType;
  confidence: number;
  timestamp?: string | null;
  evidence_event_ids?: string[];
  description?: string;
  mitre_techniques?: MitreTechniqueMapping[];
}

export interface AttackPath {
  path_id: string;
  entry_node: string;
  target_node: string;
  hop_count: number;
  risk_severity: Severity;
  confidence: number;
  steps: AttackPathStep[];
  summary: string;
}

export interface GraphSnapshot {
  incident_id: string | null;
  nodes: GraphNode[];
  edges: GraphEdge[];
  attack_paths?: AttackPath[];
  generated_at: string;
  stats?: Record<string, unknown>;
}

export interface EvidenceItem {
  evidence_id: string;
  evidence_type: string;
  sha256_hash: string;
  description: string;
  collected_at: string | null;
}

export interface EvidenceManifest {
  incident_id: string;
  manifest_hash: string | null;
  stored_hash: string | null;
  is_verified: boolean;
  status: 'VERIFIED' | 'UNSEALED' | 'TAMPER_DETECTED' | string;
  total_items: number;
  items: EvidenceItem[];
}

export interface TimelineItem {
  finding_id: string;
  event_id: string | null;
  event_type: string;
  source: string;
  timestamp: string | null;
  rule_id: string | null;
  rule_name: string | null;
  mitre_attack_ids: string[];
  severity: Severity;
  confidence: number;
  explanation: Record<string, unknown>;
  dedup_key: string | null;
  sha256_hash: string;
  normalized_payload: Record<string, unknown>;
}

export interface IncidentEvidenceResponse {
  incident_id: string;
  incident_number: number;
  affected_entities: string[];
  mitre_attack_ids: string[];
  first_seen: string | null;
  last_seen: string | null;
  update_history: Array<Record<string, unknown>>;
  timeline: TimelineItem[];
  evidence_manifest: EvidenceManifest;
}

export interface IncidentDetail extends IncidentSummary {
  description: string;
  assigned_to: string | null;
  affected_entities: string[];
  mitre_attack_ids: string[];
  risk_explanation: RiskExplanation;
  update_history: Array<Record<string, unknown>>;
  graph_snapshot: GraphSnapshot | null;
  evidence_manifest?: EvidenceManifest;
}

export interface IncidentStatusUpdateResponse {
  incident_id: string;
  previous_status: IncidentStatus;
  current_status: IncidentStatus;
  updated_at: string;
}

export interface SealedEvidenceResponse {
  incident_id: string;
  manifest_hash: string;
  sealed_at: string;
  status: string;
  items_sealed: number;
}

export interface RuleCondition {
  field: string;
  operator: '==' | '!=' | 'in' | 'not_in' | 'contains' | 'startswith' | 'endswith' | '>' | '<' | '>=' | '<=' | 'regex' | string;
  value: unknown;
}

export interface DetectionRule {
  id?: string;
  rule_id: string;
  version: number;
  name: string;
  description: string;
  severity: Severity;
  event_type: EventType;
  conditions: RuleCondition[];
  mitre_attack_ids: string[];
  dedup_window_seconds: number;
  is_active: boolean;
  created_at?: string | null;
  updated_at?: string | null;
}

export interface RuleEvaluationResult {
  rule_id: string;
  matched: boolean;
  execution_time_ms: number;
  matched_conditions: number;
  total_conditions: number;
  details: Record<string, unknown>;
}

export interface FindingRecord {
  id: string;
  rule_id: string | null;
  event_id: string;
  agent_id: string | null;
  severity: Severity;
  confidence: number;
  explanation: Record<string, unknown>;
  dedup_key: string | null;
  timestamp: string | null;
}

export interface EWMABaseline {
  key: string;
  metric_name: string;
  entity_id: string;
  mean: number;
  variance: number;
  std_dev: number;
  sample_count: number;
  last_updated: string | null;
}

export interface BehavioralAnomaly {
  finding_id: string;
  timestamp: string | null;
  severity: Severity;
  confidence: number;
  metric_name: string;
  observed_value: number;
  baseline_mean: number;
  baseline_std_dev: number;
  z_score: number;
  observed_entity?: string;
  decision_reason?: string;
}

export interface BehavioralBaselinesResponse {
  total_active_baselines: number;
  baselines: EWMABaseline[];
  recent_anomalies_count: number;
  anomalies: BehavioralAnomaly[];
  ewma_configuration: Record<string, unknown>;
}

export interface Playbook {
  playbook_id: string;
  name: string;
  description: string;
  trigger_conditions: Array<Record<string, unknown>>;
  action_steps: Array<Record<string, unknown>>;
  requires_approval: boolean;
  is_active: boolean;
}

export interface PlaybookRun {
  run_id: string;
  playbook_id: string;
  playbook_name?: string;
  incident_id: string;
  status: string;
  dry_run: boolean;
  executed_by: string;
  start_time: string | null;
  end_time: string | null;
  output_summary: Record<string, unknown>;
  actions?: ResponseAction[];
}

export interface ResponseAction {
  id: string;
  command_id: string;
  action: string;
  status: ResponseState;
  parameters: Record<string, unknown>;
  sequence: number;
  agent_id: string;
  agent?: { hostname: string; primary_ip: string; status: string };
  incident_id: string;
  incident?: { incident_number: number; title: string; severity: string };
  playbook_run_id: string | null;
  approved_by: string | null;
  approved_at: string | null;
  approval_reason: string | null;
  execution_receipt?: Record<string, unknown> | null;
  verification_receipt?: Record<string, unknown> | null;
  issued_at: string | null;
  expires_at: string | null;
}

export interface AuditRecord {
  sequence_number: number;
  record_id: string;
  timestamp: string;
  actor_id: string;
  actor_role: string;
  action: string;
  target_entity: string;
  canonical_payload?: Record<string, unknown>;
  previous_hash: string;
  current_hash: string;
}

export interface AuditVerificationResult {
  verified: boolean;
  total_records: number;
  genesis_hash: string;
  latest_hash: string | null;
  tamper_detected: boolean;
  broken_sequence: number | null;
}

export interface SessionState {
  authenticated: boolean;
  actor: string | null;
  csrf_token: string | null;
}

export interface LoginResponse {
  status: string;
  authenticated: boolean;
  actor: string;
  csrf_token: string;
  expires_in: number;
}

export interface AgentRecord {
  id: string;
  hostname: string;
  primary_ip: string;
  status: 'ONLINE' | 'OFFLINE' | 'DEGRADED' | string;
  os_family?: string;
  os_version?: string;
  agent_version?: string;
  mac_address?: string;
  last_heartbeat: string | null;
  created_at: string | null;
}

export interface AgentHealthSummary {
  total: number;
  online: number;
  degraded: number;
  offline: number;
  percentage_healthy: number;
}

export interface EventDistributionSummary {
  total_24h: number;
  by_type: Record<string, number>;
}

export interface FindingsSeveritySummary {
  total: number;
  by_severity: Record<string, number>;
}

export interface IncidentActivityItem {
  incident_id: string;
  incident_number: number;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  composite_risk_score: number;
  findings_count: number;
  last_seen: string | null;
  is_simulation?: boolean;
}

export interface IncidentsOverviewSummary {
  total: number;
  open_count: number;
  investigating_count: number;
  contained_count: number;
  resolved_count: number;
  closed_count: number;
  by_severity: Record<string, number>;
  recent_activity: IncidentActivityItem[];
}

export interface PipelineHealthSummary {
  stream_name: string;
  stream_length: number | null;
  stream_status: string;
  outbox_pending: number;
  outbox_failed: number;
  outbox_published: number;
}

export interface RulesOverviewSummary {
  total_rules: number;
  active_rules: number;
}

export interface RecentActionItem {
  command_id: string;
  action: string;
  status: ResponseState;
  issued_at: string;
  agent_id: string;
}

export interface ResponseOutcomesSummary {
  total_actions: number;
  by_status: Record<string, number>;
  recent_actions: RecentActionItem[];
}

export interface SystemOverviewResponse {
  generated_at: string;
  security_posture: 'NORMAL' | 'ELEVATED' | 'CRITICAL';
  posture_reason: string;
  agents: AgentHealthSummary;
  events_24h: EventDistributionSummary;
  findings: FindingsSeveritySummary;
  incidents: IncidentsOverviewSummary;
  pipeline: PipelineHealthSummary;
  rules: RulesOverviewSummary;
  responses: ResponseOutcomesSummary;
}

// ==============================================================================
// 10. SIMULATION & PURPLE-TEAM COVERAGE
// ==============================================================================

export interface SimulationRunRecord {
  run_id: string;
  trace_id: string;
  scenario_id: string;
  scenario_name: string;
  mitre_attack_ids: string[];
  target_rule_id: string;
  is_negative_test: boolean;
  status: 'PASSED' | 'FAILED' | 'INCONCLUSIVE' | 'RUNNING' | 'CANCELLED' | string;
  start_time: string;
  end_time: string | null;
  duration_seconds: number | null;
  events_submitted_count: number;
  events_accepted_count: number;
  expected_detection: boolean;
  observed_detection: boolean;
  matching_finding_ids: string[];
  matching_incident_ids: string[];
  latency_seconds: number | null;
  latency_notes: string | null;
  summary: string | null;
  error_detail: string | null;
  is_simulation: boolean;
  created_at: string;
  updated_at: string;
}

export interface SimulationScenarioCoverageItem {
  scenario_id: string;
  scenario_name: string;
  mitre_attack_id: string;
  target_rule_id: string;
  positive_status: 'VALIDATED' | 'FAILED' | 'INCONCLUSIVE' | 'NOT_TESTED';
  negative_status: 'VALIDATED' | 'FAILED' | 'INCONCLUSIVE' | 'NOT_TESTED';
  last_tested_at: string | null;
  last_run_id: string | null;
  last_status: string | null;
}

export interface SimulationCoverageResponse {
  total_runs: number;
  passed_runs: number;
  failed_runs: number;
  inconclusive_runs: number;
  distinct_scenarios_tested: number;
  validated_rules_count: number;
  total_rules_count: number;
  most_recent_run_id: string | null;
  most_recent_run_at: string | null;
  scenarios: SimulationScenarioCoverageItem[];
}

export interface FeedConfigurationRecord {
  id: string;
  feed_id: string;
  provider: string;
  name: string;
  description?: string | null;
  is_enabled: boolean;
  refresh_interval_minutes: number;
  last_sync_at?: string | null;
  last_successful_sync_at?: string | null;
  last_status: 'SUCCESS' | 'PARTIAL' | 'FAILED' | 'NEVER_RUN' | string;
  last_error_summary?: string | null;
  config_options: Record<string, unknown>;
  indicators_count?: number;
  created_at: string;
  updated_at: string;
}

export interface FeedSyncRunRecord {
  id: string;
  feed_id: string;
  started_at: string;
  finished_at?: string | null;
  status: 'SUCCESS' | 'PARTIAL' | 'FAILED' | 'RUNNING' | string;
  is_dry_run: boolean;
  fetched_count: number;
  normalized_count: number;
  inserted_count: number;
  updated_count: number;
  skipped_count: number;
  rejected_count: number;
  deactivated_count: number;
  error_summary?: string | null;
  diagnostics: Record<string, unknown>;
  triggered_by: string;
}

export interface ThreatIndicatorRecord {
  id: string;
  indicator_type: string;
  value: string;
  source: string;
  source_id?: string | null;
  confidence: number;
  severity: Severity;
  threat_category?: string | null;
  threat_actor?: string | null;
  tags: string[];
  description?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  expires_at?: string | null;
  last_decayed_at?: string | null;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export interface ThreatIndicatorListResponse {
  items: ThreatIndicatorRecord[];
  total: number;
  limit: number;
  offset: number;
}

export interface IncidentThreatIntelMatch {
  indicator_id: string;
  indicator_type: string;
  value: string;
  observable: string;
  source: string;
  source_id?: string | null;
  confidence_at_match: number;
  current_confidence: number;
  severity: Severity;
  threat_category?: string | null;
  threat_actor?: string | null;
  tags: string[];
  description?: string | null;
  first_seen?: string | null;
  last_seen?: string | null;
  expires_at?: string | null;
  last_decayed_at?: string | null;
  is_active: boolean;
  is_expired: boolean;
  matched_at: string;
  investigative_note: string;
  provenance_label: string;
  match_classification: 'CONFIRMED_MATCH' | 'HEURISTIC_OBSERVABLE';
}

export interface IncidentThreatIntelSummary {
  incident_id: string;
  incident_number: number;
  has_threat_intel: boolean;
  total_matched_indicators: number;
  max_confidence: number;
  threat_intel_bonus: number;
  confirmed_matches_count: number;
  heuristic_findings_count: number;
  matches: IncidentThreatIntelMatch[];
  decision_reason: string;
}

export interface ThreatIndicatorDecayRequest {
  stale_days?: number;
  decay_points?: number;
  decay_interval_days?: number;
  min_confidence?: number;
  dry_run?: boolean;
  indicator_type?: string;
  source?: string;
}

export interface ThreatIndicatorDecayResponse {
  total_evaluated: number;
  decayed_count: number;
  unaffected_count: number;
  is_dry_run: boolean;
  stale_days_threshold: number;
  decay_points_per_interval: number;
  decay_interval_days: number;
  min_confidence: number;
  decayed_indicators: Array<{
    indicator_id: string;
    value: string;
    indicator_type: string;
    source: string;
    previous_confidence: number;
    new_confidence: number;
    intervals_decayed: number;
    last_decayed_at: string;
  }>;
}

// ==============================================================================
// 12. INCIDENT RECONSTRUCTION & INTEGRITY
// ==============================================================================

export type ReconstructionItemType = 'EVENT' | 'FINDING' | 'THREAT_INTEL';

export interface ReconstructionObservationItem {
  item_id: string;
  item_type: ReconstructionItemType;
  timestamp?: string | null;
  title: string;
  severity: Severity;
  source: string;
  is_interpretation: boolean;
  associated_entity_ids: string[];
  associated_graph_edges: string[];
  mitre_techniques: MitreTechniqueMapping[];
  evidence_event_ids: string[];
  finding_ids: string[];
  explanation: string;
  raw_attributes: Record<string, unknown>;
  data_gaps: string[];
}

export interface ReconstructionAttackProgression {
  path_id: string;
  entry_node: string;
  target_node: string;
  hop_count: number;
  risk_severity: Severity;
  confidence: number;
  disclaimer: string;
  steps: AttackPathStep[];
}

export interface ReconstructionCoverageSummary {
  total_observations: number;
  chronological_events_count: number;
  correlated_findings_count: number;
  threat_intel_matches_count: number;
  mapped_techniques_count: number;
  unmapped_findings_count: number;
  insufficient_evidence_count: number;
  graph_entities_count: number;
  graph_edges_count: number;
  candidate_attack_paths_count: number;
}

export interface ReconstructionIncompleteEvidence {
  findings_without_events: string[];
  events_without_mitre: number;
  unconnected_entities: string[];
  uncertainties: string[];
}

export interface CrossLayerConsistencyReport {
  is_consistent: boolean;
  checks_run: number;
  inconsistencies: string[];
  warnings: string[];
}

export interface IncidentReconstructionResponse {
  incident_id: string;
  incident_number: number;
  incident_title: string;
  severity: Severity;
  status: IncidentStatus;
  first_observed_at?: string | null;
  last_observed_at?: string | null;
  timeline: ReconstructionObservationItem[];
  candidate_progressions: ReconstructionAttackProgression[];
  coverage_summary: ReconstructionCoverageSummary;
  incomplete_evidence: ReconstructionIncompleteEvidence;
  consistency_report: CrossLayerConsistencyReport;
  limitations: string[];
}

export type ResponsePlanStatus =
  | 'DRAFT'
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'EXECUTING'
  | 'SUCCEEDED'
  | 'FAILED'
  | 'REJECTED'
  | 'CANCELLED';

export type ActionRiskClassification =
  | 'READ_ONLY'
  | 'REVERSIBLE'
  | 'CONTAINMENT'
  | 'DESTRUCTIVE';

export interface ActionRegistryEntry {
  action_type: string;
  risk_classification: ActionRiskClassification;
  default_requires_approval: boolean;
  default_timeout_seconds: number;
  max_retries: number;
  is_reversible: boolean;
  description: string;
  parameter_fields: string[];
}

export interface ResponsePlanActionItem {
  action: string;
  parameters: Record<string, unknown>;
  agent_id: string;
  requires_approval?: boolean;
  risk_level?: ActionRiskClassification;
  description?: string;
}

export interface ResponsePlanCreateRequest {
  incident_id: string;
  title: string;
  description?: string;
  actions: ResponsePlanActionItem[];
  dry_run?: boolean;
  submit_for_approval?: boolean;
}

export interface ResponsePlanApprovalRequest {
  reason: string;
}

export interface ResponsePlanCancelRequest {
  reason: string;
}

export interface ResponsePlanExecuteRequest {
  dry_run?: boolean;
  idempotency_key?: string;
}

export interface ResponsePlanReconcileRequest {
  reason: string;
}

export interface ResponsePlanResponse {
  id: string;
  plan_number: number;
  title: string;
  description?: string | null;
  incident_id: string;
  status: ResponsePlanStatus;
  risk_level: ActionRiskClassification;
  requires_approval: boolean;
  actions: Array<{
    action: string;
    parameters: Record<string, unknown>;
    agent_id: string;
    requires_approval: boolean;
    risk_level: ActionRiskClassification;
    description: string;
  }>;
  approval_hash?: string | null;
  dry_run: boolean;
  is_simulation: boolean;
  simulation_run_id?: string | null;
  created_by: string;
  approved_by?: string | null;
  approved_at?: string | null;
  approval_reason?: string | null;
  rejected_by?: string | null;
  rejection_reason?: string | null;
  cancelled_by?: string | null;
  cancellation_reason?: string | null;
  idempotency_key?: string | null;
  execution_summary?: Record<string, unknown> | null;
  action_commands: Array<{
    id: string;
    command_id: string;
    action: string;
    status: string;
    agent_id: string;
    sequence: number;
    issued_at?: string | null;
    execution_receipt?: Record<string, unknown> | null;
  }>;
  created_at: string;
  updated_at: string;
}

export interface NotificationDestination {
  id: string;
  name: string;
  destination_url: string;
  is_enabled: boolean;
  subscribed_events: string[];
  has_signing_secret: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  last_delivery_at?: string | null;
  last_delivery_status?: string | null;
  last_delivery_error?: string | null;
}

export interface NotificationDestinationCreate {
  name: string;
  destination_url: string;
  is_enabled?: boolean;
  subscribed_events: string[];
  signing_secret?: string;
}

export interface NotificationDestinationUpdate {
  name?: string;
  destination_url?: string;
  is_enabled?: boolean;
  subscribed_events?: string[];
  signing_secret?: string;
}

export interface NotificationDelivery {
  id: string;
  destination_id: string;
  destination_name?: string | null;
  delivery_id: string;
  event_type: string;
  event_id: string;
  status: 'PENDING' | 'DELIVERING' | 'DELIVERED' | 'RETRY_SCHEDULED' | 'FAILED' | 'PERMANENTLY_FAILED';
  attempt_count: number;
  max_attempts: number;
  next_attempt_at?: string | null;
  payload: Record<string, unknown>;
  response_status_code?: number | null;
  response_time_ms?: number | null;
  error_message?: string | null;
  created_at: string;
  updated_at: string;
  delivered_at?: string | null;
}

export interface NotificationDeliveryListResponse {
  total: number;
  deliveries: NotificationDelivery[];
}

export interface InboundSource {
  id: string;
  source_id: string;
  name: string;
  provider_type: 'GENERIC' | 'EDR' | 'SIEM';
  is_enabled: boolean;
  auth_type: string;
  has_shared_secret: boolean;
  permitted_event_types: string[];
  total_events_received: number;
  total_events_accepted: number;
  total_events_rejected: number;
  total_events_deduplicated: number;
  last_received_at?: string | null;
  last_error_message?: string | null;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export interface InboundSourceCreate {
  source_id: string;
  name: string;
  provider_type?: string;
  is_enabled?: boolean;
  auth_type?: string;
  shared_secret: string;
  permitted_event_types?: string[];
}

export interface InboundSourceUpdate {
  name?: string;
  provider_type?: string;
  is_enabled?: boolean;
  auth_type?: string;
  shared_secret?: string;
  permitted_event_types?: string[];
}
