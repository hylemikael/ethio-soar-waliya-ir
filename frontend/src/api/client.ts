import {
  AttackPath,
  GraphEdge,
  GraphNode,
  IncidentAttackCoverageResponse,
  IncidentReconstructionResponse,
  LivenessResponse,
  ReadinessResponse,
  SystemDiagnosticsResponse,
  OperationalMetricsResponse,
  AuditVerificationResult,
  SessionState,
  LoginResponse,
  SystemOverviewResponse,
  IncidentSummary,
  IncidentDetail,
  IncidentEvidenceResponse,
  GraphSnapshot,
  IncidentStatus,
  IncidentStatusUpdateResponse,
  SealedEvidenceResponse,
  DetectionRule,
  RuleEvaluationResult,
  SecurityEventEnvelope,
  FindingRecord,
  BehavioralBaselinesResponse,
  Playbook,
  PlaybookRun,
  ResponseAction,
  AuditRecord,
  AgentRecord,
  SimulationRunRecord,
  SimulationCoverageResponse,
  FeedConfigurationRecord,
  FeedSyncRunRecord,
  ThreatIndicatorListResponse,
  ThreatIndicatorRecord,
  IncidentThreatIntelSummary,
  ThreatIndicatorDecayRequest,
  ThreatIndicatorDecayResponse,
  ActionRegistryEntry,
  ResponsePlanCreateRequest,
  ResponsePlanExecuteRequest,
  ResponsePlanResponse,
  NotificationDestination,
  NotificationDestinationCreate,
  NotificationDestinationUpdate,
  NotificationDelivery,
  NotificationDeliveryListResponse,
  InboundSource,
  InboundSourceCreate,
  InboundSourceUpdate,
} from '../types';

const API_BASE_URL = '/api/v1';

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
    this.name = 'ApiError';
  }
}

let cachedCsrfToken: string | null = null;

function getCsrfFromCookie(): string | null {
  if (typeof document === 'undefined') return null;
  const match = document.cookie.match(new RegExp('(^|;\\s*)waliya_csrf=([^;]*)'));
  return match ? decodeURIComponent(match[2]) : null;
}

export function setCsrfToken(token: string | null): void {
  cachedCsrfToken = token;
}

export function getActiveCsrfToken(): string | null {
  return cachedCsrfToken || getCsrfFromCookie();
}

async function request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const method = (options.method || 'GET').toUpperCase();
  const csrf = getActiveCsrfToken();

  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string>),
  };

  // Inject CSRF token on state-changing requests
  if (csrf && ['POST', 'PUT', 'PATCH', 'DELETE'].includes(method) && !headers['X-CSRF-Token']) {
    headers['X-CSRF-Token'] = csrf;
  }

  const response = await fetch(url, {
    credentials: 'include',
    ...options,
    headers,
  });

  if (!response.ok) {
    let errorDetail = `HTTP ${response.status}: ${response.statusText}`;
    try {
      const data = await response.json();
      if (data.detail) {
        errorDetail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
      }
    } catch {
      // Non-JSON error body
    }
    throw new ApiError(response.status, errorDetail);
  }

  return response.json();
}

export const apiClient = {
  // Authentication & Session
  login: async (apiKey: string): Promise<LoginResponse> => {
    const res = await request<LoginResponse>('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ api_key: apiKey }),
    });
    if (res.csrf_token) {
      setCsrfToken(res.csrf_token);
    }
    return res;
  },

  logout: async (): Promise<{ status: string }> => {
    try {
      return await request<{ status: string }>('/auth/logout', { method: 'POST' });
    } finally {
      setCsrfToken(null);
    }
  },

  getSession: async (): Promise<SessionState> => {
    const session = await request<SessionState>('/auth/session');
    if (session.csrf_token) {
      setCsrfToken(session.csrf_token);
    }
    return session;
  },

  // Operational Overview
  getOverview: (): Promise<SystemOverviewResponse> => request<SystemOverviewResponse>('/overview'),

  // Incident Investigation & Digital Forensics
  listIncidents: (params: {
    status?: string;
    severity?: string;
    limit?: number;
    offset?: number;
  } = {}): Promise<IncidentSummary[]> => {
    const query = new URLSearchParams();
    if (params.status) query.append('status', params.status);
    if (params.severity) query.append('severity', params.severity);
    if (params.limit !== undefined) query.append('limit', String(params.limit));
    if (params.offset !== undefined) query.append('offset', String(params.offset));
    const qs = query.toString();
    return request<IncidentSummary[]>(`/incidents${qs ? `?${qs}` : ''}`);
  },

  getIncident: (incidentId: string): Promise<IncidentDetail> =>
    request<IncidentDetail>(`/incidents/${incidentId}`),

  getIncidentEvidence: (incidentId: string): Promise<IncidentEvidenceResponse> =>
    request<IncidentEvidenceResponse>(`/incidents/${incidentId}/evidence`),

  getIncidentGraph: (incidentId: string): Promise<GraphSnapshot> =>
    request<GraphSnapshot>(`/incidents/${incidentId}/graph`),

  getIncidentAttackPaths: (incidentId: string): Promise<AttackPath[]> =>
    request<AttackPath[]>(`/incidents/${incidentId}/attack-paths`),

  refreshIncidentGraph: (incidentId: string): Promise<GraphSnapshot> =>
    request<GraphSnapshot>(`/incidents/${incidentId}/graph/refresh`, {
      method: 'POST',
    }),

  getIncidentMitreCoverage: (incidentId: string): Promise<IncidentAttackCoverageResponse> =>
    request<IncidentAttackCoverageResponse>(`/incidents/${incidentId}/mitre-coverage`),

  getIncidentReconstruction: (incidentId: string, maxItems = 200): Promise<IncidentReconstructionResponse> =>
    request<IncidentReconstructionResponse>(`/incidents/${incidentId}/reconstruction?max_items=${maxItems}`),

  getCorrelationAttackPaths: (maxDepth = 4, maxPaths = 10): Promise<AttackPath[]> =>
    request<AttackPath[]>(`/correlation/attack-paths?max_depth=${maxDepth}&max_paths=${maxPaths}`),

  getCorrelationPaths: (
    source: string,
    target: string,
    maxDepth = 4,
    limit = 5
  ): Promise<{ source: string; target: string; paths: AttackPath[]; total_paths_found: number }> =>
    request(`/correlation/paths?source=${encodeURIComponent(source)}&target=${encodeURIComponent(target)}&max_depth=${maxDepth}&limit=${limit}`),

  getEntityNeighbors: (
    entityId: string,
    depth = 1,
    maxNeighbors = 50
  ): Promise<{ entity: GraphNode; neighbors: GraphNode[]; edges: GraphEdge[]; degree: number }> =>
    request(`/correlation/entities/${encodeURIComponent(entityId)}/neighbors?depth=${depth}&max_neighbors=${maxNeighbors}`),

  updateIncidentStatus: (
    incidentId: string,
    status: IncidentStatus,
    note?: string
  ): Promise<IncidentStatusUpdateResponse> =>
    request<IncidentStatusUpdateResponse>(`/incidents/${incidentId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, note }),
    }),

  sealIncidentEvidence: (incidentId: string): Promise<SealedEvidenceResponse> =>
    request<SealedEvidenceResponse>(`/incidents/${incidentId}/seal-evidence`, {
      method: 'POST',
    }),

  exportIncidentDossier: (incidentId: string): Promise<Record<string, unknown>> =>
    request<Record<string, unknown>>(`/incidents/${incidentId}/export`),

  // Detection Engineering & Behavioral Analytics
  listRules: (): Promise<DetectionRule[]> => request<DetectionRule[]>('/rules'),

  saveRule: (rule: DetectionRule): Promise<{ id: string; rule_id: string; version: number; status: string }> =>
    request<{ id: string; rule_id: string; version: number; status: string }>('/rules', {
      method: 'POST',
      body: JSON.stringify(rule),
    }),

  toggleRuleStatus: (
    ruleId: string,
    isActive: boolean
  ): Promise<{ rule_id: string; is_active: boolean; previous_state: boolean; status: string }> =>
    request<{ rule_id: string; is_active: boolean; previous_state: boolean; status: string }>(
      `/rules/${ruleId}/status`,
      {
        method: 'PATCH',
        body: JSON.stringify({ is_active: isActive }),
      }
    ),

  testRule: (rule: DetectionRule, event: SecurityEventEnvelope): Promise<RuleEvaluationResult> =>
    request<RuleEvaluationResult>('/rules/test', {
      method: 'POST',
      body: JSON.stringify({ rule, event }),
    }),

  listFindings: (limit: number = 50): Promise<FindingRecord[]> =>
    request<FindingRecord[]>(`/rules/findings?limit=${limit}`),

  getBehavioralBaselines: (): Promise<BehavioralBaselinesResponse> =>
    request<BehavioralBaselinesResponse>('/rules/analytics/baselines'),

  // SOAR Operations & Playbook Orchestration
  listPlaybooks: (): Promise<Playbook[]> => request<Playbook[]>('/soar/playbooks'),

  executePlaybook: (payload: {
    playbook_id: string;
    incident_id: string;
    agent_id: string;
    dry_run: boolean;
    context_override?: Record<string, unknown>;
  }): Promise<PlaybookRun> =>
    request<PlaybookRun>('/soar/playbooks/execute', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  listResponseActions: (status?: string, limit: number = 50): Promise<ResponseAction[]> => {
    const qs = status ? `?status=${encodeURIComponent(status)}&limit=${limit}` : `?limit=${limit}`;
    return request<ResponseAction[]>(`/soar/actions${qs}`);
  },

  approveResponseAction: (
    actionId: string,
    reason: string
  ): Promise<{ action_id: string; command_id: string; status: string; message: string }> =>
    request<{ action_id: string; command_id: string; status: string; message: string }>(
      `/soar/actions/${actionId}/approve`,
      {
        method: 'POST',
        body: JSON.stringify({ reason }),
      }
    ),

  rejectResponseAction: (
    actionId: string,
    reason: string
  ): Promise<{ action_id: string; command_id: string; status: string; message: string }> =>
    request<{ action_id: string; command_id: string; status: string; message: string }>(
      `/soar/actions/${actionId}/reject`,
      {
        method: 'POST',
        body: JSON.stringify({ reason }),
      }
    ),

  listPlaybookRuns: (limit: number = 50): Promise<PlaybookRun[]> =>
    request<PlaybookRun[]>(`/soar/runs?limit=${limit}`),

  getPlaybookRun: (runId: string): Promise<PlaybookRun> =>
    request<PlaybookRun>(`/soar/runs/${runId}`),

  // Response Plans & Governance
  listActionRegistry: (): Promise<ActionRegistryEntry[]> =>
    request<ActionRegistryEntry[]>('/soar/actions/registry'),

  listResponsePlans: (
    incidentId?: string,
    status?: string,
    limit: number = 50,
    offset: number = 0
  ): Promise<ResponsePlanResponse[]> => {
    const qp = new URLSearchParams();
    if (incidentId) qp.append('incident_id', incidentId);
    if (status && status !== 'ALL') qp.append('status_filter', status);
    qp.append('limit', String(limit));
    qp.append('offset', String(offset));
    return request<ResponsePlanResponse[]>(`/soar/plans?${qp.toString()}`);
  },

  getResponsePlan: (planId: string): Promise<ResponsePlanResponse> =>
    request<ResponsePlanResponse>(`/soar/plans/${planId}`),

  createResponsePlan: (payload: ResponsePlanCreateRequest): Promise<ResponsePlanResponse> =>
    request<ResponsePlanResponse>('/soar/plans', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  submitResponsePlan: (planId: string): Promise<ResponsePlanResponse> =>
    request<ResponsePlanResponse>(`/soar/plans/${planId}/submit`, {
      method: 'POST',
    }),

  approveResponsePlan: (planId: string, reason: string): Promise<ResponsePlanResponse> =>
    request<ResponsePlanResponse>(`/soar/plans/${planId}/approve`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),

  rejectResponsePlan: (planId: string, reason: string): Promise<ResponsePlanResponse> =>
    request<ResponsePlanResponse>(`/soar/plans/${planId}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),

  cancelResponsePlan: (planId: string, reason: string): Promise<ResponsePlanResponse> =>
    request<ResponsePlanResponse>(`/soar/plans/${planId}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),

  executeResponsePlan: (
    planId: string,
    payload?: ResponsePlanExecuteRequest
  ): Promise<ResponsePlanResponse> =>
    request<ResponsePlanResponse>(`/soar/plans/${planId}/execute`, {
      method: 'POST',
      body: JSON.stringify(payload || {}),
    }),

  reconcileResponsePlan: (planId: string, reason: string): Promise<ResponsePlanResponse> =>
    request<ResponsePlanResponse>(`/soar/plans/${planId}/reconcile`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),

  // Audit Ledger Verification & Records
  listAuditRecords: (limit: number = 50, offset: number = 0): Promise<AuditRecord[]> =>
    request<AuditRecord[]>(`/soar/audit/records?limit=${limit}&offset=${offset}`),

  verifyAuditLedger: (): Promise<AuditVerificationResult> =>
    request<AuditVerificationResult>('/soar/audit/verify'),

  // Agents
  listAgents: (): Promise<AgentRecord[]> => request<AgentRecord[]>('/agents'),

  // Health & Verification
  getLiveness: (): Promise<LivenessResponse> => request<LivenessResponse>('/health/liveness'),
  getReadiness: (): Promise<ReadinessResponse> => request<ReadinessResponse>('/health/readiness'),
  getSystemDiagnostics: (): Promise<SystemDiagnosticsResponse> => request<SystemDiagnosticsResponse>('/health/diagnostics'),
  getSystemMetrics: (): Promise<OperationalMetricsResponse> => request<OperationalMetricsResponse>('/health/metrics'),

  // Purple-Team Simulations & Validation Coverage
  listSimulationRuns: (params?: {
    scenarioId?: string;
    status?: string;
    isNegative?: boolean;
    limit?: number;
    offset?: number;
  }): Promise<SimulationRunRecord[]> => {
    const qp = new URLSearchParams();
    if (params?.scenarioId && params.scenarioId !== 'ALL') qp.append('scenario_id', params.scenarioId);
    if (params?.status && params.status !== 'ALL') qp.append('status', params.status);
    if (params?.isNegative !== undefined) qp.append('is_negative', String(params.isNegative));
    if (params?.limit !== undefined) qp.append('limit', String(params.limit));
    if (params?.offset !== undefined) qp.append('offset', String(params.offset));
    const qs = qp.toString() ? `?${qp.toString()}` : '';
    return request<SimulationRunRecord[]>(`/simulations/runs${qs}`);
  },

  getSimulationRun: (runId: string): Promise<SimulationRunRecord> =>
    request<SimulationRunRecord>(`/simulations/runs/${runId}`),

  getSimulationCoverage: (): Promise<SimulationCoverageResponse> =>
    request<SimulationCoverageResponse>('/simulations/coverage'),

  // Threat Intelligence Feeds & Ingestion
  listThreatIntelFeeds: (): Promise<FeedConfigurationRecord[]> =>
    request<FeedConfigurationRecord[]>('/threat-intel/feeds'),

  getThreatIntelFeed: (feedId: string): Promise<FeedConfigurationRecord> =>
    request<FeedConfigurationRecord>(`/threat-intel/feeds/${feedId}`),

  updateThreatIntelFeed: (
    feedId: string,
    payload: { is_enabled?: boolean; refresh_interval_minutes?: number; config_options?: Record<string, unknown> }
  ): Promise<FeedConfigurationRecord> =>
    request<FeedConfigurationRecord>(`/threat-intel/feeds/${feedId}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  syncThreatIntelFeed: (
    feedId: string,
    dryRun: boolean = false,
    force: boolean = false
  ): Promise<FeedSyncRunRecord> =>
    request<FeedSyncRunRecord>(`/threat-intel/feeds/${feedId}/sync`, {
      method: 'POST',
      body: JSON.stringify({ dry_run: dryRun, force }),
    }),

  listThreatIntelSyncRuns: (
    feedId?: string,
    limit: number = 20
  ): Promise<{ items: FeedSyncRunRecord[]; total: number }> => {
    const qs = feedId ? `?feed_id=${encodeURIComponent(feedId)}&limit=${limit}` : `?limit=${limit}`;
    return request<{ items: FeedSyncRunRecord[]; total: number }>(`/threat-intel/feeds-runs${qs}`);
  },

  listThreatIndicators: (params?: {
    type?: string;
    source?: string;
    search?: string;
    limit?: number;
    offset?: number;
  }): Promise<ThreatIndicatorListResponse> => {
    const qp = new URLSearchParams();
    if (params?.type && params.type !== 'ALL') qp.append('type', params.type);
    if (params?.source && params.source !== 'ALL') qp.append('source', params.source);
    if (params?.search) qp.append('search', params.search);
    if (params?.limit !== undefined) qp.append('limit', String(params.limit));
    if (params?.offset !== undefined) qp.append('offset', String(params.offset));
    const qs = qp.toString() ? `?${qp.toString()}` : '';
    return request<ThreatIndicatorListResponse>(`/threat-intel/indicators${qs}`);
  },

  getIncidentThreatIntel: (incidentId: string): Promise<IncidentThreatIntelSummary> =>
    request<IncidentThreatIntelSummary>(`/incidents/${incidentId}/threat-intel`),

  activateThreatIndicator: (indicatorId: string): Promise<ThreatIndicatorRecord> =>
    request<ThreatIndicatorRecord>(`/threat-intel/indicators/${indicatorId}/activate`, {
      method: 'POST',
    }),

  deactivateThreatIndicator: (indicatorId: string): Promise<ThreatIndicatorRecord> =>
    request<ThreatIndicatorRecord>(`/threat-intel/indicators/${indicatorId}/deactivate`, {
      method: 'POST',
    }),

  expireThreatIndicator: (indicatorId: string): Promise<ThreatIndicatorRecord> =>
    request<ThreatIndicatorRecord>(`/threat-intel/indicators/${indicatorId}/expire`, {
      method: 'POST',
    }),

  extendThreatIndicatorExpiry: (
    indicatorId: string,
    days?: number,
    newExpiresAt?: string
  ): Promise<ThreatIndicatorRecord> =>
    request<ThreatIndicatorRecord>(`/threat-intel/indicators/${indicatorId}/extend-expiry`, {
      method: 'POST',
      body: JSON.stringify({
        extension_days: days,
        new_expires_at: newExpiresAt,
      }),
    }),

  decayThreatIndicators: (params?: ThreatIndicatorDecayRequest): Promise<ThreatIndicatorDecayResponse> =>
    request<ThreatIndicatorDecayResponse>('/threat-intel/indicators/decay', {
      method: 'POST',
      body: JSON.stringify(params || {}),
    }),

  // Outbound Integrations & Notifications
  listNotificationDestinations: (): Promise<NotificationDestination[]> =>
    request<NotificationDestination[]>('/integrations/destinations'),

  createNotificationDestination: (
    payload: NotificationDestinationCreate
  ): Promise<NotificationDestination> =>
    request<NotificationDestination>('/integrations/destinations', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getNotificationDestination: (id: string): Promise<NotificationDestination> =>
    request<NotificationDestination>(`/integrations/destinations/${id}`),

  updateNotificationDestination: (
    id: string,
    payload: NotificationDestinationUpdate
  ): Promise<NotificationDestination> =>
    request<NotificationDestination>(`/integrations/destinations/${id}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  deleteNotificationDestination: (id: string): Promise<{ status: string; destination_id: string }> =>
    request<{ status: string; destination_id: string }>(`/integrations/destinations/${id}`, {
      method: 'DELETE',
    }),

  testNotificationDestination: (id: string): Promise<NotificationDelivery> =>
    request<NotificationDelivery>(`/integrations/destinations/${id}/test`, {
      method: 'POST',
    }),

  listNotificationDeliveries: (params?: {
    destination_id?: string;
    status?: string;
    event_type?: string;
    limit?: number;
    offset?: number;
  }): Promise<NotificationDeliveryListResponse> => {
    const qp = new URLSearchParams();
    if (params?.destination_id) qp.append('destination_id', params.destination_id);
    if (params?.status && params.status !== 'ALL') qp.append('status', params.status);
    if (params?.event_type && params.event_type !== 'ALL') qp.append('event_type', params.event_type);
    if (params?.limit !== undefined) qp.append('limit', String(params.limit));
    if (params?.offset !== undefined) qp.append('offset', String(params.offset));
    const qs = qp.toString() ? `?${qp.toString()}` : '';
    return request<NotificationDeliveryListResponse>(`/integrations/deliveries${qs}`);
  },

  retryNotificationDelivery: (id: string): Promise<NotificationDelivery> =>
    request<NotificationDelivery>(`/integrations/deliveries/${id}/retry`, {
      method: 'POST',
    }),

  dispatchPendingDeliveries: (batchSize?: number): Promise<{ status: string; delivered_count: number }> =>
    request<{ status: string; delivered_count: number }>(`/integrations/deliveries/dispatch?batch_size=${batchSize || 50}`, {
      method: 'POST',
    }),

  // Inbound External Security Event Sources
  listInboundSources: (): Promise<InboundSource[]> =>
    request<InboundSource[]>('/integrations/sources'),

  createInboundSource: (payload: InboundSourceCreate): Promise<InboundSource> =>
    request<InboundSource>('/integrations/sources', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  getInboundSource: (idOrSlug: string): Promise<InboundSource> =>
    request<InboundSource>(`/integrations/sources/${idOrSlug}`),

  updateInboundSource: (
    idOrSlug: string,
    payload: InboundSourceUpdate
  ): Promise<InboundSource> =>
    request<InboundSource>(`/integrations/sources/${idOrSlug}`, {
      method: 'PATCH',
      body: JSON.stringify(payload),
    }),

  deleteInboundSource: (idOrSlug: string): Promise<{ status: string; source_id: string }> =>
    request<{ status: string; source_id: string }>(`/integrations/sources/${idOrSlug}`, {
      method: 'DELETE',
    }),
};
