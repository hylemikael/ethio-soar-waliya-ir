import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Terminal,
  ShieldCheck,
  CheckCircle2,
  AlertCircle,
  RefreshCw,
  XCircle,
  Play,
  Eye,
  FileText,
  Lock,
  ChevronRight,
  AlertTriangle,
  Server,
  Copy,
  Clock,
  Check,
  Layers,
  Send,
  Plus,
  Trash2,
  Sliders,
  Webhook,
  Globe,
  Key,
} from 'lucide-react';
import { EmptyState } from '../components/EmptyState';
import { apiClient } from '../api/client';
import {
  Playbook,
  PlaybookRun,
  ResponseAction,
  AuditRecord,
  AuditVerificationResult,
  AgentRecord,
  IncidentSummary,
  ResponsePlanResponse,
  ActionRegistryEntry,
  ResponsePlanActionItem,
  NotificationDestination,
  NotificationDelivery,
  InboundSource,
} from '../types';

type ActiveTab = 'actions' | 'plans' | 'playbooks' | 'ledger' | 'integrations';

export const SoarAuditLedger: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('actions');

  // Data states
  const [actions, setActions] = useState<ResponseAction[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [playbookRuns, setPlaybookRuns] = useState<PlaybookRun[]>([]);
  const [auditRecords, setAuditRecords] = useState<AuditRecord[]>([]);
  const [agents, setAgents] = useState<AgentRecord[]>([]);
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);

  // Loading & error states
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Ledger verification state
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<AuditVerificationResult | null>(null);

  // Modals & inspectors
  const [approvingAction, setApprovingAction] = useState<ResponseAction | null>(null);
  const [rejectingAction, setRejectingAction] = useState<ResponseAction | null>(null);
  const [approvalReason, setApprovalReason] = useState('');
  const [submittingDecision, setSubmittingDecision] = useState(false);
  const [decisionError, setDecisionError] = useState<string | null>(null);

  // Trigger playbook dialog
  const [isTriggerModalOpen, setIsTriggerModalOpen] = useState(false);
  const [selectedPlaybookId, setSelectedPlaybookId] = useState('');
  const [selectedIncidentId, setSelectedIncidentId] = useState('');
  const [selectedAgentId, setSelectedAgentId] = useState('');
  const [dryRunMode, setDryRunMode] = useState(true);
  const [triggerSubmitting, setTriggerSubmitting] = useState(false);
  const [triggerError, setTriggerError] = useState<string | null>(null);

  // Response Plans & Governance states
  const [plans, setPlans] = useState<ResponsePlanResponse[]>([]);
  const [actionRegistry, setActionRegistry] = useState<ActionRegistryEntry[]>([]);
  const [planStatusFilter, setPlanStatusFilter] = useState<string>('ALL');
  const [selectedPlanDetails, setSelectedPlanDetails] = useState<ResponsePlanResponse | null>(null);
  const [isPlanModalOpen, setIsPlanModalOpen] = useState(false);
  const [isRegistryModalOpen, setIsRegistryModalOpen] = useState(false);
  const [planDecisionModal, setPlanDecisionModal] = useState<{
    plan: ResponsePlanResponse;
    action: 'approve' | 'reject' | 'cancel' | 'execute' | 'reconcile';
  } | null>(null);
  const [planDecisionReason, setPlanDecisionReason] = useState('');
  const [planDecisionDryRun, setPlanDecisionDryRun] = useState(true);
  const [planDecisionSubmitting, setPlanDecisionSubmitting] = useState(false);
  const [planDecisionError, setPlanDecisionError] = useState<string | null>(null);

  // New plan form state
  const [newPlanTitle, setNewPlanTitle] = useState('');
  const [newPlanDescription, setNewPlanDescription] = useState('');
  const [newPlanIncidentId, setNewPlanIncidentId] = useState('');
  const [newPlanDryRun, setNewPlanDryRun] = useState(true);
  const [newPlanSubmitImmediate, setNewPlanSubmitImmediate] = useState(false);
  const [newPlanActions, setNewPlanActions] = useState<Array<{
    action: string;
    agent_id: string;
    parameters: string;
    requires_approval: boolean;
    description: string;
  }>>([
    {
      action: 'COLLECT_FORENSIC_ARTIFACT',
      agent_id: '',
      parameters: '{"artifact_type": "LOGS"}',
      requires_approval: false,
      description: 'Collect volatile host artifacts',
    },
  ]);
  const [createPlanSubmitting, setCreatePlanSubmitting] = useState(false);
  const [createPlanError, setCreatePlanError] = useState<string | null>(null);

  // Detail inspection modal
  const [inspectItem, setInspectItem] = useState<{ title: string; data: unknown } | null>(null);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Integrations state
  const [integrationSubTab, setIntegrationSubTab] = useState<'inbound' | 'outbound'>('inbound');
  const [destinations, setDestinations] = useState<NotificationDestination[]>([]);
  const [deliveries, setDeliveries] = useState<NotificationDelivery[]>([]);
  const [deliveriesTotal, setDeliveriesTotal] = useState(0);
  const [deliveryFilterStatus, setDeliveryFilterStatus] = useState<string>('ALL');
  const [isAddDestModalOpen, setIsAddDestModalOpen] = useState(false);
  const [newDestName, setNewDestName] = useState('');
  const [newDestUrl, setNewDestUrl] = useState('');
  const [newDestEvents, setNewDestEvents] = useState<string[]>([
    'INCIDENT_CREATED',
    'INCIDENT_STATUS_CHANGED',
    'DETECTION_FINDING_CREATED',
    'THREAT_INTEL_MATCHED',
    'RESPONSE_PLAN_STATE_CHANGED',
  ]);
  const [newDestSecret, setNewDestSecret] = useState('');
  const [destSubmitting, setDestSubmitting] = useState(false);
  const [destError, setDestError] = useState<string | null>(null);
  const [testingDestId, setTestingDestId] = useState<string | null>(null);
  const [retryingDeliveryId, setRetryingDeliveryId] = useState<string | null>(null);
  const [isDispatchingDeliveries, setIsDispatchingDeliveries] = useState(false);
  const [testDeliveryFeedback, setTestDeliveryFeedback] = useState<{
    destinationId: string;
    success: boolean;
    status: number | null;
    message: string;
  } | null>(null);

  // Inbound sources state
  const [inboundSources, setInboundSources] = useState<InboundSource[]>([]);
  const [isAddSourceModalOpen, setIsAddSourceModalOpen] = useState(false);
  const [selectedGuideSource, setSelectedGuideSource] = useState<InboundSource | null>(null);
  const [newSourceName, setNewSourceName] = useState('');
  const [newSourceSlug, setNewSourceSlug] = useState('');
  const [newSourceProvider, setNewSourceProvider] = useState<'GENERIC' | 'EDR' | 'SIEM'>('GENERIC');
  const [newSourcePermitted, setNewSourcePermitted] = useState<string>('*');
  const [newSourceSecret, setNewSourceSecret] = useState('');
  const [sourceSubmitting, setSourceSubmitting] = useState(false);
  const [sourceError, setSourceError] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const loadData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [
        actionsData,
        playbooksData,
        runsData,
        recordsData,
        agentsData,
        incidentsData,
        plansData,
        registryData,
        destinationsData,
        deliveriesData,
        sourcesData,
      ] = await Promise.all([
        apiClient.listResponseActions(statusFilter === 'ALL' ? undefined : statusFilter),
        apiClient.listPlaybooks(),
        apiClient.listPlaybookRuns(50),
        apiClient.listAuditRecords(50, 0),
        apiClient.listAgents().catch(() => []),
        apiClient.listIncidents().catch(() => []),
        apiClient.listResponsePlans().catch(() => []),
        apiClient.listActionRegistry().catch(() => []),
        apiClient.listNotificationDestinations().catch(() => []),
        apiClient.listNotificationDeliveries({
          status: deliveryFilterStatus === 'ALL' ? undefined : deliveryFilterStatus,
          limit: 50,
        }).catch(() => ({ total: 0, deliveries: [] })),
        apiClient.listInboundSources().catch(() => []),
      ]);

      setActions(actionsData);
      setPlaybooks(playbooksData);
      setPlaybookRuns(runsData);
      setAuditRecords(recordsData);
      setAgents(agentsData);
      setIncidents(incidentsData);
      setPlans(plansData);
      setActionRegistry(registryData);
      setDestinations(destinationsData);
      setDeliveries(deliveriesData.deliveries);
      setDeliveriesTotal(deliveriesData.total);
      setInboundSources(sourcesData);

      if (playbooksData.length > 0 && !selectedPlaybookId) {
        setSelectedPlaybookId(playbooksData[0].playbook_id);
      }
      if (incidentsData.length > 0 && !selectedIncidentId) {
        setSelectedIncidentId(incidentsData[0].incident_id);
      }
      if (agentsData.length > 0 && !selectedAgentId) {
        setSelectedAgentId(agentsData[0].id);
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to fetch SOAR & Audit data');
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const isPollingRef = useRef(false);

  // Periodic refresh
  useEffect(() => {
    const interval = setInterval(async () => {
      if (isPollingRef.current) return;
      isPollingRef.current = true;
      try {
        const [
          actionsData,
          runsData,
          recordsData,
          plansData,
          destinationsData,
          sourcesData,
          deliveriesData,
        ] = await Promise.all([
          apiClient.listResponseActions(statusFilter === 'ALL' ? undefined : statusFilter).catch(() => null),
          apiClient.listPlaybookRuns(50).catch(() => null),
          apiClient.listAuditRecords(50, 0).catch(() => null),
          apiClient.listResponsePlans().catch(() => null),
          apiClient.listNotificationDestinations().catch(() => null),
          apiClient.listInboundSources().catch(() => null),
          apiClient
            .listNotificationDeliveries({
              status: deliveryFilterStatus === 'ALL' ? undefined : deliveryFilterStatus,
              limit: 50,
            })
            .catch(() => null),
        ]);

        if (actionsData) setActions(actionsData);
        if (runsData) setPlaybookRuns(runsData);
        if (recordsData) setAuditRecords(recordsData);
        if (plansData) setPlans(plansData);
        if (destinationsData) setDestinations(destinationsData);
        if (sourcesData) setInboundSources(sourcesData);
        if (deliveriesData) {
          setDeliveries(deliveriesData.deliveries);
          setDeliveriesTotal(deliveriesData.total);
        }
      } finally {
        isPollingRef.current = false;
      }
    }, 12000);
    return () => clearInterval(interval);
  }, [statusFilter, deliveryFilterStatus]);

  const handleVerifyLedger = async () => {
    setVerifying(true);
    setError(null);
    try {
      const result = await apiClient.verifyAuditLedger();
      setVerificationResult(result);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Audit ledger verification failed');
    } finally {
      setVerifying(false);
    }
  };

  const handleApproveAction = async () => {
    if (!approvingAction || approvalReason.trim().length < 3) return;
    setSubmittingDecision(true);
    setDecisionError(null);
    try {
      await apiClient.approveResponseAction(approvingAction.id, approvalReason.trim());
      setApprovingAction(null);
      setApprovalReason('');
      await loadData();
    } catch (err: unknown) {
      setDecisionError(err instanceof Error ? err.message : 'Failed to submit approval');
    } finally {
      setSubmittingDecision(false);
    }
  };

  const handleRejectAction = async () => {
    if (!rejectingAction || approvalReason.trim().length < 3) return;
    setSubmittingDecision(true);
    setDecisionError(null);
    try {
      await apiClient.rejectResponseAction(rejectingAction.id, approvalReason.trim());
      setRejectingAction(null);
      setApprovalReason('');
      await loadData();
    } catch (err: unknown) {
      setDecisionError(err instanceof Error ? err.message : 'Failed to submit rejection');
    } finally {
      setSubmittingDecision(false);
    }
  };

  const handleExecutePlaybook = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedPlaybookId || !selectedIncidentId || !selectedAgentId) {
      setTriggerError('Please select a playbook, target incident, and target agent.');
      return;
    }
    setTriggerSubmitting(true);
    setTriggerError(null);
    try {
      await apiClient.executePlaybook({
        playbook_id: selectedPlaybookId,
        incident_id: selectedIncidentId,
        agent_id: selectedAgentId,
        dry_run: dryRunMode,
      });
      setIsTriggerModalOpen(false);
      await loadData();
    } catch (err: unknown) {
      setTriggerError(err instanceof Error ? err.message : 'Failed to execute playbook');
    } finally {
      setTriggerSubmitting(false);
    }
  };

  const handleCreatePlan = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreatePlanSubmitting(true);
    setCreatePlanError(null);
    try {
      const parsedActions: ResponsePlanActionItem[] = [];
      for (const act of newPlanActions) {
        let params: Record<string, unknown> = {};
        try {
          params = JSON.parse(act.parameters || '{}');
        } catch {
          throw new Error(`Invalid JSON parameters for action ${act.action}`);
        }
        parsedActions.push({
          action: act.action,
          agent_id: act.agent_id || (agents[0]?.id ?? ''),
          parameters: params,
          requires_approval: act.requires_approval,
          description: act.description,
        });
      }

      const targetIncId = newPlanIncidentId || (incidents[0]?.incident_id ?? '');
      if (!targetIncId) {
        throw new Error('Please select or specify a target incident');
      }

      const created = await apiClient.createResponsePlan({
        incident_id: targetIncId,
        title: newPlanTitle,
        description: newPlanDescription || undefined,
        actions: parsedActions,
        dry_run: newPlanDryRun,
        submit_for_approval: newPlanSubmitImmediate,
      });

      setPlans((prev) => [created, ...prev]);
      setIsPlanModalOpen(false);
      setNewPlanTitle('');
      setNewPlanDescription('');
    } catch (err: unknown) {
      setCreatePlanError(err instanceof Error ? err.message : 'Failed to create response plan');
    } finally {
      setCreatePlanSubmitting(false);
    }
  };

  const handleSubmitPlanForApproval = async (planId: string) => {
    setError(null);
    try {
      const updated = await apiClient.submitResponsePlan(planId);
      setPlans((prev) => prev.map((p) => (p.id === planId ? updated : p)));
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to submit plan for approval');
    }
  };

  const handlePlanDecisionSubmit = async () => {
    if (!planDecisionModal) return;
    const { plan, action } = planDecisionModal;
    setPlanDecisionSubmitting(true);
    setPlanDecisionError(null);
    try {
      let updated: ResponsePlanResponse;
      if (action === 'approve') {
        if (!planDecisionReason.trim()) throw new Error('Approval justification is required');
        updated = await apiClient.approveResponsePlan(plan.id, planDecisionReason.trim());
      } else if (action === 'reject') {
        if (!planDecisionReason.trim()) throw new Error('Rejection reason is required');
        updated = await apiClient.rejectResponsePlan(plan.id, planDecisionReason.trim());
      } else if (action === 'cancel') {
        if (!planDecisionReason.trim()) throw new Error('Cancellation reason is required');
        updated = await apiClient.cancelResponsePlan(plan.id, planDecisionReason.trim());
      } else if (action === 'execute') {
        const idempotencyKey = `exec-${plan.id.slice(0, 8)}-${Date.now()}`;
        updated = await apiClient.executeResponsePlan(plan.id, {
          dry_run: planDecisionDryRun,
          idempotency_key: idempotencyKey,
        });
      } else if (action === 'reconcile') {
        if (!planDecisionReason.trim()) throw new Error('Reconciliation reason is required');
        updated = await apiClient.reconcileResponsePlan(plan.id, planDecisionReason.trim());
      } else {
        return;
      }

      setPlans((prev) => prev.map((p) => (p.id === plan.id ? updated : p)));
      setPlanDecisionModal(null);
      setPlanDecisionReason('');
      if (selectedPlanDetails && selectedPlanDetails.id === plan.id) {
        setSelectedPlanDetails(updated);
      }
    } catch (err: unknown) {
      setPlanDecisionError(err instanceof Error ? err.message : 'Plan operation failed');
    } finally {
      setPlanDecisionSubmitting(false);
    }
  };

  const pendingApprovalsCount = actions.filter((a) => a.status === 'PENDING_APPROVAL').length;
  const pendingPlansCount = plans.filter((p) => p.status === 'PENDING_APPROVAL').length;

  const filteredPlans = plans.filter((p) => {
    if (planStatusFilter === 'ALL') return true;
    return p.status === planStatusFilter;
  });

  const getPlanRiskBadge = (risk: string) => {
    switch (risk) {
      case 'DESTRUCTIVE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-50 border border-red-200 text-red-700">DESTRUCTIVE</span>;
      case 'CONTAINMENT':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-50 border border-amber-200 text-amber-700">CONTAINMENT</span>;
      case 'REVERSIBLE':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 border border-emerald-200 text-emerald-700">REVERSIBLE</span>;
      case 'READ_ONLY':
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-50 border border-blue-200 text-blue-700">READ_ONLY</span>;
    }
  };

  const getPlanStatusBadge = (status: string) => {
    switch (status) {
      case 'DRAFT':
        return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-gray-100 border border-gray-200 text-gray-700">DRAFT</span>;
      case 'PENDING_APPROVAL':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-50 border border-amber-200 text-amber-700">PENDING APPROVAL</span>;
      case 'APPROVED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 border border-emerald-200 text-emerald-700">APPROVED</span>;
      case 'EXECUTING':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-50 border border-blue-200 text-blue-700">EXECUTING</span>;
      case 'SUCCEEDED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-50 border border-emerald-200 text-emerald-700">SUCCEEDED</span>;
      case 'FAILED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-red-50 border border-red-200 text-red-700">FAILED</span>;
      case 'REJECTED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-gray-100 border border-gray-200 text-gray-700">REJECTED</span>;
      case 'CANCELLED':
        return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-gray-100 border border-gray-200 text-gray-500">CANCELLED</span>;
      default:
        return <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-gray-100 text-gray-700 border border-gray-200">{status}</span>;
    }
  };

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'PENDING_APPROVAL':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200">
            PENDING APPROVAL
          </span>
        );
      case 'QUEUED':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
            QUEUED
          </span>
        );
      case 'EXECUTED':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-purple-50 text-purple-700 border border-purple-200">
            EXECUTED
          </span>
        );
      case 'VERIFYING':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-blue-50 text-blue-700 border border-blue-200">
            VERIFYING PROBE
          </span>
        );
      case 'VERIFIED_CONTAINED':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-emerald-50 text-emerald-700 border border-emerald-200 flex items-center space-x-1">
            <ShieldCheck className="w-3.5 h-3.5 text-emerald-600" />
            <span>VERIFIED CONTAINED</span>
          </span>
        );
      case 'VERIFICATION_INCONCLUSIVE':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200 flex items-center space-x-1">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
            <span>INCONCLUSIVE / DRY-RUN</span>
          </span>
        );
      case 'FAILED':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-red-50 text-red-700 border border-red-200">
            FAILED
          </span>
        );
      case 'TIMED_OUT':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200 flex items-center space-x-1">
            <Clock className="w-3.5 h-3.5 text-amber-600" />
            <span>TIMED OUT</span>
          </span>
        );
      case 'OUTCOME_UNCERTAIN':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-semibold bg-amber-50 text-amber-700 border border-amber-200 flex items-center space-x-1">
            <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
            <span>OUTCOME UNCERTAIN</span>
          </span>
        );
      case 'REJECTED':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-700 border border-gray-200">
            REJECTED
          </span>
        );
      case 'EXPIRED':
        return (
          <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-500 border border-gray-200">
            EXPIRED
          </span>
        );
      default:
        return (
          <span className="px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600 border border-gray-200">
            {status}
          </span>
        );
    }
  };

  const handleCreateDestination = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newDestName.trim() || !newDestUrl.trim()) return;
    setDestSubmitting(true);
    setDestError(null);
    try {
      await apiClient.createNotificationDestination({
        name: newDestName.trim(),
        destination_url: newDestUrl.trim(),
        is_enabled: true,
        subscribed_events: newDestEvents,
        signing_secret: newDestSecret.trim() ? newDestSecret.trim() : undefined,
      });
      setIsAddDestModalOpen(false);
      setNewDestName('');
      setNewDestUrl('');
      setNewDestSecret('');
      await loadData();
    } catch (err: unknown) {
      setDestError(err instanceof Error ? err.message : 'Failed to register destination');
    } finally {
      setDestSubmitting(false);
    }
  };

  const handleToggleDestination = async (dest: NotificationDestination) => {
    try {
      await apiClient.updateNotificationDestination(dest.id, {
        is_enabled: !dest.is_enabled,
      });
      await loadData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update destination state');
    }
  };

  const handleDeleteDestination = async (destId: string) => {
    if (!window.confirm('Are you sure you want to delete this notification destination? All associated delivery logs will be purged.')) {
      return;
    }
    try {
      await apiClient.deleteNotificationDestination(destId);
      await loadData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete destination');
    }
  };

  const handleTestDestination = async (destId: string) => {
    setTestingDestId(destId);
    setTestDeliveryFeedback(null);
    try {
      const res = await apiClient.testNotificationDestination(destId);
      setTestDeliveryFeedback({
        destinationId: destId,
        success: res.status === 'DELIVERED',
        status: res.response_status_code || null,
        message:
          res.status === 'DELIVERED'
            ? `Test webhook delivered successfully (${res.response_time_ms}ms, HTTP ${res.response_status_code})`
            : `Test webhook failed: ${res.error_message || res.status}`,
      });
      await loadData();
    } catch (err: unknown) {
      setTestDeliveryFeedback({
        destinationId: destId,
        success: false,
        status: null,
        message: err instanceof Error ? err.message : 'Failed to dispatch test notification',
      });
    } finally {
      setTestingDestId(null);
    }
  };

  const handleRetryDelivery = async (deliveryId: string) => {
    setRetryingDeliveryId(deliveryId);
    try {
      await apiClient.retryNotificationDelivery(deliveryId);
      await loadData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to retry delivery');
    } finally {
      setRetryingDeliveryId(null);
    }
  };

  const handleDispatchDeliveries = async () => {
    setIsDispatchingDeliveries(true);
    try {
      await apiClient.dispatchPendingDeliveries();
      await loadData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to dispatch pending deliveries');
    } finally {
      setIsDispatchingDeliveries(false);
    }
  };

  const handleGenerateSourceSecret = () => {
    const chars = 'abcdef0123456789';
    let res = '';
    for (let i = 0; i < 48; i++) {
      res += chars[Math.floor(Math.random() * chars.length)];
    }
    setNewSourceSecret(res);
  };

  const handleCreateSource = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!newSourceName.trim() || !newSourceSlug.trim() || !newSourceSecret.trim()) return;
    setSourceSubmitting(true);
    setSourceError(null);
    try {
      const permittedList = newSourcePermitted.trim() && newSourcePermitted.trim() !== '*'
        ? newSourcePermitted.split(',').map((s) => s.trim().toUpperCase()).filter(Boolean)
        : [];
      await apiClient.createInboundSource({
        name: newSourceName.trim(),
        source_id: newSourceSlug.trim().toLowerCase(),
        provider_type: newSourceProvider,
        is_enabled: true,
        shared_secret: newSourceSecret.trim(),
        permitted_event_types: permittedList,
      });
      setIsAddSourceModalOpen(false);
      setNewSourceName('');
      setNewSourceSlug('');
      setNewSourceSecret('');
      setNewSourcePermitted('*');
      await loadData();
    } catch (err: unknown) {
      setSourceError(err instanceof Error ? err.message : 'Failed to register inbound source');
    } finally {
      setSourceSubmitting(false);
    }
  };

  const handleToggleSource = async (source: InboundSource) => {
    try {
      await apiClient.updateInboundSource(source.id, {
        is_enabled: !source.is_enabled,
      });
      await loadData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to update source state');
    }
  };

  const handleDeleteSource = async (sourceId: string) => {
    if (!window.confirm('Are you sure you want to delete this inbound security event source? All deduplication history will be removed.')) {
      return;
    }
    try {
      await apiClient.deleteInboundSource(sourceId);
      await loadData();
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Failed to delete inbound source');
    }
  };

  return (
    <div className="space-y-6">
      {/* Closed-Loop Response Lifecycle State Machine Diagram */}
      <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-2 mb-3 pb-2 border-b border-border/60">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" />
            <h3 className="text-xs font-semibold text-slate-200 uppercase tracking-wider">
              Closed-Loop Response Lifecycle State Machine
            </h3>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            Cryptographic Enforcement &bull; Post-Action Verification &bull; SHA-256 Ledger
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-[11px] font-mono">
          <span className="px-2 py-1 rounded bg-surface-elevated text-slate-400 border border-border/40">
            REQUESTED
          </span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="px-2 py-1 rounded bg-amber-950/70 text-amber-300 border border-amber-800/50">
            PENDING_APPROVAL
          </span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="px-2 py-1 rounded bg-blue-950/70 text-blue-300 border border-blue-800/50">
            QUEUED
          </span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="px-2 py-1 rounded bg-purple-950/70 text-purple-300 border border-purple-800/50">
            EXECUTED
          </span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="px-2 py-1 rounded bg-cyan-950/70 text-cyan-300 border border-cyan-800/50">
            VERIFYING (Active Probe)
          </span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-600" />
          <span className="px-2 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-700/80 font-semibold shadow-sm">
            VERIFIED_CONTAINED
          </span>

          <span className="text-slate-600 mx-2">|</span>
          <span className="text-slate-400 text-[10px]">Alternative Terminal States:</span>
          <span className="px-1.5 py-0.5 rounded bg-red-950/60 text-red-400 border border-red-900/40 text-[10px]">
            FAILED
          </span>
          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-400 border border-slate-700 text-[10px]">
            REJECTED
          </span>
          <span className="px-1.5 py-0.5 rounded bg-slate-900 text-slate-500 border border-slate-800 text-[10px]">
            EXPIRED
          </span>
        </div>

        <div className="mt-2.5 pt-2 border-t border-border/40 text-[11px] text-slate-400 flex items-center space-x-1.5">
          <AlertTriangle className="w-3.5 h-3.5 text-warning flex-shrink-0" />
          <span>
            <strong>Containment Rule:</strong> Containment is never assumed upon execution. The state transitions to{' '}
            <code className="text-emerald-400 font-mono">VERIFIED_CONTAINED</code> strictly after the independent endpoint probe confirms the expected OS state (process terminated, IP dropped, or host isolated).
          </span>
        </div>
      </div>

      {/* Tabs Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-border pb-3">
        <div className="flex items-center space-x-2">
          <button
            onClick={() => setActiveTab('actions')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'actions'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-white hover:bg-surface-elevated'
            }`}
          >
            <ShieldCheck className="w-3.5 h-3.5" />
            <span>Response Actions & Approvals</span>
            {pendingApprovalsCount > 0 && (
              <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500 text-slate-950">
                {pendingApprovalsCount}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('plans')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'plans'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-white hover:bg-surface-elevated'
            }`}
          >
            <Layers className="w-3.5 h-3.5" />
            <span>Response Plans & Governance</span>
            {pendingPlansCount > 0 && (
              <span className="ml-1.5 px-1.5 py-0.2 rounded-full text-[10px] font-bold bg-amber-500 text-slate-950">
                {pendingPlansCount}
              </span>
            )}
            <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-surface-elevated text-slate-400">
              {plans.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('playbooks')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'playbooks'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-white hover:bg-surface-elevated'
            }`}
          >
            <Terminal className="w-3.5 h-3.5" />
            <span>SOAR Playbooks & History</span>
            <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-surface-elevated text-slate-400">
              {playbooks.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('ledger')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'ledger'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-white hover:bg-surface-elevated'
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>SHA-256 Audit Ledger</span>
            <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-surface-elevated text-slate-400">
              {auditRecords.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('integrations')}
            className={`flex items-center space-x-2 px-3.5 py-2 rounded-lg text-xs font-medium transition-colors ${
              activeTab === 'integrations'
                ? 'bg-blue-600 text-white'
                : 'text-slate-400 hover:text-white hover:bg-surface-elevated'
            }`}
          >
            <Webhook className="w-3.5 h-3.5" />
            <span>Integrations & Webhooks</span>
            <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-surface-elevated text-slate-400">
              {inboundSources.length + destinations.length}
            </span>
          </button>
        </div>

        <div className="flex items-center space-x-2">
          <button
            onClick={loadData}
            disabled={loading}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs font-medium transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin' : ''}`} />
            <span>Refresh</span>
          </button>

          {activeTab === 'plans' && (
            <div className="flex items-center space-x-2">
              <button
                onClick={() => setIsRegistryModalOpen(true)}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-surface-elevated hover:bg-surface text-slate-200 border border-border text-xs font-medium transition-colors"
              >
                <Sliders className="w-3.5 h-3.5 text-blue-400" />
                <span>Action Registry</span>
              </button>
              <button
                onClick={() => {
                  if (agents.length > 0 && newPlanActions[0].agent_id === '') {
                    setNewPlanActions([{ ...newPlanActions[0], agent_id: agents[0].id }]);
                  }
                  if (incidents.length > 0 && !newPlanIncidentId) {
                    setNewPlanIncidentId(incidents[0].incident_id);
                  }
                  setIsPlanModalOpen(true);
                }}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors shadow-sm"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Create Response Plan</span>
              </button>
            </div>
          )}

          {activeTab === 'playbooks' && (
            <button
              onClick={() => setIsTriggerModalOpen(true)}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors"
            >
              <Play className="w-3.5 h-3.5" />
              <span>Trigger Playbook</span>
            </button>
          )}

          {activeTab === 'ledger' && (
            <button
              onClick={handleVerifyLedger}
              disabled={verifying}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition-colors shadow-sm"
            >
              <RefreshCw className={`w-3.5 h-3.5 ${verifying ? 'animate-spin' : ''}`} />
              <span>{verifying ? 'Verifying Hashes...' : 'Verify Ledger Chain'}</span>
            </button>
          )}

          {activeTab === 'integrations' && (
            <button
              onClick={() => {
                setDestError(null);
                setIsAddDestModalOpen(true);
              }}
              className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors shadow-sm"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>Configure Destination</span>
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="p-3.5 rounded-xl bg-red-950/60 border border-red-800/60 text-red-300 text-xs flex items-center space-x-2">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 1: RESPONSE ACTIONS & APPROVALS QUEUE                            */}
      {/* ==================================================================== */}
      {activeTab === 'actions' && (
        <div className="space-y-4">
          {/* Status filter bar */}
          <div className="flex flex-wrap items-center gap-1.5 pb-2">
            <span className="text-xs text-slate-400 mr-1">Status:</span>
            {[
              'ALL',
              'PENDING_APPROVAL',
              'QUEUED',
              'EXECUTED',
              'VERIFYING',
              'VERIFIED_CONTAINED',
              'FAILED',
              'REJECTED',
            ].map((st) => (
              <button
                key={st}
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1 rounded text-xs font-medium transition-colors ${
                  statusFilter === st
                    ? 'bg-blue-600 text-white'
                    : 'bg-surface border border-border text-slate-400 hover:text-slate-200'
                }`}
              >
                {st.replace('_', ' ')}
                {st === 'PENDING_APPROVAL' && pendingApprovalsCount > 0 && (
                  <span className="ml-1 text-[10px] font-bold text-amber-300">
                    ({pendingApprovalsCount})
                  </span>
                )}
              </button>
            ))}
          </div>

          {actions.length === 0 ? (
            <EmptyState
              icon={<ShieldCheck className="w-6 h-6 text-slate-500" />}
              title="No Response Actions Found"
              description={
                statusFilter === 'ALL'
                  ? 'No automated or manual response actions have been queued yet.'
                  : `No response actions currently match the '${statusFilter}' status filter.`
              }
            />
          ) : (
            <div className="grid grid-cols-1 gap-4">
              {actions.map((act) => {
                const isPending = act.status === 'PENDING_APPROVAL';
                const hasReceipts = Boolean(act.execution_receipt || act.verification_receipt);

                return (
                  <div
                    key={act.id}
                    className={`rounded-xl border p-4 transition-all ${
                      isPending
                        ? 'border-amber-800/70 bg-amber-950/20 shadow-sm'
                        : act.status === 'VERIFIED_CONTAINED'
                        ? 'border-emerald-800/60 bg-emerald-950/15'
                        : 'border-border bg-surface'
                    }`}
                  >
                    <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3 pb-3 border-b border-border/50">
                      <div className="flex items-center space-x-3">
                        <span className="px-2.5 py-1 rounded-md text-xs font-mono font-bold bg-surface-elevated text-blue-400 border border-blue-900/40">
                          {act.action}
                        </span>
                        {getStatusBadge(act.status)}
                        {Boolean((act.execution_receipt as any)?.dry_run || act.status === 'VERIFICATION_INCONCLUSIVE') && (
                          <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-amber-950/60 text-amber-300 border border-amber-800/80">
                            DRY-RUN SIMULATED
                          </span>
                        )}
                        <span className="text-xs text-slate-500 font-mono">
                          Seq #{act.sequence}
                        </span>
                      </div>

                      <div className="flex items-center space-x-2 text-xs text-slate-400">
                        <Clock className="w-3.5 h-3.5 text-slate-500" />
                        <span>Issued: {act.issued_at ? new Date(act.issued_at).toLocaleString() : 'N/A'}</span>
                        {act.expires_at && (
                          <span className="text-[11px] text-slate-500">
                            (Expires: {new Date(act.expires_at).toLocaleTimeString()})
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 py-3 text-xs">
                      {/* Target Host Details */}
                      <div className="space-y-1">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                          Target Host / Agent
                        </span>
                        <div className="flex items-center space-x-1.5 font-medium text-slate-200">
                          <Server className="w-3.5 h-3.5 text-slate-400" />
                          <span>{act.agent?.hostname || 'Unknown Endpoint'}</span>
                        </div>
                        <div className="text-[11px] text-slate-400 font-mono">
                          IP: {act.agent?.primary_ip || 'N/A'} &bull; Status: {act.agent?.status || 'UNKNOWN'}
                        </div>
                        <div className="text-[10px] text-slate-500 font-mono truncate">
                          ID: {act.agent_id}
                        </div>
                      </div>

                      {/* Associated Incident */}
                      <div className="space-y-1">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                          Associated Incident
                        </span>
                        <div className="font-medium text-slate-200">
                          #{act.incident?.incident_number || 0} &bull; {act.incident?.title || 'Security Incident'}
                        </div>
                        <div className="flex items-center space-x-2">
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-elevated text-slate-400">
                            Severity: {act.incident?.severity || 'MEDIUM'}
                          </span>
                          <span className="text-[10px] text-slate-500 font-mono truncate">
                            ID: {act.incident_id}
                          </span>
                        </div>
                      </div>

                      {/* Parameters */}
                      <div className="space-y-1">
                        <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider block">
                          Command Parameters
                        </span>
                        <div className="bg-surface-elevated/70 p-2 rounded border border-border/40 font-mono text-[11px] text-slate-300 max-h-16 overflow-y-auto">
                          {Object.keys(act.parameters || {}).length === 0 ? (
                            <span className="text-slate-500 italic">No parameters</span>
                          ) : (
                            Object.entries(act.parameters).map(([k, v]) => (
                              <div key={k} className="truncate">
                                <span className="text-slate-400">{k}:</span>{' '}
                                <span className="text-blue-300 font-semibold">{String(v)}</span>
                              </div>
                            ))
                          )}
                        </div>
                      </div>
                    </div>

                    {/* Approver / Rejection note if present */}
                    {(act.approved_by || act.approval_reason) && (
                      <div className="px-3 py-2 rounded-lg bg-surface-elevated/50 border border-border/40 text-[11px] text-slate-400 mb-3 flex items-center justify-between">
                        <div>
                          <span className="text-slate-300 font-medium">Analyst Decision:</span>{' '}
                          {act.approved_by ? `Authorized by ${act.approved_by}` : 'Decision logged'}{' '}
                          {act.approved_at ? `on ${new Date(act.approved_at).toLocaleString()}` : ''}
                          {act.approval_reason && (
                            <span className="italic text-slate-300 ml-1">
                              &mdash; &ldquo;{act.approval_reason}&rdquo;
                            </span>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Action Footprint & Control Buttons */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pt-2 border-t border-border/40">
                      <div className="text-[11px] font-mono text-slate-500">
                        Command UUID: <span className="text-slate-400">{act.command_id}</span>
                      </div>

                      <div className="flex items-center space-x-2">
                        {hasReceipts && (
                          <button
                            onClick={() =>
                              setInspectItem({
                                title: `Receipts & Probe Result: ${act.action} (#${act.sequence})`,
                                data: {
                                  execution_receipt: act.execution_receipt,
                                  verification_receipt: act.verification_receipt,
                                },
                              })
                            }
                            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-surface-elevated hover:bg-surface border border-border text-slate-300 text-xs font-medium transition-colors"
                          >
                            <Eye className="w-3.5 h-3.5 text-blue-400" />
                            <span>Inspect Receipts</span>
                          </button>
                        )}

                        {isPending && (
                          <>
                            <button
                              onClick={() => {
                                setApprovingAction(act);
                                setApprovalReason('');
                                setDecisionError(null);
                              }}
                              className="flex items-center space-x-1 px-3 py-1 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors shadow-sm"
                            >
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Authorize Action</span>
                            </button>
                            <button
                              onClick={() => {
                                setRejectingAction(act);
                                setApprovalReason('');
                                setDecisionError(null);
                              }}
                              className="flex items-center space-x-1 px-3 py-1 rounded-lg bg-red-700 hover:bg-red-600 text-white text-xs font-medium transition-colors"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Reject</span>
                            </button>
                          </>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB: GOVERNED RESPONSE PLANS                                         */}
      {/* ==================================================================== */}
      {activeTab === 'plans' && (
        <div className="space-y-6">
          {/* Summary metrics */}
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3">
            <div className="p-3 rounded-xl border border-border bg-surface">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Total Plans</span>
              <div className="text-xl font-bold text-white mt-1">{plans.length}</div>
            </div>
            <div className="p-3 rounded-xl border border-border bg-surface">
              <span className="text-[10px] text-slate-400 uppercase font-semibold">Drafts</span>
              <div className="text-xl font-bold text-slate-300 mt-1">
                {plans.filter((p) => p.status === 'DRAFT').length}
              </div>
            </div>
            <div className="p-3 rounded-xl border border-amber-900/40 bg-amber-950/20">
              <span className="text-[10px] text-amber-400 uppercase font-semibold">Pending Approval</span>
              <div className="text-xl font-bold text-amber-300 mt-1">
                {plans.filter((p) => p.status === 'PENDING_APPROVAL').length}
              </div>
            </div>
            <div className="p-3 rounded-xl border border-emerald-900/40 bg-emerald-950/20">
              <span className="text-[10px] text-emerald-400 uppercase font-semibold">Approved</span>
              <div className="text-xl font-bold text-emerald-300 mt-1">
                {plans.filter((p) => p.status === 'APPROVED').length}
              </div>
            </div>
            <div className="p-3 rounded-xl border border-blue-900/40 bg-blue-950/20">
              <span className="text-[10px] text-blue-400 uppercase font-semibold">Executing / Done</span>
              <div className="text-xl font-bold text-blue-300 mt-1">
                {plans.filter((p) => p.status === 'EXECUTING' || p.status === 'SUCCEEDED').length}
              </div>
            </div>
            <div className="p-3 rounded-xl border border-red-900/40 bg-red-950/20">
              <span className="text-[10px] text-red-400 uppercase font-semibold">Failed / Rejected</span>
              <div className="text-xl font-bold text-red-300 mt-1">
                {plans.filter((p) => p.status === 'FAILED' || p.status === 'REJECTED').length}
              </div>
            </div>
          </div>

          {/* Status filter bar */}
          <div className="flex flex-wrap items-center gap-1.5 pb-1">
            <span className="text-xs text-slate-400 mr-1">Filter Status:</span>
            {[
              'ALL',
              'DRAFT',
              'PENDING_APPROVAL',
              'APPROVED',
              'EXECUTING',
              'SUCCEEDED',
              'FAILED',
              'REJECTED',
              'CANCELLED',
            ].map((st) => (
              <button
                key={st}
                onClick={() => setPlanStatusFilter(st)}
                className={`px-2.5 py-1 rounded-lg text-xs font-medium transition-colors ${
                  planStatusFilter === st
                    ? 'bg-blue-600 text-white font-semibold'
                    : 'bg-surface-elevated text-slate-400 hover:text-white'
                }`}
              >
                {st.replace('_', ' ')}
                {st !== 'ALL' && (
                  <span className="ml-1 text-[10px] opacity-70">
                    ({plans.filter((p) => p.status === st).length})
                  </span>
                )}
              </button>
            ))}
          </div>

          {/* Plan cards */}
          {filteredPlans.length === 0 ? (
            <EmptyState
              icon={<Layers className="w-8 h-8 text-slate-500" />}
              title="No Response Plans Found"
              description="No response plans match the current filter. Create a governed plan or change status filters."
            />
          ) : (
            <div className="space-y-4">
              {filteredPlans.map((plan) => {
                const linkedInc = incidents.find((i) => i.incident_id === plan.incident_id);
                return (
                  <div
                    key={plan.id}
                    className="rounded-xl border border-border bg-surface p-5 space-y-4 hover:border-slate-700 transition-colors shadow-sm"
                  >
                    {/* Header */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border/70">
                      <div className="flex items-center space-x-3">
                        <span className="text-xs font-mono font-bold text-blue-400 bg-blue-950/60 border border-blue-800/60 px-2 py-0.5 rounded">
                          PLAN-#{String(plan.plan_number).padStart(4, '0')}
                        </span>
                        <h4 className="text-sm font-semibold text-white">{plan.title}</h4>
                      </div>

                      <div className="flex items-center space-x-2">
                        {getPlanRiskBadge(plan.risk_level)}
                        {getPlanStatusBadge(plan.status)}
                        {plan.is_simulation ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-amber-950/70 border border-amber-800 text-amber-300">
                            SIMULATION (DRY-RUN)
                          </span>
                        ) : plan.dry_run ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-medium bg-slate-800 text-slate-300">
                            DRY-RUN
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-purple-950 border border-purple-800 text-purple-300">
                            LIVE EXECUTION
                          </span>
                        )}
                      </div>
                    </div>

                    {/* Description & linked incident */}
                    <div className="text-xs text-slate-300 flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <p className="text-slate-400">{plan.description || 'No description provided.'}</p>
                      <div className="flex items-center space-x-1.5 font-mono text-[11px] text-slate-400">
                        <span className="text-slate-500">Incident:</span>
                        <span className="text-slate-300">
                          {linkedInc ? `INC-${String(linkedInc.incident_number).padStart(4, '0')} (${linkedInc.title})` : plan.incident_id.slice(0, 12)}
                        </span>
                      </div>
                    </div>

                    {/* Action steps preview */}
                    <div className="space-y-1.5 bg-slate-950/60 p-3 rounded-lg border border-border/50">
                      <div className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider mb-1 flex items-center justify-between">
                        <span>Planned Actions ({plan.actions.length})</span>
                        {plan.approval_hash && (
                          <div className="flex items-center space-x-1 font-mono text-[10px] text-slate-400">
                            <span>Hash:</span>
                            <span className="text-emerald-400 font-bold">{plan.approval_hash.slice(0, 12)}...</span>
                            <button
                              onClick={() => copyToClipboard(plan.approval_hash!, plan.id)}
                              className="p-0.5 hover:text-white"
                              title="Copy approval hash"
                            >
                              <Copy className="w-3 h-3" />
                            </button>
                          </div>
                        )}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {plan.actions.map((act, idx) => (
                          <div
                            key={idx}
                            className="p-2 rounded bg-surface border border-border/40 text-xs flex items-center justify-between"
                          >
                            <div className="flex items-center space-x-2">
                              <span className="text-slate-500 font-mono text-[10px]">#{idx + 1}</span>
                              <span className="font-mono font-semibold text-slate-200">{act.action}</span>
                            </div>
                            <span className="text-[10px] text-slate-400 truncate max-w-[180px]">
                              {JSON.stringify(act.parameters)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Metadata & Actions footer */}
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-2 text-xs text-slate-400">
                      <div className="flex flex-wrap items-center gap-3 text-[11px]">
                        <span>Created by <strong className="text-slate-300 font-mono">{plan.created_by}</strong></span>
                        <span>&bull;</span>
                        <span>{new Date(plan.created_at).toLocaleString()}</span>
                        {plan.approved_by && (
                          <>
                            <span>&bull;</span>
                            <span className="text-emerald-400">
                              Approved by <strong>{plan.approved_by}</strong>
                            </span>
                          </>
                        )}
                        {plan.rejected_by && (
                          <>
                            <span>&bull;</span>
                            <span className="text-rose-400">
                              Rejected by <strong>{plan.rejected_by}</strong>
                            </span>
                          </>
                        )}
                      </div>

                      <div className="flex items-center space-x-2">
                        <button
                          onClick={() => setSelectedPlanDetails(plan)}
                          className="flex items-center space-x-1 px-2.5 py-1 rounded bg-surface-elevated hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5" />
                          <span>Details</span>
                        </button>

                        {plan.status === 'DRAFT' && (
                          <>
                            <button
                              onClick={() => handleSubmitPlanForApproval(plan.id)}
                              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors shadow-sm"
                            >
                              <Send className="w-3.5 h-3.5" />
                              <span>Submit</span>
                            </button>
                            <button
                              onClick={() => setPlanDecisionModal({ plan, action: 'cancel' })}
                              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Cancel</span>
                            </button>
                          </>
                        )}

                        {plan.status === 'PENDING_APPROVAL' && (
                          <>
                            <button
                              onClick={() => {
                                setPlanDecisionModal({ plan, action: 'approve' });
                                setPlanDecisionReason('');
                                setPlanDecisionError(null);
                              }}
                              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-medium transition-colors shadow-sm"
                            >
                              <CheckCircle2 className="w-3.5 h-3.5" />
                              <span>Approve</span>
                            </button>
                            <button
                              onClick={() => {
                                setPlanDecisionModal({ plan, action: 'reject' });
                                setPlanDecisionReason('');
                                setPlanDecisionError(null);
                              }}
                              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-red-700 hover:bg-red-600 text-white text-xs font-medium transition-colors"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Reject</span>
                            </button>
                            <button
                              onClick={() => {
                                setPlanDecisionModal({ plan, action: 'cancel' });
                                setPlanDecisionReason('');
                                setPlanDecisionError(null);
                              }}
                              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Cancel</span>
                            </button>
                          </>
                        )}

                        {plan.status === 'APPROVED' && (
                          <>
                            <button
                              onClick={() => {
                                setPlanDecisionModal({ plan, action: 'execute' });
                                setPlanDecisionDryRun(plan.dry_run);
                                setPlanDecisionError(null);
                              }}
                              className="flex items-center space-x-1 px-3 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition-colors shadow-sm"
                            >
                              <Play className="w-3.5 h-3.5" />
                              <span>Execute Plan</span>
                            </button>
                            <button
                              onClick={() => {
                                setPlanDecisionModal({ plan, action: 'cancel' });
                                setPlanDecisionReason('');
                                setPlanDecisionError(null);
                              }}
                              className="flex items-center space-x-1 px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-medium transition-colors"
                            >
                              <XCircle className="w-3.5 h-3.5" />
                              <span>Cancel</span>
                            </button>
                          </>
                        )}

                        {plan.status === 'EXECUTING' && (
                          <button
                            onClick={() => {
                              setPlanDecisionModal({ plan, action: 'reconcile' });
                              setPlanDecisionReason('');
                              setPlanDecisionError(null);
                            }}
                            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-amber-700 hover:bg-amber-600 text-white text-xs font-medium transition-colors shadow-sm"
                            title="Reconcile an interrupted execution"
                          >
                            <AlertTriangle className="w-3.5 h-3.5" />
                            <span>Reconcile</span>
                          </button>
                        )}

                        {(plan.status === 'SUCCEEDED' || plan.status === 'FAILED') && plan.execution_summary && (
                          <button
                            onClick={() =>
                              setInspectItem({
                                title: `Execution Summary: PLAN-#${String(plan.plan_number).padStart(4, '0')}`,
                                data: plan.execution_summary,
                              })
                            }
                            className="flex items-center space-x-1 px-2.5 py-1 rounded bg-surface-elevated hover:bg-slate-700 text-slate-200 text-xs font-medium transition-colors"
                          >
                            <FileText className="w-3.5 h-3.5" />
                            <span>Receipt</span>
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 2: SOAR PLAYBOOKS & RUN HISTORY                                 */}
      {/* ==================================================================== */}
      {activeTab === 'playbooks' && (
        <div className="space-y-6">
          {/* Section: Configured Playbooks */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-2">
                <Terminal className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-semibold text-white">Configured Response Playbooks</h3>
              </div>
              <span className="text-xs text-slate-500 font-mono">
                {playbooks.length} Active Workflows
              </span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {playbooks.map((pb) => (
                <div
                  key={pb.playbook_id}
                  className="rounded-xl border border-border bg-surface p-4 flex flex-col justify-between space-y-3"
                >
                  <div className="space-y-1.5">
                    <div className="flex items-start justify-between gap-2">
                      <h4 className="text-xs font-bold text-white font-mono break-all">
                        {pb.name}
                      </h4>
                      {pb.requires_approval ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-950 text-amber-300 border border-amber-800/60 flex-shrink-0">
                          APPROVAL GATE
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-blue-950 text-blue-300 border border-blue-800/60 flex-shrink-0">
                          AUTO-EXECUTE
                        </span>
                      )}
                    </div>
                    <p className="text-xs text-slate-400">{pb.description}</p>
                  </div>

                  <div className="space-y-2 pt-2 border-t border-border/50 text-xs">
                    <div className="text-[11px] text-slate-400">
                      <span className="font-semibold text-slate-300">Action Steps:</span>{' '}
                      {pb.action_steps.length > 0 ? (
                        <span className="font-mono text-purple-300">
                          {pb.action_steps
                            .map((s) => String((s as Record<string, unknown>).action || 'ACTION'))
                            .join(' &rarr; ')}
                        </span>
                      ) : (
                        <span className="italic text-slate-500">None defined</span>
                      )}
                    </div>

                    <div className="flex items-center justify-between pt-1">
                      <span className="text-[10px] text-slate-500 font-mono truncate max-w-[200px]">
                        ID: {pb.playbook_id}
                      </span>
                      <button
                        onClick={() => {
                          setSelectedPlaybookId(pb.playbook_id);
                          setIsTriggerModalOpen(true);
                        }}
                        className="flex items-center space-x-1 px-2.5 py-1 rounded bg-purple-900/50 hover:bg-purple-800/60 border border-purple-700/60 text-purple-200 text-xs font-medium transition-colors"
                      >
                        <Play className="w-3 h-3" />
                        <span>Launch Workflow</span>
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Section: Playbook Run History */}
          <div className="rounded-xl border border-border bg-surface p-5">
            <div className="flex items-center justify-between pb-3 border-b border-border mb-4">
              <div className="flex items-center space-x-2">
                <FileText className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-semibold text-white">Playbook Run History</h3>
              </div>
              <span className="text-xs text-slate-500 font-mono">
                {playbookRuns.length} Recorded Executions
              </span>
            </div>

            {playbookRuns.length === 0 ? (
              <EmptyState
                icon={<Terminal className="w-5 h-5 text-slate-500" />}
                title="No Playbook Runs Recorded"
                description="Trigger an automated workflow or simulate response actions to view historical runs."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-surface-elevated text-slate-400 uppercase text-[10px] tracking-wider">
                    <tr>
                      <th className="py-2.5 px-3">Run ID</th>
                      <th className="py-2.5 px-3">Playbook</th>
                      <th className="py-2.5 px-3">Target Incident</th>
                      <th className="py-2.5 px-3">Mode</th>
                      <th className="py-2.5 px-3">Status</th>
                      <th className="py-2.5 px-3">Executed By</th>
                      <th className="py-2.5 px-3">Timestamp</th>
                      <th className="py-2.5 px-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {playbookRuns.map((run) => (
                      <tr key={run.run_id} className="hover:bg-surface-elevated/40 transition-colors">
                        <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px]">
                          {run.run_id.slice(0, 8)}...
                        </td>
                        <td className="py-2.5 px-3 font-medium text-slate-200">
                          {run.playbook_name || 'Playbook'}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-400 text-[11px]">
                          {run.incident_id.slice(0, 8)}...
                        </td>
                        <td className="py-2.5 px-3">
                          {run.dry_run ? (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-blue-950 text-blue-300 border border-blue-800/60">
                              SIMULATION
                            </span>
                          ) : (
                            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-amber-950 text-amber-300 border border-amber-800/60 font-semibold">
                              LIVE
                            </span>
                          )}
                        </td>
                        <td className="py-2.5 px-3">
                          {run.status === 'SUCCESS' ? (
                            <span className="text-emerald-400 font-semibold">SUCCESS</span>
                          ) : run.status === 'PENDING_APPROVAL' ? (
                            <span className="text-amber-300 font-semibold">PENDING APPROVAL</span>
                          ) : run.status === 'FAILED' ? (
                            <span className="text-red-400 font-semibold">FAILED</span>
                          ) : (
                            <span className="text-slate-400">{run.status}</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 font-mono text-[11px]">
                          {run.executed_by}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                          {run.start_time ? new Date(run.start_time).toLocaleString() : 'N/A'}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() =>
                              setInspectItem({
                                title: `Playbook Run Output: ${run.playbook_name || run.run_id}`,
                                data: run.output_summary,
                              })
                            }
                            className="p-1 rounded hover:bg-surface-elevated text-slate-400 hover:text-slate-200"
                            title="Inspect Output Summary"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 3: CRYPTOGRAPHIC AUDIT LEDGER                                   */}
      {/* ==================================================================== */}
      {activeTab === 'ledger' && (
        <div className="space-y-6">
          {/* Verification Status Card */}
          <div className="rounded-xl border border-border bg-surface p-5">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-border mb-4">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-emerald-400" />
                <h3 className="text-sm font-semibold text-white">
                  SHA-256 Hash-Chained Audit Ledger
                </h3>
              </div>
              <span className="text-xs text-slate-400 font-mono">
                {auditRecords.length} Hash-Chained Records Loaded
              </span>
            </div>

            {verificationResult && (
              <div
                className={`p-4 rounded-xl border mb-4 space-y-2 ${
                  verificationResult.tamper_detected
                    ? 'bg-red-950/70 border-red-800 text-red-200'
                    : 'bg-emerald-950/60 border-emerald-800/70 text-emerald-200'
                }`}
              >
                <div className="flex items-center space-x-2 font-bold text-sm">
                  {verificationResult.tamper_detected ? (
                    <>
                      <AlertTriangle className="w-5 h-5 text-red-400" />
                      <span>
                        CRITICAL: Tamper Detected in Audit Trail at Sequence #
                        {verificationResult.broken_sequence}!
                      </span>
                    </>
                  ) : (
                    <>
                      <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                      <span>
                        Cryptographic Hash Chain Intact: {verificationResult.total_records} Records Verified
                      </span>
                    </>
                  )}
                </div>

                <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono pt-1 text-slate-300">
                  <div className="p-2 rounded bg-surface/60 border border-border/40">
                    <span className="text-slate-400 block text-[10px] uppercase font-bold">
                      Genesis Anchor Hash:
                    </span>
                    <span className="break-all text-[11px]">
                      {verificationResult.genesis_hash}
                    </span>
                  </div>
                  <div className="p-2 rounded bg-surface/60 border border-border/40">
                    <span className="text-slate-400 block text-[10px] uppercase font-bold">
                      Latest Committed Block Hash:
                    </span>
                    <span className="break-all text-[11px]">
                      {verificationResult.latest_hash || 'None'}
                    </span>
                  </div>
                </div>
              </div>
            )}

            {/* Audit Records Table */}
            {auditRecords.length === 0 ? (
              <EmptyState
                icon={<Lock className="w-5 h-5 text-slate-500" />}
                title="Audit Ledger Initialized"
                description="Sensitive operations, playbook approvals, and containment actions will be cryptographically chained here."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs text-left">
                  <thead className="bg-surface-elevated text-slate-400 uppercase text-[10px] tracking-wider">
                    <tr>
                      <th className="py-2.5 px-3">Seq #</th>
                      <th className="py-2.5 px-3">Timestamp</th>
                      <th className="py-2.5 px-3">Actor</th>
                      <th className="py-2.5 px-3">Action</th>
                      <th className="py-2.5 px-3">Target Entity</th>
                      <th className="py-2.5 px-3 font-mono">Current Hash (SHA-256)</th>
                      <th className="py-2.5 px-3 font-mono">Previous Hash</th>
                      <th className="py-2.5 px-3 text-right">Payload</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {auditRecords.map((rec) => (
                      <tr key={rec.record_id} className="hover:bg-surface-elevated/40 transition-colors">
                        <td className="py-2.5 px-3 font-mono font-bold text-blue-400 text-[11px]">
                          #{rec.sequence_number}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                          {rec.timestamp ? new Date(rec.timestamp).toLocaleString() : 'N/A'}
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="font-mono text-slate-200 text-[11px]">{rec.actor_id}</div>
                          <span className="text-[10px] text-slate-500">{rec.actor_role}</span>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="px-2 py-0.5 rounded text-[11px] font-mono font-medium bg-surface-elevated text-purple-300 border border-purple-900/30">
                            {rec.action}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-slate-300 text-[11px] truncate max-w-[150px]">
                          {rec.target_entity}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-emerald-400">
                          <div className="flex items-center space-x-1">
                            <span>{rec.current_hash.slice(0, 10)}...</span>
                            <button
                              onClick={() => copyToClipboard(rec.current_hash, `curr-${rec.record_id}`)}
                              className="p-0.5 hover:text-white text-slate-500"
                              title="Copy SHA-256 Hash"
                            >
                              {copiedKey === `curr-${rec.record_id}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-slate-500">
                          <div className="flex items-center space-x-1">
                            <span>{rec.previous_hash.slice(0, 8)}...</span>
                            <button
                              onClick={() => copyToClipboard(rec.previous_hash, `prev-${rec.record_id}`)}
                              className="p-0.5 hover:text-white text-slate-600"
                              title="Copy Previous Hash"
                            >
                              {copiedKey === `prev-${rec.record_id}` ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <button
                            onClick={() =>
                              setInspectItem({
                                title: `Audit Record #${rec.sequence_number}: ${rec.action}`,
                                data: rec.canonical_payload || {},
                              })
                            }
                            className="p-1 rounded hover:bg-surface-elevated text-slate-400 hover:text-slate-200"
                            title="Inspect Canonical Payload"
                          >
                            <Eye className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* TAB 5: INTEGRATIONS & WEBHOOKS (INBOUND & OUTBOUND)                  */}
      {/* ==================================================================== */}
      {activeTab === 'integrations' && (
        <div className="space-y-6">
          {/* Sub Navigation Segmented Switcher */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-border/80 pb-3">
            <div className="flex items-center space-x-2 bg-surface-elevated/60 p-1 rounded-xl border border-border">
              <button
                type="button"
                onClick={() => setIntegrationSubTab('inbound')}
                className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  integrationSubTab === 'inbound'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white hover:bg-surface'
                }`}
              >
                <Server className="w-3.5 h-3.5" />
                <span>Inbound Event Sources</span>
                <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
                  {inboundSources.length}
                </span>
              </button>

              <button
                type="button"
                onClick={() => setIntegrationSubTab('outbound')}
                className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  integrationSubTab === 'outbound'
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-white hover:bg-surface'
                }`}
              >
                <Webhook className="w-3.5 h-3.5" />
                <span>Outbound Destinations</span>
                <span className="ml-1 px-1.5 py-0.2 rounded text-[10px] bg-slate-800 text-slate-300 font-mono">
                  {destinations.length}
                </span>
              </button>
            </div>

            <div className="flex items-center space-x-2 text-xs text-slate-400">
              <span className="font-mono text-[11px] bg-surface px-2.5 py-1 rounded-lg border border-border">
                {integrationSubTab === 'inbound'
                  ? 'Authenticated Ingestion & Normalization'
                  : 'SSRF-Protected Security Notifier'}
              </span>
            </div>
          </div>

          {/* ---------------------------------------------------------------- */}
          {/* SUB-VIEW 1: INBOUND EVENT SOURCES                                */}
          {/* ---------------------------------------------------------------- */}
          {integrationSubTab === 'inbound' && (
            <div className="space-y-6">
              {/* Inbound KPI Metrics Row */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
                  <div className="flex items-center justify-between text-slate-400 mb-1">
                    <span className="text-xs font-semibold uppercase tracking-wider">Authorized Sources</span>
                    <Server className="w-4 h-4 text-blue-400" />
                  </div>
                  <div className="flex items-baseline space-x-2">
                    <span className="text-2xl font-bold font-mono text-white">{inboundSources.length}</span>
                    <span className="text-xs text-slate-400">
                      ({inboundSources.filter((s) => s.is_enabled).length} Active)
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-2">
                    Configured external security products (GENERIC, EDR, SIEM)
                  </p>
                </div>

                <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
                  <div className="flex items-center justify-between text-slate-400 mb-1">
                    <span className="text-xs font-semibold uppercase tracking-wider">Ingested Events</span>
                    <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  </div>
                  <div className="flex items-baseline space-x-2">
                    <span className="text-2xl font-bold font-mono text-emerald-400">
                      {inboundSources.reduce((acc, s) => acc + s.total_events_accepted, 0)}
                    </span>
                    <span className="text-xs text-slate-400">
                      / {inboundSources.reduce((acc, s) => acc + s.total_events_received, 0)} received
                    </span>
                  </div>
                  <div className="flex items-center space-x-3 mt-2 text-[11px]">
                    <span className="text-blue-400 font-mono">
                      {inboundSources.reduce((acc, s) => acc + s.total_events_deduplicated, 0)} Deduplicated
                    </span>
                    <span className="text-red-400 font-mono">
                      {inboundSources.reduce((acc, s) => acc + s.total_events_rejected, 0)} Rejected
                    </span>
                  </div>
                </div>

                <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
                  <div className="flex items-center justify-between text-slate-400 mb-1">
                    <span className="text-xs font-semibold uppercase tracking-wider">Trust & Freshness Shield</span>
                    <ShieldCheck className="w-4 h-4 text-purple-400" />
                  </div>
                  <div className="flex items-center space-x-2">
                    <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-950 text-purple-300 border border-purple-800">
                      HMAC-SHA256 & 300s WINDOW
                    </span>
                  </div>
                  <p className="text-[11px] text-slate-500 mt-2">
                    Constant-time signature verification, replay protection & agent impersonation prevention
                  </p>
                </div>
              </div>

              {/* Inbound Sources Table */}
              <div className="p-5 rounded-xl border border-border bg-surface shadow-sm space-y-4">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border">
                  <div>
                    <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                      <Server className="w-4 h-4 text-blue-400" />
                      <span>Configured Inbound Security Event Sources</span>
                    </h3>
                    <p className="text-xs text-slate-400">
                      Authenticated external event feeds routed into Ethio-SOAR detection & correlation pipeline
                    </p>
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      setSourceError(null);
                      setIsAddSourceModalOpen(true);
                    }}
                    className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors shadow-sm"
                  >
                    <Plus className="w-3.5 h-3.5" />
                    <span>Add Inbound Source</span>
                  </button>
                </div>

                {inboundSources.length === 0 ? (
                  <EmptyState
                    icon={<Server className="w-8 h-8 text-slate-500" />}
                    title="No Inbound Event Sources Configured"
                    description="Register an external EDR, SIEM, or generic security event sender to securely stream alerts into Ethio-SOAR."
                    actionText="Configure First Inbound Source"
                    onAction={() => setIsAddSourceModalOpen(true)}
                  />
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs border-collapse">
                      <thead>
                        <tr className="border-b border-border/60 text-slate-400">
                          <th className="py-2.5 px-3 font-semibold">Name & Status</th>
                          <th className="py-2.5 px-3 font-semibold">Source Slug & Ingest Route</th>
                          <th className="py-2.5 px-3 font-semibold">Provider Profile</th>
                          <th className="py-2.5 px-3 font-semibold">Permitted Events</th>
                          <th className="py-2.5 px-3 font-semibold">Ingestion Metrics</th>
                          <th className="py-2.5 px-3 font-semibold">Last Received</th>
                          <th className="py-2.5 px-3 text-right font-semibold">Actions</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/40 text-slate-300">
                        {inboundSources.map((source) => (
                          <tr key={source.id} className="hover:bg-surface-elevated/40 transition-colors">
                            <td className="py-2.5 px-3 font-medium">
                              <div className="flex items-center space-x-2">
                                <span
                                  className={`w-2 h-2 rounded-full ${
                                    source.is_enabled ? 'bg-emerald-400' : 'bg-slate-600'
                                  }`}
                                />
                                <div>
                                  <div className="text-white font-semibold">{source.name}</div>
                                  <div className="text-[10px] text-slate-500 font-mono">
                                    Auth: {source.auth_type}
                                  </div>
                                </div>
                              </div>
                            </td>
                            <td className="py-2.5 px-3">
                              <div className="flex items-center space-x-1.5">
                                <span className="font-mono text-[11px] text-blue-300 bg-surface-elevated px-1.5 py-0.5 rounded border border-border">
                                  /inbound/{source.source_id}/events
                                </span>
                                <button
                                  type="button"
                                  onClick={() =>
                                    copyToClipboard(
                                      `/api/v1/integrations/inbound/${source.source_id}/events`,
                                      `route-${source.id}`
                                    )
                                  }
                                  className="p-1 hover:text-white text-slate-500 rounded"
                                  title="Copy Ingest Route"
                                >
                                  {copiedKey === `route-${source.id}` ? (
                                    <Check className="w-3 h-3 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3 h-3" />
                                  )}
                                </button>
                              </div>
                            </td>
                            <td className="py-2.5 px-3">
                              <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-800 text-slate-200 border border-slate-700 font-mono">
                                {source.provider_type}
                              </span>
                            </td>
                            <td className="py-2.5 px-3">
                              <div className="flex flex-wrap gap-1">
                                {source.permitted_event_types.length === 0 ? (
                                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-slate-800 text-slate-400 font-mono">
                                    ALL (*)
                                  </span>
                                ) : (
                                  source.permitted_event_types.map((ev) => (
                                    <span
                                      key={ev}
                                      className="px-1.5 py-0.5 rounded text-[10px] bg-blue-950/80 text-blue-300 border border-blue-800/60 font-mono"
                                    >
                                      {ev}
                                    </span>
                                  ))
                                )}
                              </div>
                            </td>
                            <td className="py-2.5 px-3 font-mono text-[11px]">
                              <div className="space-y-0.5">
                                <span className="text-emerald-400 font-semibold">
                                  {source.total_events_accepted} accepted
                                </span>
                                <span className="text-slate-500 mx-1">·</span>
                                <span className="text-blue-400">
                                  {source.total_events_deduplicated} dedup
                                </span>
                                {source.total_events_rejected > 0 && (
                                  <div className="text-red-400 text-[10px]">
                                    {source.total_events_rejected} rejected
                                  </div>
                                )}
                              </div>
                            </td>
                            <td className="py-2.5 px-3 text-slate-400 text-[11px]">
                              {source.last_received_at ? (
                                <span>{new Date(source.last_received_at).toLocaleString()}</span>
                              ) : (
                                <span className="text-slate-600">Never</span>
                              )}
                            </td>
                            <td className="py-2.5 px-3 text-right">
                              <div className="flex items-center justify-end space-x-1">
                                <button
                                  type="button"
                                  onClick={() => setSelectedGuideSource(source)}
                                  className="p-1 rounded hover:bg-surface-elevated text-blue-400 hover:text-blue-300"
                                  title="View Ingestion Guide & Payload Sample"
                                >
                                  <Terminal className="w-3.5 h-3.5" />
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleToggleSource(source)}
                                  className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
                                    source.is_enabled
                                      ? 'bg-amber-950/70 border border-amber-800/70 text-amber-300 hover:bg-amber-900/80'
                                      : 'bg-emerald-950/70 border border-emerald-800/70 text-emerald-300 hover:bg-emerald-900/80'
                                  }`}
                                  title={source.is_enabled ? 'Disable Inbound Source' : 'Enable Inbound Source'}
                                >
                                  {source.is_enabled ? 'Disable' : 'Enable'}
                                </button>
                                <button
                                  type="button"
                                  onClick={() => handleDeleteSource(source.id)}
                                  className="p-1 rounded hover:bg-red-950 text-slate-500 hover:text-red-400"
                                  title="Delete Source"
                                >
                                  <Trash2 className="w-3.5 h-3.5" />
                                </button>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* ---------------------------------------------------------------- */}
          {/* SUB-VIEW 2: OUTBOUND WEBHOOK DESTINATIONS (Prompt 1 baseline)     */}
          {/* ---------------------------------------------------------------- */}
          {integrationSubTab === 'outbound' && (
            <div className="space-y-6">
              {/* Top KPI Metrics Row */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-xs font-semibold uppercase tracking-wider">Configured Destinations</span>
                <Webhook className="w-4 h-4 text-blue-400" />
              </div>
              <div className="flex items-baseline space-x-2">
                <span className="text-2xl font-bold font-mono text-white">{destinations.length}</span>
                <span className="text-xs text-slate-400">
                  ({destinations.filter((d) => d.is_enabled).length} Active)
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-2">
                Provider-neutral HTTPS outbound security webhooks
              </p>
            </div>

            <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-xs font-semibold uppercase tracking-wider">Outbound Deliveries</span>
                <Send className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="flex items-baseline space-x-2">
                <span className="text-2xl font-bold font-mono text-emerald-400">
                  {deliveries.filter((d) => d.status === 'DELIVERED').length}
                </span>
                <span className="text-xs text-slate-400">
                  / {deliveriesTotal} total
                </span>
              </div>
              <div className="flex items-center space-x-3 mt-2 text-[11px]">
                <span className="text-amber-400">
                  {deliveries.filter((d) => d.status === 'RETRY_SCHEDULED').length} Retrying
                </span>
                <span className="text-red-400">
                  {deliveries.filter((d) => d.status === 'PERMANENTLY_FAILED' || d.status === 'FAILED').length} Failed
                </span>
              </div>
            </div>

            <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
              <div className="flex items-center justify-between text-slate-400 mb-1">
                <span className="text-xs font-semibold uppercase tracking-wider">Outbound SSRF Shield</span>
                <ShieldCheck className="w-4 h-4 text-purple-400" />
              </div>
              <div className="flex items-center space-x-2">
                <span className="px-2 py-0.5 rounded text-[11px] font-bold bg-purple-950 text-purple-300 border border-purple-800">
                  STRICT ENFORCEMENT
                </span>
              </div>
              <p className="text-[11px] text-slate-500 mt-2">
                RFC 1918, Loopback, Link-Local &amp; Cloud Metadata (169.254.169.254) Blocked
              </p>
            </div>
          </div>

          {/* Test Feedback Toast / Alert Banner */}
          {testDeliveryFeedback && (
            <div
              className={`p-3.5 rounded-xl border text-xs flex items-center justify-between transition-all ${
                testDeliveryFeedback.success
                  ? 'bg-emerald-950/60 border-emerald-800/60 text-emerald-300'
                  : 'bg-amber-950/60 border-amber-800/60 text-amber-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                {testDeliveryFeedback.success ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0" />
                ) : (
                  <AlertCircle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                )}
                <span>{testDeliveryFeedback.message}</span>
              </div>
              <button
                onClick={() => setTestDeliveryFeedback(null)}
                className="text-slate-400 hover:text-white text-xs px-2 py-0.5 rounded"
              >
                Dismiss
              </button>
            </div>
          )}

          {/* Destinations Table */}
          <div className="p-5 rounded-xl border border-border bg-surface shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                  <Globe className="w-4 h-4 text-blue-400" />
                  <span>Configured Webhook Destinations</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Explicitly authorized external destinations receiving verified security events
                </p>
              </div>
              <button
                onClick={() => {
                  setDestError(null);
                  setIsAddDestModalOpen(true);
                }}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-xs font-medium transition-colors shadow-sm"
              >
                <Plus className="w-3.5 h-3.5" />
                <span>Add Destination</span>
              </button>
            </div>

            {destinations.length === 0 ? (
              <EmptyState
                icon={<Webhook className="w-8 h-8 text-slate-500" />}
                title="No Notification Destinations Configured"
                description="Add an external HTTPS webhook to deliver real-time incident, detection finding, or response plan notifications."
                actionText="Configure First Destination"
                onAction={() => setIsAddDestModalOpen(true)}
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-border/60 text-slate-400">
                      <th className="py-2.5 px-3 font-semibold">Name &amp; Status</th>
                      <th className="py-2.5 px-3 font-semibold">Target Endpoint</th>
                      <th className="py-2.5 px-3 font-semibold">Subscribed Events</th>
                      <th className="py-2.5 px-3 font-semibold">Signing</th>
                      <th className="py-2.5 px-3 font-semibold">Last Delivery</th>
                      <th className="py-2.5 px-3 text-right font-semibold">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40 text-slate-300">
                    {destinations.map((dest) => (
                      <tr key={dest.id} className="hover:bg-surface-elevated/40 transition-colors">
                        <td className="py-2.5 px-3 font-medium">
                          <div className="flex items-center space-x-2">
                            <span
                              className={`w-2 h-2 rounded-full ${
                                dest.is_enabled ? 'bg-emerald-400' : 'bg-slate-600'
                              }`}
                            />
                            <span className="text-white font-semibold">{dest.name}</span>
                          </div>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300 max-w-xs truncate">
                          {dest.destination_url}
                        </td>
                        <td className="py-2.5 px-3">
                          <div className="flex flex-wrap gap-1">
                            {dest.subscribed_events.map((ev) => (
                              <span
                                key={ev}
                                className="px-1.5 py-0.5 rounded text-[10px] bg-blue-950/80 text-blue-300 border border-blue-800/60 font-mono"
                              >
                                {ev}
                              </span>
                            ))}
                          </div>
                        </td>
                        <td className="py-2.5 px-3">
                          {dest.has_signing_secret ? (
                            <span className="inline-flex items-center space-x-1 px-1.5 py-0.5 rounded text-[10px] bg-emerald-950/80 text-emerald-300 border border-emerald-800/60 font-medium">
                              <Key className="w-3 h-3 text-emerald-400" />
                              <span>HMAC-SHA256</span>
                            </span>
                          ) : (
                            <span className="text-[10px] text-slate-500">Unsigned</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3">
                          {dest.last_delivery_status ? (
                            <div className="space-y-0.5">
                              <span
                                className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                                  dest.last_delivery_status === 'DELIVERED'
                                    ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                    : 'bg-red-950 text-red-300 border border-red-800'
                                }`}
                              >
                                {dest.last_delivery_status}
                              </span>
                              {dest.last_delivery_at && (
                                <p className="text-[10px] text-slate-500 font-mono">
                                  {new Date(dest.last_delivery_at).toLocaleTimeString()}
                                </p>
                              )}
                            </div>
                          ) : (
                            <span className="text-[10px] text-slate-500">Never</span>
                          )}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <div className="flex items-center justify-end space-x-1.5">
                            <button
                              onClick={() => handleTestDestination(dest.id)}
                              disabled={testingDestId === dest.id || !dest.is_enabled}
                              className="px-2 py-1 rounded text-[11px] font-medium bg-blue-600/80 hover:bg-blue-600 disabled:opacity-40 text-white transition-colors"
                              title="Dispatch test notification"
                            >
                              {testingDestId === dest.id ? 'Testing...' : 'Test'}
                            </button>
                            <button
                              onClick={() => handleToggleDestination(dest)}
                              className={`px-2 py-1 rounded text-[11px] font-medium transition-colors ${
                                dest.is_enabled
                                  ? 'bg-amber-950/60 text-amber-300 border border-amber-800/60 hover:bg-amber-900/60'
                                  : 'bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 hover:bg-emerald-900/60'
                              }`}
                            >
                              {dest.is_enabled ? 'Disable' : 'Enable'}
                            </button>
                            <button
                              onClick={() => handleDeleteDestination(dest.id)}
                              className="p-1 rounded text-red-400 hover:text-red-300 hover:bg-red-950/40 transition-colors"
                              title="Delete destination"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Outbound Delivery History Log */}
          <div className="p-5 rounded-xl border border-border bg-surface shadow-sm space-y-4">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-3 border-b border-border">
              <div>
                <h3 className="text-sm font-bold text-white flex items-center space-x-2">
                  <Send className="w-4 h-4 text-emerald-400" />
                  <span>Outbound Delivery Telemetry Log</span>
                </h3>
                <p className="text-xs text-slate-400">
                  Durable delivery lifecycle receipts, latency metrics, and bounded retry records
                </p>
              </div>

              <div className="flex items-center space-x-2">
                <span className="text-xs text-slate-400">Filter Status:</span>
                <select
                  value={deliveryFilterStatus}
                  onChange={(e) => {
                    setDeliveryFilterStatus(e.target.value);
                    loadData();
                  }}
                  className="rounded-lg bg-surface-elevated border border-border px-2.5 py-1 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  <option value="ALL">All Outcomes</option>
                  <option value="DELIVERED">Delivered</option>
                  <option value="RETRY_SCHEDULED">Retry Scheduled</option>
                  <option value="PENDING">Pending</option>
                  <option value="PERMANENTLY_FAILED">Permanently Failed</option>
                </select>

                <button
                  onClick={handleDispatchDeliveries}
                  disabled={isDispatchingDeliveries}
                  className="px-2.5 py-1 rounded-lg text-xs font-semibold bg-emerald-950/80 border border-emerald-700 hover:bg-emerald-900 text-emerald-200 transition-colors flex items-center space-x-1 disabled:opacity-50"
                  title="Process pending and due retry outbound notification deliveries immediately"
                >
                  <Send className="w-3 h-3 text-emerald-400" />
                  <span>{isDispatchingDeliveries ? 'Dispatching...' : 'Dispatch Pending'}</span>
                </button>
              </div>
            </div>

            {deliveries.length === 0 ? (
              <EmptyState
                icon={<Clock className="w-8 h-8 text-slate-500" />}
                title="No Notification Deliveries Recorded"
                description="When subscribed security incidents or response plan transitions occur, delivery receipts and HMAC verification metrics will appear here."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="border-b border-border/60 text-slate-400">
                      <th className="py-2.5 px-3 font-semibold">Delivery ID</th>
                      <th className="py-2.5 px-3 font-semibold">Event Type</th>
                      <th className="py-2.5 px-3 font-semibold">Destination</th>
                      <th className="py-2.5 px-3 font-semibold">Status</th>
                      <th className="py-2.5 px-3 font-semibold">Latency</th>
                      <th className="py-2.5 px-3 font-semibold">Attempts</th>
                      <th className="py-2.5 px-3 font-semibold">Timestamp</th>
                      <th className="py-2.5 px-3 text-right font-semibold">Details / Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/40 text-slate-300">
                    {deliveries.map((del) => (
                      <tr key={del.id} className="hover:bg-surface-elevated/40 transition-colors">
                        <td className="py-2.5 px-3 font-mono text-[11px] text-slate-300">
                          <div className="flex items-center space-x-1">
                            <span>{del.delivery_id.substring(0, 8)}...</span>
                            <button
                              onClick={() => copyToClipboard(del.delivery_id, del.delivery_id)}
                              className="text-slate-500 hover:text-slate-300"
                              title="Copy Full Delivery ID"
                            >
                              {copiedKey === del.delivery_id ? (
                                <Check className="w-3 h-3 text-emerald-400" />
                              ) : (
                                <Copy className="w-3 h-3" />
                              )}
                            </button>
                          </div>
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="px-1.5 py-0.5 rounded text-[10px] bg-surface-elevated border border-border/60 font-mono text-slate-300">
                            {del.event_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-medium text-slate-200">
                          {del.destination_name || 'Webhook Destination'}
                        </td>
                        <td className="py-2.5 px-3">
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              del.status === 'DELIVERED'
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                                : del.status === 'RETRY_SCHEDULED'
                                ? 'bg-amber-950 text-amber-300 border border-amber-800'
                                : del.status === 'PENDING' || del.status === 'DELIVERING'
                                ? 'bg-blue-950 text-blue-300 border border-blue-800'
                                : 'bg-red-950 text-red-300 border border-red-800'
                            }`}
                          >
                            {del.status}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px]">
                          {del.response_time_ms !== null && del.response_time_ms !== undefined
                            ? `${del.response_time_ms}ms`
                            : '-'}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[11px]">
                          {del.attempt_count} / {del.max_attempts}
                        </td>
                        <td className="py-2.5 px-3 font-mono text-[10px] text-slate-400">
                          {new Date(del.created_at).toLocaleTimeString()}
                        </td>
                        <td className="py-2.5 px-3 text-right">
                          <div className="flex items-center justify-end space-x-1.5">
                            <button
                              onClick={() =>
                                setInspectItem({
                                  title: `Notification Delivery: ${del.event_type}`,
                                  data: {
                                    delivery_id: del.delivery_id,
                                    event_type: del.event_type,
                                    event_id: del.event_id,
                                    status: del.status,
                                    status_code: del.response_status_code,
                                    response_time_ms: del.response_time_ms,
                                    error_message: del.error_message,
                                    payload: del.payload,
                                    created_at: del.created_at,
                                    delivered_at: del.delivered_at,
                                  },
                                })
                              }
                              className="p-1 rounded hover:bg-surface-elevated text-slate-400 hover:text-slate-200"
                              title="Inspect Payload"
                            >
                              <Eye className="w-3.5 h-3.5" />
                            </button>

                            {(del.status === 'FAILED' ||
                              del.status === 'PERMANENTLY_FAILED' ||
                              del.status === 'RETRY_SCHEDULED') && (
                              <button
                                onClick={() => handleRetryDelivery(del.id)}
                                disabled={retryingDeliveryId === del.id}
                                className="px-2 py-0.5 rounded text-[10px] font-medium bg-surface-elevated border border-border hover:bg-surface text-slate-200 transition-colors"
                                title="Manually Retry Delivery"
                              >
                                {retryingDeliveryId === del.id ? 'Retrying...' : 'Retry'}
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )}

      {/* ==================================================================== */}
      {/* MODAL: ADD NOTIFICATION DESTINATION                                  */}
      {/* ==================================================================== */}
      {isAddDestModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2 text-blue-400">
                <Webhook className="w-5 h-5" />
                <h3 className="text-sm font-bold text-white">Configure Outbound Webhook</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsAddDestModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateDestination} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 block">
                  Destination Name <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={newDestName}
                  onChange={(e) => setNewDestName(e.target.value)}
                  placeholder="e.g. Enterprise SIEM / Discord SOC / PagerDuty"
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 block">
                  Destination URL <span className="text-red-400">*</span>
                </label>
                <input
                  type="url"
                  required
                  value={newDestUrl}
                  onChange={(e) => setNewDestUrl(e.target.value)}
                  placeholder="https://siem.enterprise.gov.et/alerts"
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
                />
                <p className="text-[10px] text-slate-500">
                  Strict HTTPS enforced. Internal subnets, loopback, and cloud metadata (169.254.169.254) are rejected.
                </p>
              </div>

              <div className="space-y-1.5">
                <label className="text-xs font-semibold text-slate-300 block">
                  Subscribed Security Events <span className="text-red-400">*</span>
                </label>
                <div className="space-y-1.5 p-3 rounded-lg bg-surface-elevated border border-border text-xs">
                  {[
                    { id: 'INCIDENT_CREATED', label: 'New Security Incident Spawned' },
                    { id: 'INCIDENT_STATUS_CHANGED', label: 'Incident Status Transition (Contained, Closed)' },
                    { id: 'DETECTION_FINDING_CREATED', label: 'High-Confidence Detection Rule Finding' },
                    { id: 'THREAT_INTEL_MATCHED', label: 'Active Threat Intelligence Observable Match' },
                    { id: 'RESPONSE_PLAN_STATE_CHANGED', label: 'Governed Response Plan Lifecycle State Change' },
                  ].map((ev) => (
                    <label key={ev.id} className="flex items-center space-x-2 cursor-pointer text-slate-300">
                      <input
                        type="checkbox"
                        checked={newDestEvents.includes(ev.id)}
                        onChange={(e) => {
                          if (e.target.checked) {
                            setNewDestEvents([...newDestEvents, ev.id]);
                          } else {
                            setNewDestEvents(newDestEvents.filter((id) => id !== ev.id));
                          }
                        }}
                        className="rounded border-border bg-slate-900 text-blue-600 focus:ring-0"
                      />
                      <span>{ev.label}</span>
                    </label>
                  ))}
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 block">
                  HMAC-SHA256 Signing Secret <span className="text-slate-500">(Optional)</span>
                </label>
                <input
                  type="password"
                  value={newDestSecret}
                  onChange={(e) => setNewDestSecret(e.target.value)}
                  placeholder="Enter shared secret for X-Waliya-Signature verification..."
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
                />
                <p className="text-[10px] text-slate-500">
                  Encrypted at rest with platform master key. Never displayed or logged in plaintext.
                </p>
              </div>

              {destError && (
                <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-300 text-xs flex items-center space-x-1.5">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{destError}</span>
                </div>
              )}

              <div className="flex justify-end space-x-2 pt-2 border-t border-border">
                <button
                  type="button"
                  onClick={() => setIsAddDestModalOpen(false)}
                  className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={destSubmitting || newDestEvents.length === 0}
                  className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition-colors shadow-sm"
                >
                  {destSubmitting ? 'Validating &amp; Saving...' : 'Save Destination'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: ADD INBOUND SECURITY EVENT SOURCE                             */}
      {/* ==================================================================== */}
      {isAddSourceModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2 text-blue-400">
                <Server className="w-5 h-5" />
                <h3 className="text-sm font-bold text-white">Register Inbound Event Source</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsAddSourceModalOpen(false)}
                className="text-slate-400 hover:text-white text-xs"
              >
                Cancel
              </button>
            </div>

            <form onSubmit={handleCreateSource} className="space-y-4">
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 block">
                  Source Name <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={newSourceName}
                  onChange={(e) => setNewSourceName(e.target.value)}
                  placeholder="e.g. Enterprise CrowdStrike Falcon / AWS GuardDuty / Splunk"
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-300 block">
                    Source Identifier (Slug) <span className="text-red-400">*</span>
                  </label>
                  <input
                    type="text"
                    required
                    pattern="^[a-zA-Z0-9_-]+$"
                    value={newSourceSlug}
                    onChange={(e) => setNewSourceSlug(e.target.value)}
                    placeholder="crowdstrike-edr-prod"
                    className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
                  />
                  <p className="text-[10px] text-slate-500">
                    Route: /api/v1/integrations/inbound/&lt;slug&gt;/events
                  </p>
                </div>

                <div className="space-y-1">
                  <label className="text-xs font-semibold text-slate-300 block">
                    Provider Profile <span className="text-red-400">*</span>
                  </label>
                  <select
                    value={newSourceProvider}
                    onChange={(e) => setNewSourceProvider(e.target.value as 'GENERIC' | 'EDR' | 'SIEM')}
                    className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500 font-mono"
                  >
                    <option value="GENERIC">GENERIC (Waliya Standard)</option>
                    <option value="EDR">EDR (Endpoint Detection Profile)</option>
                    <option value="SIEM">SIEM (Log & Alert Profile)</option>
                  </select>
                  <p className="text-[10px] text-slate-500">
                    Normalized mapping schema
                  </p>
                </div>
              </div>

              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 block">
                  Permitted Event Types <span className="text-slate-500">(Comma-separated, or * for all)</span>
                </label>
                <input
                  type="text"
                  value={newSourcePermitted}
                  onChange={(e) => setNewSourcePermitted(e.target.value)}
                  placeholder="*, EXTERNAL_ALERT, PROCESS_EXECUTION, NETWORK_CONNECTION"
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-semibold text-slate-300 block">
                    HMAC-SHA256 Shared Secret <span className="text-red-400">*</span>
                  </label>
                  <button
                    type="button"
                    onClick={handleGenerateSourceSecret}
                    className="text-[11px] text-blue-400 hover:text-blue-300 underline font-medium"
                  >
                    Generate Strong Secret
                  </button>
                </div>
                <input
                  type="text"
                  required
                  minLength={16}
                  value={newSourceSecret}
                  onChange={(e) => setNewSourceSecret(e.target.value)}
                  placeholder="Minimum 16 characters secret for cryptographic signature..."
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 font-mono focus:outline-none focus:border-blue-500"
                />
                <p className="text-[10px] text-amber-400/90 flex items-center space-x-1 mt-1">
                  <AlertCircle className="w-3 h-3 flex-shrink-0" />
                  <span>This secret will be encrypted with Fernet and never displayed again in plaintext. Copy it now.</span>
                </p>
              </div>

              {sourceError && (
                <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-300 text-xs flex items-center space-x-1.5">
                  <AlertCircle className="w-4 h-4 flex-shrink-0" />
                  <span>{sourceError}</span>
                </div>
              )}

              <div className="flex justify-end space-x-2 pt-2 border-t border-border">
                <button
                  type="button"
                  onClick={() => setIsAddSourceModalOpen(false)}
                  className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={sourceSubmitting || !newSourceSecret.trim() || newSourceSecret.length < 16}
                  className="px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition-colors shadow-sm"
                >
                  {sourceSubmitting ? 'Registering Source...' : 'Register Source'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: INBOUND INGESTION GUIDE & PAYLOAD PREVIEW                     */}
      {/* ==================================================================== */}
      {selectedGuideSource && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2 text-blue-400">
                <Terminal className="w-5 h-5" />
                <div>
                  <h3 className="text-sm font-bold text-white">
                    Integration Guide: {selectedGuideSource.name}
                  </h3>
                  <p className="text-[10px] text-slate-400 font-mono">
                    Provider: {selectedGuideSource.provider_type} · Slug: {selectedGuideSource.source_id}
                  </p>
                </div>
              </div>
              <button
                type="button"
                onClick={() => setSelectedGuideSource(null)}
                className="text-slate-400 hover:text-white text-xs"
              >
                Close
              </button>
            </div>

            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-400 font-semibold block mb-1">Target Endpoint:</span>
                <div className="flex items-center space-x-2 bg-surface-elevated p-2 rounded-lg border border-border font-mono text-[11px] text-blue-300">
                  <span className="font-bold text-emerald-400">POST</span>
                  <span>/api/v1/integrations/inbound/{selectedGuideSource.source_id}/events</span>
                </div>
              </div>

              <div>
                <span className="text-slate-400 font-semibold block mb-1">Required Request Headers:</span>
                <div className="bg-surface-elevated p-3 rounded-lg border border-border font-mono text-[11px] text-slate-300 space-y-1">
                  <div><strong className="text-white">Content-Type:</strong> application/json</div>
                  <div><strong className="text-white">X-Waliya-Source-Id:</strong> {selectedGuideSource.source_id}</div>
                  <div><strong className="text-white">X-Waliya-Timestamp:</strong> &lt;ISO-8601 UTC timestamp, max 300s drift&gt;</div>
                  <div><strong className="text-white">X-Waliya-Signature:</strong> &lt;HMAC-SHA256 hex digest of raw request body&gt;</div>
                </div>
              </div>

              <div>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-slate-400 font-semibold">Example curl Submission:</span>
                  <button
                    type="button"
                    onClick={() =>
                      copyToClipboard(
                        `PAYLOAD='{"schema_version":"1.0","external_event_id":"ext-evt-1001","event_type":"EXTERNAL_ALERT","severity":"HIGH","title":"Malicious Process Detected","attributes":{"src_ip":"203.0.113.45","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}'
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SECRET="<YOUR_SHARED_SECRET>"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)

curl -X POST "http://localhost:8000/api/v1/integrations/inbound/${selectedGuideSource.source_id}/events" \\
  -H "Content-Type: application/json" \\
  -H "X-Waliya-Source-Id: ${selectedGuideSource.source_id}" \\
  -H "X-Waliya-Timestamp: $TIMESTAMP" \\
  -H "X-Waliya-Signature: $SIGNATURE" \\
  -d "$PAYLOAD"`,
                        'guide-curl'
                      )
                    }
                    className="text-[11px] text-blue-400 hover:text-white flex items-center space-x-1"
                  >
                    {copiedKey === 'guide-curl' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedKey === 'guide-curl' ? 'Copied' : 'Copy Bash Script'}</span>
                  </button>
                </div>

                <pre className="bg-slate-950 p-3 rounded-lg border border-border text-[11px] font-mono text-slate-300 overflow-x-auto whitespace-pre">
{`# 1. Prepare external event payload
PAYLOAD='{"schema_version":"1.0","external_event_id":"ext-evt-1001","event_type":"EXTERNAL_ALERT","severity":"HIGH","title":"Malicious Process Detected","attributes":{"src_ip":"203.0.113.45","sha256":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}'

# 2. Generate ISO 8601 UTC timestamp and compute HMAC-SHA256 signature
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
SECRET="<YOUR_SHARED_SECRET>"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)

# 3. Submit to Waliya-IR
curl -X POST "http://localhost:8000/api/v1/integrations/inbound/${selectedGuideSource.source_id}/events" \\
  -H "Content-Type: application/json" \\
  -H "X-Waliya-Source-Id: ${selectedGuideSource.source_id}" \\
  -H "X-Waliya-Timestamp: $TIMESTAMP" \\
  -H "X-Waliya-Signature: $SIGNATURE" \\
  -d "$PAYLOAD"`}
                </pre>
              </div>

              <div className="p-3 rounded-lg bg-surface-elevated border border-border">
                <span className="text-slate-400 font-semibold block mb-1">Idempotency & Deduplication:</span>
                <p className="text-[11px] text-slate-300">
                  Submissions with identical <code className="text-blue-300 font-mono">external_event_id</code> from this source are durably deduplicated in PostgreSQL without creating duplicate events or re-triggering correlation passes.
                </p>
              </div>
            </div>

            <div className="flex justify-end pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setSelectedGuideSource(null)}
                className="px-3 py-1.5 rounded-lg bg-surface-elevated hover:bg-surface border border-border text-slate-300 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}


      {/* ==================================================================== */}
      {/* MODAL: APPROVE ACTION                                                */}
      {/* ==================================================================== */}
      {approvingAction && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-emerald-800/80 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center space-x-2 text-emerald-400">
              <CheckCircle2 className="w-5 h-5" />
              <h3 className="text-sm font-bold text-white">Authorize Response Action</h3>
            </div>

            <div className="p-3 rounded-lg bg-surface-elevated border border-border text-xs space-y-1.5">
              <div className="flex justify-between">
                <span className="text-slate-400">Action:</span>
                <span className="font-mono font-bold text-blue-400">{approvingAction.action}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target Host:</span>
                <span className="font-mono text-slate-200">{approvingAction.agent?.hostname || 'Unknown'}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Linked Incident:</span>
                <span className="text-slate-200">#{approvingAction.incident?.incident_number || 0}</span>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-800/40 text-[11px] text-emerald-300 flex items-start space-x-2">
              <ShieldCheck className="w-4 h-4 flex-shrink-0 mt-0.5 text-emerald-400" />
              <div>
                <strong>Cryptographic Signing Note:</strong> Approving will immediately generate an HMAC-SHA256 signed envelope and queue it for dispatch to the target agent. An immutable entry will be chained to the audit ledger.
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300 block">
                Authorization Justification / Reason <span className="text-red-400">*</span>
              </label>
              <textarea
                value={approvalReason}
                onChange={(e) => setApprovalReason(e.target.value)}
                placeholder="State the technical reason for authorizing containment on this asset (min 3 chars)..."
                rows={3}
                className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-emerald-500"
              />
            </div>

            {decisionError && (
              <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-300 text-xs">
                {decisionError}
              </div>
            )}

            <div className="flex items-center justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setApprovingAction(null)}
                disabled={submittingDecision}
                className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleApproveAction}
                disabled={approvalReason.trim().length < 3 || submittingDecision}
                className="px-4 py-1.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 disabled:opacity-50 text-white text-xs font-medium transition-colors flex items-center space-x-1.5"
              >
                {submittingDecision && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>Authorize & Sign</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: REJECT ACTION                                                 */}
      {/* ==================================================================== */}
      {rejectingAction && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-red-800/80 rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center space-x-2 text-red-400">
              <XCircle className="w-5 h-5" />
              <h3 className="text-sm font-bold text-white">Reject Response Action</h3>
            </div>

            <div className="p-3 rounded-lg bg-surface-elevated border border-border text-xs space-y-1.5">
              <div className="flex justify-between">
                <span className="text-slate-400">Action:</span>
                <span className="font-mono font-bold text-red-400">{rejectingAction.action}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Target Host:</span>
                <span className="font-mono text-slate-200">{rejectingAction.agent?.hostname || 'Unknown'}</span>
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold text-slate-300 block">
                Rejection Reason <span className="text-red-400">*</span>
              </label>
              <textarea
                value={approvalReason}
                onChange={(e) => setApprovalReason(e.target.value)}
                placeholder="State the reason this action was deemed unnecessary or risky..."
                rows={3}
                className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-red-500"
              />
            </div>

            {decisionError && (
              <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-300 text-xs">
                {decisionError}
              </div>
            )}

            <div className="flex items-center justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setRejectingAction(null)}
                disabled={submittingDecision}
                className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handleRejectAction}
                disabled={approvalReason.trim().length < 3 || submittingDecision}
                className="px-4 py-1.5 rounded-lg bg-red-700 hover:bg-red-600 disabled:opacity-50 text-white text-xs font-medium transition-colors flex items-center space-x-1.5"
              >
                {submittingDecision && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>Confirm Rejection</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: TRIGGER PLAYBOOK                                              */}
      {/* ==================================================================== */}
      {isTriggerModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <form
            onSubmit={handleExecutePlaybook}
            className="bg-surface border border-border rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl"
          >
            <div className="flex items-center space-x-2 text-purple-400">
              <Play className="w-5 h-5" />
              <h3 className="text-sm font-bold text-white">Trigger SOAR Response Workflow</h3>
            </div>

            <div className="space-y-3 text-xs">
              {/* Playbook Select */}
              <div className="space-y-1">
                <label className="text-slate-300 font-semibold block">Select Playbook</label>
                <select
                  value={selectedPlaybookId}
                  onChange={(e) => setSelectedPlaybookId(e.target.value)}
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-purple-500"
                >
                  {playbooks.map((pb) => (
                    <option key={pb.playbook_id} value={pb.playbook_id}>
                      {pb.name} ({pb.requires_approval ? 'Approval Gate' : 'Auto'})
                    </option>
                  ))}
                </select>
              </div>

              {/* Target Incident Select */}
              <div className="space-y-1">
                <label className="text-slate-300 font-semibold block">Target Incident</label>
                {incidents.length > 0 ? (
                  <select
                    value={selectedIncidentId}
                    onChange={(e) => setSelectedIncidentId(e.target.value)}
                    className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-purple-500"
                  >
                    {incidents.map((inc) => (
                      <option key={inc.incident_id} value={inc.incident_id}>
                        #{inc.incident_number}: {inc.title} ({inc.severity})
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    value={selectedIncidentId}
                    onChange={(e) => setSelectedIncidentId(e.target.value)}
                    placeholder="Enter target Incident UUID..."
                    className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-slate-200 text-xs font-mono"
                  />
                )}
              </div>

              {/* Target Agent Select */}
              <div className="space-y-1">
                <label className="text-slate-300 font-semibold block">Target Endpoint Agent</label>
                {agents.length > 0 ? (
                  <select
                    value={selectedAgentId}
                    onChange={(e) => setSelectedAgentId(e.target.value)}
                    className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-slate-200 text-xs focus:outline-none focus:border-purple-500"
                  >
                    {agents.map((ag) => (
                      <option key={ag.id} value={ag.id}>
                        {ag.hostname} ({ag.primary_ip}) &bull; {ag.status}
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="text"
                    value={selectedAgentId}
                    onChange={(e) => setSelectedAgentId(e.target.value)}
                    placeholder="Enter target Agent UUID..."
                    className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-slate-200 text-xs font-mono"
                  />
                )}
              </div>

              {/* Dry-run Toggle */}
              <div className="p-3 rounded-lg border border-border bg-surface-elevated space-y-2">
                <label className="flex items-center space-x-2 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={dryRunMode}
                    onChange={(e) => setDryRunMode(e.target.checked)}
                    className="rounded border-slate-700 text-blue-600 focus:ring-0 focus:ring-offset-0 w-4 h-4 bg-surface"
                  />
                  <span className="font-semibold text-slate-200 text-xs">
                    Dry-Run Simulation Mode (Default & Recommended)
                  </span>
                </label>
                <p className="text-[11px] text-slate-400 pl-6">
                  {dryRunMode
                    ? 'Safe execution: steps will be simulated, recorded in audit logs, and verified without making live alterations to the target operating system.'
                    : 'LIVE ENFORCEMENT: Response commands will be cryptographically signed and dispatched for real-time execution on the endpoint.'}
                </p>
              </div>
            </div>

            {triggerError && (
              <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-300 text-xs">
                {triggerError}
              </div>
            )}

            <div className="flex items-center justify-end space-x-2 pt-2">
              <button
                type="button"
                onClick={() => setIsTriggerModalOpen(false)}
                disabled={triggerSubmitting}
                className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={triggerSubmitting}
                className="px-4 py-1.5 rounded-lg bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs font-medium transition-colors flex items-center space-x-1.5"
              >
                {triggerSubmitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>Launch Workflow</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: DETAIL / JSON INSPECTOR                                       */}
      {/* ==================================================================== */}
      {inspectItem && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <h3 className="text-sm font-bold text-white truncate max-w-md">
                {inspectItem.title}
              </h3>
              <button
                onClick={() => setInspectItem(null)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <div className="relative">
              <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 max-h-96 overflow-y-auto whitespace-pre-wrap break-all">
                {JSON.stringify(inspectItem.data, null, 2)}
              </pre>
              <button
                onClick={() => copyToClipboard(JSON.stringify(inspectItem.data, null, 2), 'modal-copy')}
                className="absolute top-2 right-2 p-1.5 rounded bg-surface hover:bg-surface-elevated border border-border text-slate-300 text-xs flex items-center space-x-1 shadow"
              >
                {copiedKey === 'modal-copy' ? (
                  <>
                    <Check className="w-3 h-3 text-emerald-400" />
                    <span className="text-[10px] text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3 h-3" />
                    <span className="text-[10px]">Copy JSON</span>
                  </>
                )}
              </button>
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                onClick={() => setInspectItem(null)}
                className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: CREATE RESPONSE PLAN                                          */}
      {/* ==================================================================== */}
      {isPlanModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <form
            onSubmit={handleCreatePlan}
            className="bg-surface border border-border rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl max-h-[90vh] overflow-y-auto"
          >
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2 text-white">
                <Plus className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-bold">Create Governed Response Plan</h3>
              </div>
              <button
                type="button"
                onClick={() => setIsPlanModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            {createPlanError && (
              <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-300 text-xs flex items-center space-x-1.5">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{createPlanError}</span>
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Target Incident <span className="text-red-400">*</span>
                </label>
                <select
                  value={newPlanIncidentId}
                  onChange={(e) => setNewPlanIncidentId(e.target.value)}
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-blue-500"
                >
                  {incidents.map((inc) => (
                    <option key={inc.incident_id} value={inc.incident_id}>
                      INC-#{String(inc.incident_number).padStart(4, '0')}: {inc.title}
                    </option>
                  ))}
                </select>
              </div>

              <div>
                <label className="text-xs font-semibold text-slate-300 block mb-1">
                  Plan Title <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  value={newPlanTitle}
                  onChange={(e) => setNewPlanTitle(e.target.value)}
                  placeholder="e.g. Contain compromised web host & isolate"
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                  required
                />
              </div>
            </div>

            <div>
              <label className="text-xs font-semibold text-slate-300 block mb-1">
                Plan Description
              </label>
              <textarea
                value={newPlanDescription}
                onChange={(e) => setNewPlanDescription(e.target.value)}
                placeholder="Operational purpose and scope of this response plan..."
                rows={2}
                className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
              />
            </div>

            {/* Actions builder */}
            <div className="space-y-3 pt-2 border-t border-border/60">
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-300">
                  Response Actions Sequence ({newPlanActions.length})
                </span>
                <button
                  type="button"
                  onClick={() =>
                    setNewPlanActions([
                      ...newPlanActions,
                      {
                        action: actionRegistry[0]?.action_type || 'COLLECT_FORENSIC_ARTIFACT',
                        agent_id: agents[0]?.id || '',
                        parameters: '{}',
                        requires_approval: true,
                        description: '',
                      },
                    ])
                  }
                  className="flex items-center space-x-1 px-2 py-1 rounded bg-surface-elevated hover:bg-slate-700 text-blue-400 text-xs font-medium"
                >
                  <Plus className="w-3 h-3" />
                  <span>Add Action</span>
                </button>
              </div>

              <div className="space-y-3">
                {newPlanActions.map((act, idx) => (
                  <div
                    key={idx}
                    className="p-3 rounded-lg bg-surface-elevated border border-border space-y-2 relative"
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-mono font-bold text-slate-400">Step #{idx + 1}</span>
                      {newPlanActions.length > 1 && (
                        <button
                          type="button"
                          onClick={() => setNewPlanActions(newPlanActions.filter((_, i) => i !== idx))}
                          className="text-slate-500 hover:text-red-400 p-0.5 rounded"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      )}
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                      <div>
                        <label className="text-[11px] text-slate-400 block mb-0.5">Action Type</label>
                        <select
                          value={act.action}
                          onChange={(e) => {
                            const val = e.target.value;
                            const regMeta = actionRegistry.find((r) => r.action_type === val);
                            const updated = [...newPlanActions];
                            updated[idx].action = val;
                            if (regMeta) {
                              updated[idx].requires_approval = regMeta.default_requires_approval;
                            }
                            setNewPlanActions(updated);
                          }}
                          className="w-full rounded bg-surface border border-border px-2 py-1 text-xs text-slate-200 focus:outline-none"
                        >
                          {actionRegistry.map((reg) => (
                            <option key={reg.action_type} value={reg.action_type}>
                              {reg.action_type} ({reg.risk_classification})
                            </option>
                          ))}
                        </select>
                      </div>

                      <div>
                        <label className="text-[11px] text-slate-400 block mb-0.5">Target Agent</label>
                        <select
                          value={act.agent_id}
                          onChange={(e) => {
                            const updated = [...newPlanActions];
                            updated[idx].agent_id = e.target.value;
                            setNewPlanActions(updated);
                          }}
                          className="w-full rounded bg-surface border border-border px-2 py-1 text-xs text-slate-200 focus:outline-none"
                        >
                          {agents.map((ag) => (
                            <option key={ag.id} value={ag.id}>
                              {ag.hostname} ({ag.primary_ip})
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    <div>
                      <label className="text-[11px] text-slate-400 block mb-0.5">Parameters (JSON)</label>
                      <input
                        type="text"
                        value={act.parameters}
                        onChange={(e) => {
                          const updated = [...newPlanActions];
                          updated[idx].parameters = e.target.value;
                          setNewPlanActions(updated);
                        }}
                        placeholder='{"ip_address": "198.51.100.4"}'
                        className="w-full font-mono rounded bg-surface border border-border px-2 py-1 text-xs text-slate-200 focus:outline-none"
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Options */}
            <div className="flex flex-wrap items-center gap-4 pt-2 border-t border-border/60">
              <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={newPlanDryRun}
                  onChange={(e) => setNewPlanDryRun(e.target.checked)}
                  className="rounded border-border text-blue-600 focus:ring-0"
                />
                <span>Default to Dry-Run Mode (Recommended)</span>
              </label>

              <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer">
                <input
                  type="checkbox"
                  checked={newPlanSubmitImmediate}
                  onChange={(e) => setNewPlanSubmitImmediate(e.target.checked)}
                  className="rounded border-border text-blue-600 focus:ring-0"
                />
                <span>Submit Immediately for Security Approval</span>
              </label>
            </div>

            <div className="flex items-center justify-end space-x-2 pt-3 border-t border-border">
              <button
                type="button"
                onClick={() => setIsPlanModalOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={createPlanSubmitting || !newPlanTitle.trim()}
                className="px-4 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-medium transition-colors flex items-center space-x-1.5 shadow-sm"
              >
                {createPlanSubmitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>Create Response Plan</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: PLAN DECISION (APPROVE / REJECT / CANCEL / EXECUTE)            */}
      {/* ==================================================================== */}
      {planDecisionModal && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-lg w-full p-5 space-y-4 shadow-2xl">
            <div className="flex items-center space-x-2">
              {planDecisionModal.action === 'approve' && (
                <>
                  <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  <h3 className="text-sm font-bold text-emerald-400">Authorize Response Plan</h3>
                </>
              )}
              {planDecisionModal.action === 'reject' && (
                <>
                  <XCircle className="w-5 h-5 text-red-400" />
                  <h3 className="text-sm font-bold text-red-400">Reject Response Plan</h3>
                </>
              )}
              {planDecisionModal.action === 'cancel' && (
                <>
                  <XCircle className="w-5 h-5 text-slate-400" />
                  <h3 className="text-sm font-bold text-slate-200">Cancel Response Plan</h3>
                </>
              )}
              {planDecisionModal.action === 'execute' && (
                <>
                  <Play className="w-5 h-5 text-blue-400" />
                  <h3 className="text-sm font-bold text-blue-400">Execute Approved Plan</h3>
                </>
              )}
              {planDecisionModal.action === 'reconcile' && (
                <>
                  <AlertTriangle className="w-5 h-5 text-amber-400" />
                  <h3 className="text-sm font-bold text-amber-400">Reconcile Interrupted Plan</h3>
                </>
              )}
            </div>

            <div className="p-3 rounded-lg bg-surface-elevated border border-border text-xs space-y-1.5">
              <div className="flex justify-between">
                <span className="text-slate-400">Plan:</span>
                <span className="font-semibold text-slate-200">
                  PLAN-#{String(planDecisionModal.plan.plan_number).padStart(4, '0')} - {planDecisionModal.plan.title}
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Risk Classification:</span>
                {getPlanRiskBadge(planDecisionModal.plan.risk_level)}
              </div>
              <div className="flex justify-between">
                <span className="text-slate-400">Actions Count:</span>
                <span className="text-slate-200">{planDecisionModal.plan.actions.length} allowlisted steps</span>
              </div>
              {planDecisionModal.plan.approval_hash && (
                <div className="flex justify-between font-mono text-[10px]">
                  <span className="text-slate-400">Approval Hash:</span>
                  <span className="text-emerald-400">{planDecisionModal.plan.approval_hash.slice(0, 16)}...</span>
                </div>
              )}
            </div>

            {planDecisionModal.action === 'execute' ? (
              <div className="space-y-3">
                <div className="p-3 rounded-lg bg-blue-950/40 border border-blue-800/40 text-xs text-blue-200 space-y-1">
                  <div className="font-semibold flex items-center space-x-1.5">
                    <ShieldCheck className="w-4 h-4 text-blue-400" />
                    <span>Cryptographic Integrity & Signed Dispatch</span>
                  </div>
                  <p className="text-[11px] text-blue-300">
                    Executing this plan will verify that the actions match the approval hash, compute HMAC-SHA256 signatures for each command, and dispatch them to the target agents with tamper-evident audit logging.
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-surface-elevated border border-border text-xs">
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={planDecisionDryRun}
                      disabled={planDecisionModal.plan.is_simulation}
                      onChange={(e) => setPlanDecisionDryRun(e.target.checked)}
                      className="rounded border-border text-blue-600 focus:ring-0"
                    />
                    <span>
                      Dry-Run Mode{' '}
                      {planDecisionModal.plan.is_simulation && '(Forced: synthetic simulation incident)'}
                    </span>
                  </label>
                </div>
              </div>
            ) : (
              <div className="space-y-1">
                <label className="text-xs font-semibold text-slate-300 block">
                  Mandatory Justification / Reason <span className="text-red-400">*</span>
                </label>
                <textarea
                  value={planDecisionReason}
                  onChange={(e) => setPlanDecisionReason(e.target.value)}
                  placeholder={`State the operational reason for ${planDecisionModal.action}ing this plan...`}
                  rows={3}
                  className="w-full rounded-lg bg-surface-elevated border border-border px-3 py-2 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-blue-500"
                />
              </div>
            )}

            {planDecisionError && (
              <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-300 text-xs flex items-center space-x-1.5">
                <AlertCircle className="w-4 h-4 flex-shrink-0" />
                <span>{planDecisionError}</span>
              </div>
            )}

            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setPlanDecisionModal(null)}
                disabled={planDecisionSubmitting}
                className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={handlePlanDecisionSubmit}
                disabled={
                  planDecisionSubmitting ||
                  (planDecisionModal.action !== 'execute' && planDecisionReason.trim().length < 3)
                }
                className={`px-4 py-1.5 rounded-lg text-white text-xs font-medium transition-colors flex items-center space-x-1.5 shadow-sm ${
                  planDecisionModal.action === 'approve'
                    ? 'bg-emerald-600 hover:bg-emerald-500'
                    : planDecisionModal.action === 'reject'
                    ? 'bg-red-700 hover:bg-red-600'
                    : planDecisionModal.action === 'execute'
                    ? 'bg-blue-600 hover:bg-blue-500'
                    : planDecisionModal.action === 'reconcile'
                    ? 'bg-amber-700 hover:bg-amber-600'
                    : 'bg-slate-700 hover:bg-slate-600'
                }`}
              >
                {planDecisionSubmitting && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
                <span>
                  {planDecisionModal.action === 'approve' && 'Authorize Plan'}
                  {planDecisionModal.action === 'reject' && 'Reject Plan'}
                  {planDecisionModal.action === 'cancel' && 'Confirm Cancellation'}
                  {planDecisionModal.action === 'execute' && 'Execute Plan Now'}
                  {planDecisionModal.action === 'reconcile' && 'Reconcile Plan'}
                </span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: ALLOWLISTED ACTION REGISTRY                                   */}
      {/* ==================================================================== */}
      {isRegistryModalOpen && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-4xl w-full p-5 space-y-4 shadow-2xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2">
                <Sliders className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-bold text-white">
                  Allowlisted Response Action Registry
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setIsRegistryModalOpen(false)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-slate-400 font-semibold bg-surface-elevated">
                    <th className="py-2 px-3">Action Type</th>
                    <th className="py-2 px-3">Risk Classification</th>
                    <th className="py-2 px-3">Approval Mandate</th>
                    <th className="py-2 px-3">Timeout / Retries</th>
                    <th className="py-2 px-3">Reversible</th>
                    <th className="py-2 px-3">Parameters</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40 font-mono text-[11px]">
                  {actionRegistry.map((reg) => (
                    <tr key={reg.action_type} className="hover:bg-surface-elevated/50">
                      <td className="py-2.5 px-3 font-bold text-slate-200">{reg.action_type}</td>
                      <td className="py-2.5 px-3">{getPlanRiskBadge(reg.risk_classification)}</td>
                      <td className="py-2.5 px-3">
                        {reg.default_requires_approval ? (
                          <span className="text-amber-400 font-semibold">Mandatory</span>
                        ) : (
                          <span className="text-slate-400">Pre-approved</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-slate-300">
                        {reg.default_timeout_seconds}s (max {reg.max_retries} retries)
                      </td>
                      <td className="py-2.5 px-3">
                        {reg.is_reversible ? (
                          <span className="text-emerald-400 font-semibold">Yes</span>
                        ) : (
                          <span className="text-rose-400 font-semibold">No</span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-slate-400">
                        {reg.parameter_fields.join(', ')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="flex justify-end pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setIsRegistryModalOpen(false)}
                className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODAL: PLAN DETAILS & PROVENANCE INSPECTOR                           */}
      {/* ==================================================================== */}
      {selectedPlanDetails && (
        <div className="fixed inset-0 z-50 bg-black/70 flex items-center justify-center p-4">
          <div className="bg-surface border border-border rounded-xl max-w-2xl w-full p-5 space-y-4 shadow-2xl max-h-[85vh] overflow-y-auto">
            <div className="flex items-center justify-between pb-2 border-b border-border">
              <div className="flex items-center space-x-2">
                <FileText className="w-4 h-4 text-blue-400" />
                <h3 className="text-sm font-bold text-white">
                  PLAN-#{String(selectedPlanDetails.plan_number).padStart(4, '0')} - {selectedPlanDetails.title}
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedPlanDetails(null)}
                className="text-slate-400 hover:text-white p-1 rounded"
              >
                <XCircle className="w-4 h-4" />
              </button>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
              <div className="p-2 rounded bg-surface-elevated border border-border">
                <span className="text-[10px] text-slate-400 block">Status</span>
                <span className="font-semibold text-white">{selectedPlanDetails.status}</span>
              </div>
              <div className="p-2 rounded bg-surface-elevated border border-border">
                <span className="text-[10px] text-slate-400 block">Risk</span>
                <span className="font-semibold text-white">{selectedPlanDetails.risk_level}</span>
              </div>
              <div className="p-2 rounded bg-surface-elevated border border-border">
                <span className="text-[10px] text-slate-400 block">Execution Mode</span>
                <span className="font-semibold text-white">
                  {selectedPlanDetails.dry_run ? 'Dry Run' : 'Live Execution'}
                </span>
              </div>
              <div className="p-2 rounded bg-surface-elevated border border-border">
                <span className="text-[10px] text-slate-400 block">Simulation</span>
                <span className="font-semibold text-white">
                  {selectedPlanDetails.is_simulation ? 'Yes' : 'No'}
                </span>
              </div>
            </div>

            {selectedPlanDetails.approval_hash && (
              <div className="p-2.5 rounded bg-slate-950 border border-slate-800 text-xs font-mono">
                <div className="text-[10px] text-slate-400 uppercase font-semibold mb-1">
                  Cryptographic Approval Hash (SHA-256)
                </div>
                <div className="text-emerald-400 break-all">{selectedPlanDetails.approval_hash}</div>
              </div>
            )}

            <div className="space-y-2">
              <span className="text-xs font-semibold text-slate-300">Action Specifications</span>
              <div className="space-y-1.5">
                {selectedPlanDetails.actions.map((act, i) => (
                  <div
                    key={i}
                    className="p-2.5 rounded bg-surface-elevated border border-border text-xs space-y-1 font-mono"
                  >
                    <div className="flex justify-between font-bold text-slate-200">
                      <span>Step #{i + 1}: {act.action}</span>
                      <span className="text-[10px] text-slate-400">Agent: {act.agent_id.slice(0, 8)}...</span>
                    </div>
                    <pre className="text-[11px] text-slate-400 whitespace-pre-wrap break-all">
                      {JSON.stringify(act.parameters, null, 2)}
                    </pre>
                  </div>
                ))}
              </div>
            </div>

            {Boolean((selectedPlanDetails.execution_summary as any)?.has_uncertain_outcomes) && (
              <div className="p-3 rounded-lg bg-amber-950/80 border border-amber-600/80 text-amber-200 text-xs space-y-1">
                <div className="font-semibold flex items-center space-x-1.5 text-amber-300">
                  <AlertTriangle className="w-4 h-4 text-amber-400 flex-shrink-0" />
                  <span>Uncertain Execution Outcome Detected</span>
                </div>
                <p className="text-[11px] text-amber-300/90">
                  One or more actions timed out or yielded an ambiguous outcome. To prevent dangerous duplicate side effects, automatic retries were halted. Investigate endpoint state directly before re-triggering.
                </p>
              </div>
            )}

            {selectedPlanDetails.execution_summary && (
              <div className="space-y-2">
                <span className="text-xs font-semibold text-slate-300">Execution Receipt</span>
                <pre className="p-3 rounded-lg bg-slate-950 border border-slate-800 font-mono text-[11px] text-slate-300 max-h-48 overflow-y-auto whitespace-pre-wrap break-all">
                  {JSON.stringify(selectedPlanDetails.execution_summary, null, 2)}
                </pre>
              </div>
            )}

            <div className="flex justify-end pt-2 border-t border-border">
              <button
                type="button"
                onClick={() => setSelectedPlanDetails(null)}
                className="px-3 py-1.5 rounded-lg border border-border bg-surface hover:bg-surface-elevated text-slate-300 text-xs font-medium"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
