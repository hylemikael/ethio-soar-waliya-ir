import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Brain,
  Sliders,
  ShieldAlert,
  Cpu,
  Search,
  Plus,
  Play,
  Edit3,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  RefreshCw,
  Power,
  X,
  Lock,
  Target,
  Clock,
  ExternalLink,
  Copy,
  Check,
  Terminal,
  Layers,
  ShieldCheck,
  ArrowRight,
  Globe,
  Radio,
  Database,
} from 'lucide-react';
import { apiClient, ApiError } from '../api/client';
import {
  DetectionRule,
  RuleEvaluationResult,
  FindingRecord,
  BehavioralBaselinesResponse,
  Severity,
  EventType,
  SecurityEventEnvelope,
  SimulationRunRecord,
  SimulationCoverageResponse,
  FeedConfigurationRecord,
  FeedSyncRunRecord,
  ThreatIndicatorRecord,
} from '../types';
import { EmptyState } from '../components/EmptyState';
import { WorkspaceId } from '../components/Header';

interface DetectionAnalyticsProps {
  onOpenLogin?: () => void;
  isAuthenticated?: boolean;
  onSelectWorkspace?: (workspace: WorkspaceId, incidentId?: string) => void;
}

export const DetectionAnalytics: React.FC<DetectionAnalyticsProps> = ({
  onOpenLogin,
  isAuthenticated: _isAuthenticated,
  onSelectWorkspace,
}) => {
  // Rules State
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [rulesLoading, setRulesLoading] = useState(true);
  const [rulesError, setRulesError] = useState<string | null>(null);

  // Findings State
  const [findings, setFindings] = useState<FindingRecord[]>([]);
  const [findingsLoading, setFindingsLoading] = useState(true);

  // Baselines & Anomalies State
  const [baselinesData, setBaselinesData] = useState<BehavioralBaselinesResponse | null>(null);
  const [baselinesLoading, setBaselinesLoading] = useState(true);

  // Active View Tab: 'rules' | 'findings' | 'baselines' | 'purple-team' | 'feeds'
  const [activeTab, setActiveTab] = useState<'rules' | 'findings' | 'baselines' | 'purple-team' | 'feeds'>('rules');

  // Threat Intel Feeds State
  const [feeds, setFeeds] = useState<FeedConfigurationRecord[]>([]);
  const [feedsLoading, setFeedsLoading] = useState(false);
  const [feedsError, setFeedsError] = useState<string | null>(null);
  const [syncRuns, setSyncRuns] = useState<FeedSyncRunRecord[]>([]);
  const [syncRunsLoading, setSyncRunsLoading] = useState(false);
  const [tiIndicators, setTiIndicators] = useState<ThreatIndicatorRecord[]>([]);
  const [tiIndicatorsTotal, setTiIndicatorsTotal] = useState(0);
  const [tiIndicatorsLoading, setTiIndicatorsLoading] = useState(false);
  const [tiSearchQuery, setTiSearchQuery] = useState('');
  const [tiTypeFilter, setTiTypeFilter] = useState('ALL');
  const [tiSourceFilter, setTiSourceFilter] = useState('ALL');
  const [syncingFeedId, setSyncingFeedId] = useState<string | null>(null);
  const [dryRunOption, setDryRunOption] = useState(false);
  const [forceOption, setForceOption] = useState(false);
  const [syncMessage, setSyncMessage] = useState<{ type: 'success' | 'error'; text: string } | null>(null);

  // Purple-Team Simulation State
  const [coverageData, setCoverageData] = useState<SimulationCoverageResponse | null>(null);
  const [coverageLoading, setCoverageLoading] = useState(false);
  const [simulationRuns, setSimulationRuns] = useState<SimulationRunRecord[]>([]);
  const [simRunsLoading, setSimRunsLoading] = useState(false);
  const [simError, setSimError] = useState<string | null>(null);

  // Simulation Filters & Pagination
  const [simScenarioFilter, setSimScenarioFilter] = useState<string>('ALL');
  const [simStatusFilter, setSimStatusFilter] = useState<string>('ALL');
  const [simBoundaryFilter, setSimBoundaryFilter] = useState<'ALL' | 'POSITIVE' | 'NEGATIVE'>('ALL');
  const [simSearchQuery, setSimSearchQuery] = useState<string>('');
  const [simPage, setSimPage] = useState(1);
  const simPageSize = 10;

  // Selected Simulation Run Modal
  const [selectedRun, setSelectedRun] = useState<SimulationRunRecord | null>(null);
  const [isRunModalOpen, setIsRunModalOpen] = useState(false);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  // Search and Filters (for Rules)
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [eventTypeFilter, setEventTypeFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Rule Edit / Create Modal State
  const [isEditorOpen, setIsEditorOpen] = useState(false);
  const [editingRule, setEditingRule] = useState<Partial<DetectionRule>>({
    rule_id: '',
    version: 1,
    name: '',
    description: '',
    severity: 'HIGH',
    event_type: 'PROCESS_EXECUTION',
    conditions: [{ field: 'attributes.exe', operator: '==', value: '/usr/bin/sudo' }],
    mitre_attack_ids: ['T1548.003'],
    dedup_window_seconds: 300,
    is_active: true,
  });
  const [editorConditionsJson, setEditorConditionsJson] = useState('[]');
  const [editorMitreStr, setEditorMitreStr] = useState('T1548.003');
  const [editorError, setEditorError] = useState<string | null>(null);
  const [editorSubmitting, setEditorSubmitting] = useState(false);

  // Rule Test Modal State
  const [isTesterOpen, setIsTesterOpen] = useState(false);
  const [testingRule, setTestingRule] = useState<DetectionRule | null>(null);
  const [sampleEventJson, setSampleEventJson] = useState('');
  const [testResult, setTestResult] = useState<RuleEvaluationResult | null>(null);
  const [testLoading, setTestLoading] = useState(false);
  const [testError, setTestError] = useState<string | null>(null);

  const isMountedRef = useRef(true);

  // Fetch Rules, Findings, and Baselines
  const loadData = useCallback(async () => {
    try {
      setRulesLoading(true);
      setFindingsLoading(true);
      setBaselinesLoading(true);
      setRulesError(null);

      const [rulesRes, findingsRes, baselinesRes] = await Promise.all([
        apiClient.listRules(),
        apiClient.listFindings(50),
        apiClient.getBehavioralBaselines(),
      ]);

      if (isMountedRef.current) {
        setRules(rulesRes);
        setFindings(findingsRes);
        setBaselinesData(baselinesRes);
      }
    } catch (err: unknown) {
      if (isMountedRef.current) {
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          setRulesError('Administrative session authentication required to view detection engine state.');
        } else {
          setRulesError('Failed to retrieve detection rules and analytics from backend.');
        }
      }
    } finally {
      if (isMountedRef.current) {
        setRulesLoading(false);
        setFindingsLoading(false);
        setBaselinesLoading(false);
      }
    }
  }, []);

  // Fetch Purple-Team Simulation Data
  const loadSimulationData = useCallback(async () => {
    try {
      setCoverageLoading(true);
      setSimRunsLoading(true);
      setSimError(null);

      const [cov, runs] = await Promise.all([
        apiClient.getSimulationCoverage(),
        apiClient.listSimulationRuns({ limit: 100 }),
      ]);

      if (isMountedRef.current) {
        setCoverageData(cov);
        setSimulationRuns(runs);
      }
    } catch (err: unknown) {
      if (isMountedRef.current) {
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          setSimError('Administrative session authentication required to view purple-team validation.');
        } else {
          setSimError('Failed to retrieve simulation coverage and run history from backend.');
        }
      }
    } finally {
      if (isMountedRef.current) {
        setCoverageLoading(false);
        setSimRunsLoading(false);
      }
    }
  }, []);

  useEffect(() => {
    isMountedRef.current = true;
    loadData();
    loadSimulationData();
    return () => {
      isMountedRef.current = false;
    };
  }, [loadData, loadSimulationData]);

  // Threat Intel Callbacks
  const loadFeedsData = useCallback(async () => {
    setFeedsLoading(true);
    setSyncRunsLoading(true);
    setFeedsError(null);
    try {
      const [feedsRes, runsRes] = await Promise.all([
        apiClient.listThreatIntelFeeds(),
        apiClient.listThreatIntelSyncRuns(undefined, 15),
      ]);
      setFeeds(feedsRes);
      setSyncRuns(runsRes.items);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed loading threat intelligence feeds';
      setFeedsError(msg);
    } finally {
      setFeedsLoading(false);
      setSyncRunsLoading(false);
    }
  }, []);

  const loadIndicators = useCallback(async () => {
    setTiIndicatorsLoading(true);
    try {
      const res = await apiClient.listThreatIndicators({
        type: tiTypeFilter,
        source: tiSourceFilter,
        search: tiSearchQuery || undefined,
        limit: 25,
      });
      setTiIndicators(res.items);
      setTiIndicatorsTotal(res.total);
    } catch (err) {
      console.error('Failed loading threat indicators', err);
    } finally {
      setTiIndicatorsLoading(false);
    }
  }, [tiTypeFilter, tiSourceFilter, tiSearchQuery]);

  useEffect(() => {
    if (activeTab === 'feeds') {
      loadFeedsData();
      loadIndicators();
    }
  }, [activeTab, loadFeedsData, loadIndicators]);

  const handleSyncFeed = async (feedId: string) => {
    setSyncingFeedId(feedId);
    setSyncMessage(null);
    try {
      const run = await apiClient.syncThreatIntelFeed(feedId, dryRunOption, forceOption);
      const mode = run.is_dry_run ? 'Dry-run preview' : 'Live synchronization';
      setSyncMessage({
        type: run.status === 'FAILED' ? 'error' : 'success',
        text: `${mode} for ${feedId} completed with status: ${run.status}. Fetched: ${run.fetched_count}, Inserted: ${run.inserted_count}, Updated: ${run.updated_count}, Rejected: ${run.rejected_count}, Skipped: ${run.skipped_count}. ${run.error_summary || ''}`,
      });
      await loadFeedsData();
      await loadIndicators();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Sync request failed';
      setSyncMessage({ type: 'error', text: `Failed syncing ${feedId}: ${msg}` });
    } finally {
      setSyncingFeedId(null);
    }
  };

  const handleToggleFeed = async (feedId: string, currentEnabled: boolean) => {
    try {
      await apiClient.updateThreatIntelFeed(feedId, { is_enabled: !currentEnabled });
      await loadFeedsData();
    } catch (err) {
      console.error('Failed toggling feed', err);
    }
  };

  // Filtered Purple-Team Simulation Runs
  const filteredSimulationRuns = useMemo(() => {
    return simulationRuns.filter((run) => {
      const q = simSearchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        run.run_id.toLowerCase().includes(q) ||
        run.trace_id.toLowerCase().includes(q) ||
        run.scenario_id.toLowerCase().includes(q) ||
        run.scenario_name.toLowerCase().includes(q) ||
        run.target_rule_id.toLowerCase().includes(q) ||
        (run.mitre_attack_ids || []).some((m) => m.toLowerCase().includes(q));

      const matchesScenario =
        simScenarioFilter === 'ALL' || run.scenario_id === simScenarioFilter;

      const matchesStatus =
        simStatusFilter === 'ALL' || run.status.toUpperCase() === simStatusFilter.toUpperCase();

      const matchesBoundary =
        simBoundaryFilter === 'ALL' ||
        (simBoundaryFilter === 'POSITIVE' && !run.is_negative_test) ||
        (simBoundaryFilter === 'NEGATIVE' && run.is_negative_test);

      return matchesSearch && matchesScenario && matchesStatus && matchesBoundary;
    });
  }, [simulationRuns, simSearchQuery, simScenarioFilter, simStatusFilter, simBoundaryFilter]);

  const totalSimPages = Math.max(1, Math.ceil(filteredSimulationRuns.length / simPageSize));
  const paginatedRuns = useMemo(() => {
    const start = (simPage - 1) * simPageSize;
    return filteredSimulationRuns.slice(start, start + simPageSize);
  }, [filteredSimulationRuns, simPage, simPageSize]);

  useEffect(() => {
    setSimPage(1);
  }, [simSearchQuery, simScenarioFilter, simStatusFilter, simBoundaryFilter]);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => {
      setCopiedId((curr) => (curr === id ? null : curr));
    }, 2000);
  };

  const getSimStatusBadge = (status: string) => {
    switch (status.toUpperCase()) {
      case 'PASSED':
      case 'VALIDATED':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'FAILED':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'INCONCLUSIVE':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'RUNNING':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'NOT_TESTED':
      default:
        return 'bg-gray-100 text-gray-600 border-gray-200';
    }
  };

  const formatIsoDate = (isoStr?: string | null) => {
    if (!isoStr) return 'N/A';
    try {
      const d = new Date(isoStr);
      return d.toLocaleString(undefined, {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      });
    } catch {
      return isoStr;
    }
  };

  // Filtered Rules
  const filteredRules = useMemo(() => {
    return rules.filter((r) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        r.rule_id.toLowerCase().includes(q) ||
        r.name.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        (r.mitre_attack_ids || []).some((m) => m.toLowerCase().includes(q));

      const matchesSeverity = severityFilter === 'ALL' || r.severity === severityFilter;
      const matchesEventType = eventTypeFilter === 'ALL' || r.event_type === eventTypeFilter;
      const matchesStatus =
        statusFilter === 'ALL' ||
        (statusFilter === 'ACTIVE' && r.is_active) ||
        (statusFilter === 'INACTIVE' && !r.is_active);

      return matchesSearch && matchesSeverity && matchesEventType && matchesStatus;
    });
  }, [rules, searchQuery, severityFilter, eventTypeFilter, statusFilter]);

  // Toggle Rule Status
  const handleToggleRule = async (rule: DetectionRule) => {
    try {
      const updated = await apiClient.toggleRuleStatus(rule.rule_id, !rule.is_active);
      setRules((prev) =>
        prev.map((r) => (r.rule_id === rule.rule_id ? { ...r, is_active: updated.is_active } : r))
      );
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to update rule status');
    }
  };

  // Open Create / Edit Modal
  const openEditor = (rule?: DetectionRule) => {
    setEditorError(null);
    if (rule) {
      setEditingRule({ ...rule });
      setEditorConditionsJson(JSON.stringify(rule.conditions || [], null, 2));
      setEditorMitreStr((rule.mitre_attack_ids || []).join(', '));
    } else {
      const newId = `RULE-CUSTOM-${String(rules.length + 1).padStart(3, '0')}`;
      setEditingRule({
        rule_id: newId,
        version: 1,
        name: 'New Custom Detection Rule',
        description: 'Detects anomalous process execution on Linux hosts',
        severity: 'HIGH',
        event_type: 'PROCESS_EXECUTION',
        dedup_window_seconds: 300,
        is_active: true,
      });
      setEditorConditionsJson(
        JSON.stringify(
          [{ field: 'attributes.exe', operator: '==', value: '/usr/bin/python3' }],
          null,
          2
        )
      );
      setEditorMitreStr('T1059.006');
    }
    setIsEditorOpen(true);
  };

  // Save Rule
  const handleSaveRule = async (e: React.FormEvent) => {
    e.preventDefault();
    setEditorError(null);

    let parsedConditions;
    try {
      parsedConditions = JSON.parse(editorConditionsJson);
      if (!Array.isArray(parsedConditions) || parsedConditions.length === 0) {
        throw new Error('Conditions must be a non-empty array of objects');
      }
    } catch (err) {
      setEditorError(`Invalid JSON in conditions: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }

    const mitreList = editorMitreStr
      .split(',')
      .map((s) => s.trim().toUpperCase())
      .filter(Boolean);

    const rulePayload: DetectionRule = {
      rule_id: (editingRule.rule_id || '').trim().toUpperCase(),
      version: Number(editingRule.version) || 1,
      name: (editingRule.name || '').trim(),
      description: (editingRule.description || '').trim(),
      severity: editingRule.severity as Severity,
      event_type: editingRule.event_type as EventType,
      conditions: parsedConditions,
      mitre_attack_ids: mitreList,
      dedup_window_seconds: Number(editingRule.dedup_window_seconds) || 300,
      is_active: Boolean(editingRule.is_active),
    };

    if (!rulePayload.rule_id || !rulePayload.name) {
      setEditorError('Rule ID and Name are required fields.');
      return;
    }

    setEditorSubmitting(true);
    try {
      await apiClient.saveRule(rulePayload);
      setIsEditorOpen(false);
      await loadData();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        setEditorError(`Server rejected rule: ${err.message}`);
      } else {
        setEditorError('Network error while saving detection rule.');
      }
    } finally {
      setEditorSubmitting(false);
    }
  };

  // Open Dry-Run Test Modal
  const openTester = (rule: DetectionRule) => {
    setTestingRule(rule);
    setTestResult(null);
    setTestError(null);

    // Pre-populate sample event payload based on event_type
    const defaultSample: SecurityEventEnvelope = {
      event_id: 'test-event-uuid-001',
      event_type: rule.event_type,
      severity: rule.severity,
      timestamp: new Date().toISOString(),
      source: 'linux_sensor_01',
      payload:
        rule.event_type === 'PROCESS_EXECUTION'
          ? {
              exe: '/usr/bin/sudo',
              cmd: 'sudo su - root',
              username: 'attacker',
              pid: 4891,
            }
          : rule.event_type === 'AUTHENTICATION'
          ? {
              username: 'root',
              src_ip: '198.51.100.22',
              status: 'FAILURE',
            }
          : rule.event_type === 'FILE_INTEGRITY'
          ? {
              path: '/etc/shadow',
              action: 'MODIFIED',
            }
          : {
              data: 'Sample security telemetry payload',
            },
    };

    setSampleEventJson(JSON.stringify(defaultSample, null, 2));
    setIsTesterOpen(true);
  };

  // Run Test
  const handleRunTest = async () => {
    if (!testingRule) return;
    setTestError(null);
    setTestResult(null);

    let eventEnvelope: SecurityEventEnvelope;
    try {
      eventEnvelope = JSON.parse(sampleEventJson);
    } catch (err) {
      setTestError(`Invalid JSON in sample event: ${err instanceof Error ? err.message : String(err)}`);
      return;
    }

    setTestLoading(true);
    try {
      const res = await apiClient.testRule(testingRule, eventEnvelope);
      setTestResult(res);
    } catch (err: unknown) {
      setTestError(err instanceof Error ? err.message : 'Rule evaluation failed');
    } finally {
      setTestLoading(false);
    }
  };

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'HIGH':
        return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'MEDIUM':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'LOW':
        return 'bg-gray-50 text-gray-700 border-gray-200';
      default:
        return 'bg-gray-50 text-gray-700 border-gray-200';
    }
  };

  return (
    <div className="space-y-6">
      {/* Top Header Card */}
      <div className="p-4 rounded-xl border border-border bg-surface flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
        <div>
          <div className="flex items-center space-x-2">
            <Sliders className="w-5 h-5 text-blue-400" />
            <h2 className="text-sm font-semibold text-white">
              Detection Engineering & Behavioral Analytics
            </h2>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Versioned rule AST catalog with dry-run testing and streaming online EWMA baselines
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="px-2.5 py-1 rounded-md bg-surface-elevated text-slate-300 border border-border font-mono text-[11px]">
            EWMA Decay: &alpha; = 0.1
          </span>
          <span className="px-2.5 py-1 rounded-md bg-surface-elevated text-purple-300 border border-purple-800/40 font-mono text-[11px]">
            Anomaly Threshold: |Z| &ge; 3.0&sigma;
          </span>
          <button
            onClick={loadData}
            title="Refresh engine state"
            className="p-1.5 rounded-lg bg-surface-elevated hover:bg-slate-700 text-slate-300 border border-border transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${rulesLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Auth Error Banner if unauthenticated */}
      {rulesError && (
        <div className="p-4 rounded-xl border border-blue-500/30 bg-blue-950/30 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Lock className="w-5 h-5 text-blue-400" />
            <div>
              <h4 className="text-sm font-semibold text-white">Administrator Authentication Required</h4>
              <p className="text-xs text-slate-400">{rulesError}</p>
            </div>
          </div>
          {onOpenLogin && (
            <button
              onClick={onOpenLogin}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow transition-colors"
            >
              Sign In to Access Rules
            </button>
          )}
        </div>
      )}

      {/* Sub-Navigation Tabs */}
      <div className="flex items-center space-x-2 border-b border-border pb-1">
        <button
          onClick={() => setActiveTab('rules')}
          className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
            activeTab === 'rules'
              ? 'border-blue-500 text-blue-400 bg-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
          }`}
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Detection Rules Catalog</span>
          <span className="text-[10px] font-mono bg-surface-elevated px-1.5 py-0.2 rounded text-slate-400">
            {rules.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('findings')}
          className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
            activeTab === 'findings'
              ? 'border-blue-500 text-blue-400 bg-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
          }`}
        >
          <ShieldAlert className="w-3.5 h-3.5" />
          <span>Security Alert Findings</span>
          <span className="text-[10px] font-mono bg-surface-elevated px-1.5 py-0.2 rounded text-slate-400">
            {findings.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('baselines')}
          className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
            activeTab === 'baselines'
              ? 'border-blue-500 text-blue-400 bg-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
          }`}
        >
          <Brain className="w-3.5 h-3.5" />
          <span>Streaming EWMA Baselines</span>
          <span className="text-[10px] font-mono bg-surface-elevated px-1.5 py-0.2 rounded text-purple-300">
            {baselinesData?.total_active_baselines || 0}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('purple-team')}
          className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
            activeTab === 'purple-team'
              ? 'border-purple-500 text-purple-400 bg-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
          }`}
        >
          <Target className="w-3.5 h-3.5 text-purple-400" />
          <span>Purple-Team Validation</span>
          {coverageData ? (
            <span className="text-[10px] font-mono bg-purple-950/80 border border-purple-800/60 px-1.5 py-0.2 rounded text-purple-300">
              {coverageData.validated_rules_count}/{coverageData.total_rules_count} Rules
            </span>
          ) : (
            <span className="text-[10px] font-mono bg-surface-elevated px-1.5 py-0.2 rounded text-slate-400">
              Coverage
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('feeds')}
          className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
            activeTab === 'feeds'
              ? 'border-emerald-500 text-emerald-400 bg-surface'
              : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
          }`}
        >
          <Globe className="w-3.5 h-3.5 text-emerald-400" />
          <span>Threat Intel Feeds</span>
          {feeds.length > 0 && (
            <span className="text-[10px] font-mono bg-surface-elevated px-1.5 py-0.2 rounded text-emerald-300">
              {feeds.filter((f) => f.is_enabled).length}/{feeds.length} Active
            </span>
          )}
        </button>
      </div>

      {/* Tab 1: Detection Rules Catalog */}
      {activeTab === 'rules' && (
        <div className="space-y-4">
          {/* Controls Bar: Search, Filters, New Rule Button */}
          <div className="p-4 rounded-xl border border-border bg-surface flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
            <div className="flex-1 flex flex-wrap items-center gap-2">
              <div className="relative min-w-[220px]">
                <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
                <input
                  type="text"
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  placeholder="Search rules, MITRE techniques..."
                  className="w-full pl-9 pr-3 py-1.5 bg-surface-elevated border border-border rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <select
                value={severityFilter}
                onChange={(e) => setSeverityFilter(e.target.value)}
                className="bg-surface-elevated border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="HIGH">HIGH</option>
                <option value="MEDIUM">MEDIUM</option>
                <option value="LOW">LOW</option>
              </select>

              <select
                value={eventTypeFilter}
                onChange={(e) => setEventTypeFilter(e.target.value)}
                className="bg-surface-elevated border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Event Types</option>
                <option value="PROCESS_EXECUTION">PROCESS_EXECUTION</option>
                <option value="AUTHENTICATION">AUTHENTICATION</option>
                <option value="FILE_INTEGRITY">FILE_INTEGRITY</option>
                <option value="NETWORK_CONNECTION">NETWORK_CONNECTION</option>
                <option value="SYSTEM_LOG">SYSTEM_LOG</option>
              </select>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="bg-surface-elevated border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
              >
                <option value="ALL">All Statuses</option>
                <option value="ACTIVE">Active Only</option>
                <option value="INACTIVE">Inactive Only</option>
              </select>
            </div>

            <button
              onClick={() => openEditor()}
              className="flex items-center justify-center space-x-1.5 px-3.5 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow transition-colors shrink-0"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Rule</span>
            </button>
          </div>

          {/* Rules Grid */}
          {rulesLoading && rules.length === 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4 animate-pulse">
              {[1, 2, 3, 4].map((i) => (
                <div key={i} className="h-44 bg-surface rounded-xl border border-border" />
              ))}
            </div>
          ) : filteredRules.length === 0 ? (
            <div className="rounded-xl border border-border bg-surface p-12 text-center">
              <EmptyState
                icon={<Sliders className="w-6 h-6" />}
                title="No Matching Detection Rules"
                description="Adjust your search filter or create a new versioned detection rule."
              />
            </div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {filteredRules.map((rule) => (
                <div
                  key={rule.rule_id}
                  className={`p-4 rounded-xl border transition-all ${
                    rule.is_active
                      ? 'bg-surface border-border hover:border-slate-600'
                      : 'bg-surface/50 border-border/60 opacity-70'
                  }`}
                >
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div>
                      <div className="flex items-center space-x-2">
                        <span className="font-mono text-xs font-bold text-white">
                          {rule.rule_id}
                        </span>
                        <span className="text-[10px] font-mono text-slate-400 bg-surface-elevated px-1.5 py-0.2 rounded border border-border">
                          v{rule.version}
                        </span>
                        <span
                          className={`px-1.5 py-0.2 rounded text-[10px] font-bold border ${getSeverityBadge(
                            rule.severity
                          )}`}
                        >
                          {rule.severity}
                        </span>
                      </div>
                      <h3 className="text-sm font-semibold text-white mt-1">{rule.name}</h3>
                    </div>

                    {/* Toggle Active Button */}
                    <button
                      onClick={() => handleToggleRule(rule)}
                      title={rule.is_active ? 'Disable Rule' : 'Enable Rule'}
                      className={`flex items-center space-x-1 px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
                        rule.is_active
                          ? 'bg-emerald-950/70 text-emerald-400 border-emerald-800 hover:bg-emerald-950'
                          : 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
                      }`}
                    >
                      <Power className="w-3 h-3" />
                      <span>{rule.is_active ? 'Active' : 'Disabled'}</span>
                    </button>
                  </div>

                  <p className="text-xs text-slate-400 line-clamp-2 mb-3">{rule.description}</p>

                  {/* Conditions & MITRE tags */}
                  <div className="space-y-2 pt-2 border-t border-border/60 text-xs">
                    <div className="flex items-center justify-between text-[11px]">
                      <span className="text-slate-400 font-mono">
                        Event: <strong className="text-slate-200">{rule.event_type}</strong>
                      </span>
                      <span className="text-slate-400 font-mono">
                        {rule.conditions?.length || 0} conditions (dedup: {rule.dedup_window_seconds}s)
                      </span>
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5">
                      {rule.mitre_attack_ids?.map((tid) => (
                        <span
                          key={tid}
                          className="px-1.5 py-0.2 rounded bg-purple-950/70 text-purple-300 border border-purple-800/60 text-[10px] font-mono font-semibold"
                        >
                          {tid}
                        </span>
                      ))}
                    </div>
                  </div>

                  {/* Bottom Actions: Test & Edit */}
                  <div className="flex items-center justify-end space-x-2 pt-3 mt-2 border-t border-border/40">
                    <button
                      onClick={() => openTester(rule)}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded bg-blue-600/15 hover:bg-blue-600/25 text-blue-400 border border-blue-500/30 text-xs font-medium transition-colors"
                    >
                      <Play className="w-3 h-3" />
                      <span>Dry-Run Test</span>
                    </button>

                    <button
                      onClick={() => openEditor(rule)}
                      className="flex items-center space-x-1 px-2.5 py-1 rounded bg-surface-elevated hover:bg-slate-700 text-slate-300 border border-border text-xs font-medium transition-colors"
                    >
                      <Edit3 className="w-3 h-3" />
                      <span>Edit</span>
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Security Alert Findings */}
      {activeTab === 'findings' && (
        <div className="rounded-xl border border-border bg-surface p-5 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <div className="flex items-center space-x-2">
              <ShieldAlert className="w-4 h-4 text-amber-400" />
              <h3 className="text-sm font-semibold text-white">
                Live Generated Alert Findings ({findings.length})
              </h3>
            </div>
            <span className="text-xs text-slate-500 font-mono">Real Ingested Telemetry Matches</span>
          </div>

          {findingsLoading && findings.length === 0 ? (
            <div className="space-y-3 animate-pulse">
              {[1, 2, 3].map((i) => (
                <div key={i} className="h-20 bg-surface-elevated rounded-lg border border-border" />
              ))}
            </div>
          ) : findings.length === 0 ? (
            <EmptyState
              icon={<ShieldAlert className="w-6 h-6" />}
              title="No Security Findings Generated"
              description="When endpoint sensors transmit telemetry that triggers active detection rules or EWMA thresholds, validated findings appear here."
            />
          ) : (
            <div className="space-y-3">
              {findings.map((f) => (
                <div
                  key={f.id}
                  className="p-3.5 rounded-lg bg-surface-elevated/40 border border-border/80 space-y-2 hover:bg-surface-elevated/70 transition-colors text-xs"
                >
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                    <div className="flex items-center space-x-2">
                      <span
                        className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                          f.severity
                        )}`}
                      >
                        {f.severity}
                      </span>
                      <span className="font-mono font-bold text-white">
                        {f.rule_id || 'BEHAVIORAL_ANOMALY'}
                      </span>
                      <span className="text-slate-400 font-mono text-[11px]">
                        (Confidence: {Math.round(f.confidence * 100)}%)
                      </span>
                    </div>

                    <div className="text-[11px] text-slate-400 font-mono">
                      {f.timestamp ? new Date(f.timestamp).toLocaleString() : 'N/A'}
                    </div>
                  </div>

                  <div className="text-slate-300 font-mono text-[11px] bg-surface p-2 rounded border border-border/60 overflow-x-auto">
                    {typeof f.explanation === 'object'
                      ? JSON.stringify(f.explanation, null, 2)
                      : String(f.explanation)}
                  </div>

                  <div className="flex items-center justify-between text-[10px] text-slate-500 font-mono pt-1 border-t border-border/40">
                    <span>Dedup Key: {f.dedup_key || 'None'}</span>
                    <span>Event Ref: {f.event_id}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Tab 3: Streaming EWMA Baselines */}
      {activeTab === 'baselines' && (
        <div className="space-y-6">
          {/* Baseline Configuration Pill Bar */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs font-mono">
            <div className="p-3 bg-surface rounded-xl border border-border">
              <span className="text-slate-500 block text-[10px] uppercase">Decay Constant (&alpha;)</span>
              <span className="text-white font-bold text-sm">0.10</span>
              <span className="text-[10px] text-slate-500 block">Smooth rolling weight</span>
            </div>
            <div className="p-3 bg-surface rounded-xl border border-border">
              <span className="text-slate-500 block text-[10px] uppercase">Z-Score Threshold</span>
              <span className="text-purple-400 font-bold text-sm">&ge; 3.0&sigma;</span>
              <span className="text-[10px] text-slate-500 block">Statistically significant</span>
            </div>
            <div className="p-3 bg-surface rounded-xl border border-border">
              <span className="text-slate-500 block text-[10px] uppercase">Cold-Start Floor</span>
              <span className="text-white font-bold text-sm">5 samples</span>
              <span className="text-[10px] text-slate-500 block">Suppresses early noise</span>
            </div>
            <div className="p-3 bg-surface rounded-xl border border-border">
              <span className="text-slate-500 block text-[10px] uppercase">Redis State TTL</span>
              <span className="text-white font-bold text-sm">24 hours</span>
              <span className="text-[10px] text-slate-500 block">Bounded rolling state</span>
            </div>
          </div>

          {/* Active Baselines Table */}
          <div className="rounded-xl border border-border bg-surface p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="flex items-center space-x-2">
                <Brain className="w-4 h-4 text-purple-400" />
                <h3 className="text-sm font-semibold text-white">
                  Active Entity Statistical Baselines ({baselinesData?.total_active_baselines || 0})
                </h3>
              </div>
              <span className="text-xs text-slate-500 font-mono">Redis State (Decoded)</span>
            </div>

            {baselinesLoading && !baselinesData ? (
              <div className="space-y-3 animate-pulse">
                <div className="h-28 bg-surface-elevated rounded-lg" />
              </div>
            ) : !baselinesData || baselinesData.baselines.length === 0 ? (
              <EmptyState
                icon={<Cpu className="w-6 h-6" />}
                title="No Statistical Baselines Active"
                description="When telemetry batches stream through the consumer worker, sliding EWMA counters track per-entity frequencies (e.g. auth failures, connection rates)."
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead>
                    <tr className="border-b border-border text-slate-400 font-semibold">
                      <th className="pb-2.5">METRIC</th>
                      <th className="pb-2.5">ENTITY ID</th>
                      <th className="pb-2.5">MEAN (&mu;)</th>
                      <th className="pb-2.5">STD DEV (&sigma;)</th>
                      <th className="pb-2.5">SAMPLES</th>
                      <th className="pb-2.5 text-right">LAST UPDATED</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {baselinesData.baselines.map((b) => (
                      <tr key={b.key} className="hover:bg-surface-elevated/40">
                        <td className="py-2.5 font-mono text-cyan-300">{b.metric_name}</td>
                        <td className="py-2.5 font-mono text-white">{b.entity_id}</td>
                        <td className="py-2.5 font-mono text-slate-200">{b.mean}</td>
                        <td className="py-2.5 font-mono text-purple-300">&plusmn;{b.std_dev}</td>
                        <td className="py-2.5 font-mono text-slate-400">{b.sample_count}</td>
                        <td className="py-2.5 font-mono text-slate-500 text-right">
                          {b.last_updated ? new Date(b.last_updated).toLocaleTimeString() : 'N/A'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* Behavioral Anomaly Deviations */}
          {baselinesData && baselinesData.anomalies.length > 0 && (
            <div className="rounded-xl border border-red-800/60 bg-red-950/20 p-5 space-y-3">
              <div className="flex items-center space-x-2 pb-2 border-b border-red-800/40">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <h4 className="text-sm font-bold text-red-300">
                  Detected Behavioral Anomalies (|Z| &ge; 3.0&sigma;)
                </h4>
              </div>

              <div className="space-y-2 text-xs font-mono">
                {baselinesData.anomalies.map((anom) => (
                  <div
                    key={anom.finding_id}
                    className="p-3 rounded-lg bg-surface border border-red-800/50 flex flex-col md:flex-row md:items-center justify-between gap-2"
                  >
                    <div>
                      <span className="font-bold text-red-400 block text-[11px]">
                        Anomaly: {anom.metric_name} (Z = +{anom.z_score})
                      </span>
                      <p className="text-slate-300 font-sans text-xs mt-0.5">
                        {anom.decision_reason ||
                          `Observed ${anom.observed_value} vs baseline mean ${anom.baseline_mean} (std dev: ${anom.baseline_std_dev})`}
                      </p>
                    </div>
                    <span className="text-[10px] text-slate-500">
                      {anom.timestamp ? new Date(anom.timestamp).toLocaleString() : 'Recent'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Tab 4: Purple-Team Validation & MITRE ATT&CK Coverage */}
      {activeTab === 'purple-team' && (
        <div className="space-y-6">
          {/* Auth/Error Banner for Simulations */}
          {simError && (
            <div className="p-4 rounded-xl border border-purple-500/30 bg-purple-950/30 flex items-center justify-between">
              <div className="flex items-center space-x-3">
                <Lock className="w-5 h-5 text-purple-400" />
                <div>
                  <h4 className="text-sm font-semibold text-white">Administrator Access Required</h4>
                  <p className="text-xs text-slate-400">{simError}</p>
                </div>
              </div>
              {onOpenLogin && (
                <button
                  onClick={onOpenLogin}
                  className="px-4 py-2 rounded-lg text-xs font-semibold bg-purple-600 hover:bg-purple-500 text-white shadow transition-colors"
                >
                  Sign In to Access Simulations
                </button>
              )}
            </div>
          )}

          {/* SECTION A: Platform Validation Posture & Summary Cards */}
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-3.5">
            {/* Card 1: Validation Posture */}
            <div className="p-4 rounded-xl border border-border bg-surface flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Validation Posture
                </span>
                <ShieldCheck className="w-4 h-4 text-purple-400" />
              </div>
              <div className="mt-2">
                <div className="text-lg font-bold text-white flex items-center space-x-1.5">
                  <span>{coverageData ? `${coverageData.distinct_scenarios_tested} / 4 Scenarios` : '—'}</span>
                </div>
                <div className="mt-1">
                  {coverageData && coverageData.distinct_scenarios_tested >= 4 ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
                      FULL COVERAGE
                    </span>
                  ) : coverageData && coverageData.distinct_scenarios_tested > 0 ? (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-amber-950 text-amber-300 border border-amber-800">
                      PARTIAL VALIDATION
                    </span>
                  ) : (
                    <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-800 text-slate-400 border border-slate-700">
                      PENDING RUNS
                    </span>
                  )}
                </div>
              </div>
              <p className="text-[10px] text-slate-500 mt-2">
                Simulated purple-team matrices
              </p>
            </div>

            {/* Card 2: Validated Detection Rules */}
            <div className="p-4 rounded-xl border border-border bg-surface flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Validated Rules
                </span>
                <Sliders className="w-4 h-4 text-blue-400" />
              </div>
              <div className="mt-2">
                <div className="text-lg font-bold text-white">
                  {coverageData ? `${coverageData.validated_rules_count} / ${coverageData.total_rules_count}` : '—'}
                </div>
                {coverageData && coverageData.total_rules_count > 0 && (
                  <div className="w-full bg-slate-800 h-1.5 rounded-full mt-2 overflow-hidden">
                    <div
                      className="bg-blue-500 h-full rounded-full transition-all duration-500"
                      style={{
                        width: `${Math.round(
                          (coverageData.validated_rules_count / Math.max(1, coverageData.total_rules_count)) * 100
                        )}%`,
                      }}
                    />
                  </div>
                )}
              </div>
              <p className="text-[10px] text-slate-500 mt-2">
                {coverageData && coverageData.total_rules_count > 0
                  ? `${Math.round(
                      (coverageData.validated_rules_count / Math.max(1, coverageData.total_rules_count)) * 100
                    )}% verified in PostgreSQL`
                  : 'Rules catalog coverage'}
              </p>
            </div>

            {/* Card 3: Total Runs */}
            <div className="p-4 rounded-xl border border-border bg-surface flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Simulation Runs
                </span>
                <Target className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2">
                <div className="text-lg font-bold text-white">
                  {coverageData ? coverageData.total_runs : '—'}
                </div>
                <div className="text-[10px] text-slate-400 mt-1 flex flex-wrap gap-1 font-mono">
                  <span className="text-emerald-400 font-semibold">{coverageData?.passed_runs ?? 0} P</span>
                  <span>&bull;</span>
                  <span className="text-red-400 font-semibold">{coverageData?.failed_runs ?? 0} F</span>
                  <span>&bull;</span>
                  <span className="text-amber-400 font-semibold">{coverageData?.inconclusive_runs ?? 0} I</span>
                </div>
              </div>
              <p className="text-[10px] text-slate-500 mt-2">
                Durable execution history
              </p>
            </div>

            {/* Card 4: Pass Rate */}
            <div className="p-4 rounded-xl border border-border bg-surface flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Pass Rate
                </span>
                <CheckCircle2 className="w-4 h-4 text-emerald-400" />
              </div>
              <div className="mt-2">
                <div className="text-lg font-bold text-white">
                  {coverageData && coverageData.total_runs > 0
                    ? `${Math.round((coverageData.passed_runs / coverageData.total_runs) * 100)}%`
                    : 'N/A'}
                </div>
                <span className="text-[10px] text-slate-400 block mt-1">
                  {coverageData && coverageData.total_runs > 0
                    ? `${coverageData.passed_runs} of ${coverageData.total_runs} certified`
                    : 'Awaiting execution'}
                </span>
              </div>
              <p className="text-[10px] text-slate-500 mt-2">
                Server-verified verdicts
              </p>
            </div>

            {/* Card 5: Recent Validation & Refresh */}
            <div className="p-4 rounded-xl border border-border bg-surface flex flex-col justify-between">
              <div className="flex items-center justify-between">
                <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                  Latest Run
                </span>
                <button
                  onClick={loadSimulationData}
                  title="Refresh simulation data"
                  className="p-1 rounded bg-surface-elevated hover:bg-slate-700 text-slate-300 transition-colors"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${coverageLoading || simRunsLoading ? 'animate-spin text-purple-400' : ''}`} />
                </button>
              </div>
              <div className="mt-2">
                <div className="text-xs font-semibold text-white truncate" title={coverageData?.most_recent_run_id || 'None'}>
                  {coverageData?.most_recent_run_id ? formatIsoDate(coverageData.most_recent_run_at) : 'None'}
                </div>
                {coverageData?.most_recent_run_id && (
                  <span className="font-mono text-[10px] text-purple-400 truncate block mt-0.5">
                    {coverageData.most_recent_run_id.slice(0, 16)}...
                  </span>
                )}
              </div>
              <p className="text-[10px] text-slate-500 mt-2">
                Independent backend check
              </p>
            </div>
          </div>

          {/* SECTION B: MITRE ATT&CK & Scenario Validation Matrix */}
          <div className="rounded-xl border border-border bg-surface overflow-hidden">
            <div className="p-4 border-b border-border flex flex-col md:flex-row md:items-center justify-between gap-3">
              <div>
                <div className="flex items-center space-x-2">
                  <ShieldCheck className="w-4 h-4 text-purple-400" />
                  <h3 className="text-sm font-semibold text-white">
                    MITRE ATT&CK & Scenario Validation Matrix
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Defensive validation matrix with separate positive trigger and negative boundary tracking. Passes cannot mask false positives.
                </p>
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="px-2 py-0.5 rounded bg-emerald-950/60 text-emerald-300 border border-emerald-800/60 font-mono text-[10px]">
                  Positive Trigger: Alert Required
                </span>
                <span className="px-2 py-0.5 rounded bg-purple-950/60 text-purple-300 border border-purple-800/60 font-mono text-[10px]">
                  Negative Boundary: Alert Suppressed
                </span>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-[#0b101d] text-slate-400 font-semibold border-b border-border">
                  <tr>
                    <th className="py-3 px-4">Scenario</th>
                    <th className="py-3 px-4">MITRE Technique</th>
                    <th className="py-3 px-4">Target Detection Rule</th>
                    <th className="py-3 px-4">Positive Trigger Status</th>
                    <th className="py-3 px-4">Negative Boundary Status</th>
                    <th className="py-3 px-4">Last Tested</th>
                    <th className="py-3 px-4 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {(!coverageData || coverageData.scenarios.length === 0) ? (
                    <tr>
                      <td colSpan={7} className="py-8 text-center text-slate-500">
                        {coverageLoading ? 'Loading scenario matrix...' : 'No scenarios registered.'}
                      </td>
                    </tr>
                  ) : (
                    coverageData.scenarios.map((sc) => {
                      return (
                        <tr key={sc.scenario_id} className="hover:bg-surface-elevated/40 transition-colors">
                          <td className="py-3.5 px-4">
                            <div className="font-semibold text-white">{sc.scenario_name}</div>
                            <div className="font-mono text-[10px] text-slate-500">{sc.scenario_id}</div>
                          </td>
                          <td className="py-3.5 px-4">
                            <span className="px-2 py-0.5 rounded font-mono text-[11px] bg-blue-950/80 text-blue-300 border border-blue-800/60">
                              {sc.mitre_attack_id}
                            </span>
                          </td>
                          <td className="py-3.5 px-4 font-mono text-slate-300 text-[11px]">
                            {sc.target_rule_id}
                          </td>
                          <td className="py-3.5 px-4">
                            <span
                              className={`inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-[10px] font-semibold border ${getSimStatusBadge(
                                sc.positive_status
                              )}`}
                            >
                              {sc.positive_status === 'VALIDATED' && <CheckCircle2 className="w-3 h-3 mr-1" />}
                              {sc.positive_status === 'FAILED' && <XCircle className="w-3 h-3 mr-1" />}
                              {sc.positive_status === 'INCONCLUSIVE' && <AlertTriangle className="w-3 h-3 mr-1" />}
                              {sc.positive_status === 'NOT_TESTED' && <Clock className="w-3 h-3 mr-1" />}
                              <span>{sc.positive_status.replace('_', ' ')}</span>
                            </span>
                          </td>
                          <td className="py-3.5 px-4">
                            <span
                              className={`inline-flex items-center space-x-1 px-2.5 py-1 rounded-md text-[10px] font-semibold border ${getSimStatusBadge(
                                sc.negative_status
                              )}`}
                            >
                              {sc.negative_status === 'VALIDATED' && <CheckCircle2 className="w-3 h-3 mr-1" />}
                              {sc.negative_status === 'FAILED' && <XCircle className="w-3 h-3 mr-1" />}
                              {sc.negative_status === 'INCONCLUSIVE' && <AlertTriangle className="w-3 h-3 mr-1" />}
                              {sc.negative_status === 'NOT_TESTED' && <Clock className="w-3 h-3 mr-1" />}
                              <span>{sc.negative_status.replace('_', ' ')}</span>
                            </span>
                          </td>
                          <td className="py-3.5 px-4 text-slate-400 font-mono text-[11px]">
                            {formatIsoDate(sc.last_tested_at)}
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            {sc.last_run_id ? (
                              <button
                                onClick={async () => {
                                  try {
                                    const r = await apiClient.getSimulationRun(sc.last_run_id!);
                                    setSelectedRun(r);
                                    setIsRunModalOpen(true);
                                  } catch (err) {
                                    alert('Failed to load run details');
                                  }
                                }}
                                className="px-2.5 py-1 rounded text-[11px] font-medium bg-surface-elevated hover:bg-slate-700 text-purple-300 border border-purple-800/40 transition-colors"
                              >
                                View Run
                              </button>
                            ) : (
                              <span className="text-[11px] text-slate-500">Not Tested</span>
                            )}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* SECTION C: Simulation Run History Table */}
          <div className="rounded-xl border border-border bg-surface overflow-hidden space-y-4 p-4">
            <div className="flex flex-col md:flex-row md:items-center justify-between gap-3 pb-3 border-b border-border">
              <div>
                <div className="flex items-center space-x-2">
                  <Layers className="w-4 h-4 text-blue-400" />
                  <h3 className="text-sm font-semibold text-white">
                    Simulation Execution History & Evidence
                  </h3>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Durable run audit trail verified against PostgreSQL findings and incidents
                </p>
              </div>

              {/* Filters */}
              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[180px]">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-2.5 text-slate-500" />
                  <input
                    type="text"
                    value={simSearchQuery}
                    onChange={(e) => setSimSearchQuery(e.target.value)}
                    placeholder="Search runs, traces, rules..."
                    className="w-full pl-8 pr-3 py-1.5 bg-surface-elevated border border-border rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-purple-500"
                  />
                </div>

                <select
                  value={simScenarioFilter}
                  onChange={(e) => setSimScenarioFilter(e.target.value)}
                  className="bg-surface-elevated border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="ALL">All Scenarios</option>
                  <option value="brute-force">brute-force</option>
                  <option value="web-shell">web-shell</option>
                  <option value="port-scan">port-scan</option>
                  <option value="priv-esc">priv-esc</option>
                </select>

                <select
                  value={simStatusFilter}
                  onChange={(e) => setSimStatusFilter(e.target.value)}
                  className="bg-surface-elevated border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="PASSED">PASSED</option>
                  <option value="FAILED">FAILED</option>
                  <option value="INCONCLUSIVE">INCONCLUSIVE</option>
                  <option value="RUNNING">RUNNING</option>
                </select>

                <select
                  value={simBoundaryFilter}
                  onChange={(e) => setSimBoundaryFilter(e.target.value as 'ALL' | 'POSITIVE' | 'NEGATIVE')}
                  className="bg-surface-elevated border border-border rounded-lg px-2.5 py-1.5 text-xs text-slate-300 focus:outline-none"
                >
                  <option value="ALL">All Boundaries</option>
                  <option value="POSITIVE">Positive Triggers Only</option>
                  <option value="NEGATIVE">Negative Boundaries Only</option>
                </select>
              </div>
            </div>

            {/* Run Table */}
            {filteredSimulationRuns.length === 0 ? (
              <EmptyState
                icon={<Target className="w-8 h-8 text-slate-500" />}
                title={simRunsLoading ? 'Loading Simulation History...' : 'No Simulation Runs Found'}
                description={
                  simRunsLoading
                    ? 'Retrieving verified simulation runs from the platform database...'
                    : simulationRuns.length === 0
                    ? 'No purple-team simulation runs have been recorded yet. Execute `python3 -m waliya_sim matrix` in your terminal to generate deterministic validation runs.'
                    : 'No runs matched your current search and filter criteria.'
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="bg-[#0b101d] text-slate-400 font-semibold border-b border-border">
                    <tr>
                      <th className="py-2.5 px-3">Run & Trace ID</th>
                      <th className="py-2.5 px-3">Scenario</th>
                      <th className="py-2.5 px-3">Boundary Type</th>
                      <th className="py-2.5 px-3">Expected vs Observed</th>
                      <th className="py-2.5 px-3">Verdict</th>
                      <th className="py-2.5 px-3">Latency</th>
                      <th className="py-2.5 px-3">Database Evidence</th>
                      <th className="py-2.5 px-3">Executed</th>
                      <th className="py-2.5 px-3 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/60">
                    {paginatedRuns.map((r) => {
                      const expectedLabel = r.expected_detection ? 'Alert Expected' : 'Suppressed';
                      const observedLabel = r.observed_detection ? 'Alert Triggered' : 'Suppressed';
                      const matched = r.expected_detection === r.observed_detection;

                      return (
                        <tr key={r.run_id} className="hover:bg-surface-elevated/40 transition-colors">
                          <td className="py-3 px-3">
                            <div className="flex items-center space-x-1.5">
                              <span className="font-mono text-purple-300 font-medium">
                                {r.run_id.slice(0, 16)}...
                              </span>
                              <span className="px-1.5 py-0.5 rounded text-[9px] font-bold bg-purple-950 text-purple-300 border border-purple-800/60">
                                SIM
                              </span>
                            </div>
                            <div className="font-mono text-[10px] text-slate-500 truncate max-w-[130px]" title={r.trace_id}>
                              tr: {r.trace_id.slice(0, 12)}...
                            </div>
                          </td>
                          <td className="py-3 px-3">
                            <div className="font-medium text-white">{r.scenario_name}</div>
                            <div className="font-mono text-[10px] text-slate-400">{r.scenario_id}</div>
                          </td>
                          <td className="py-3 px-3">
                            {r.is_negative_test ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-purple-950/70 text-purple-300 border border-purple-800/50">
                                Negative Boundary
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium bg-blue-950/70 text-blue-300 border border-blue-800/50">
                                Positive Trigger
                              </span>
                            )}
                          </td>
                          <td className="py-3 px-3">
                            <div className="flex items-center space-x-1 text-[11px]">
                              <span className="text-slate-400">{expectedLabel}</span>
                              <ArrowRight className="w-3 h-3 text-slate-600" />
                              <span className={matched ? 'text-emerald-400 font-semibold' : 'text-red-400 font-semibold'}>
                                {observedLabel}
                              </span>
                            </div>
                          </td>
                          <td className="py-3 px-3">
                            <span
                              className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-[10px] font-bold border ${getSimStatusBadge(
                                r.status
                              )}`}
                            >
                              {r.status}
                            </span>
                          </td>
                          <td className="py-3 px-3 font-mono text-slate-300 text-[11px]">
                            {r.latency_seconds != null ? `${r.latency_seconds.toFixed(2)}s` : '—'}
                          </td>
                          <td className="py-3 px-3">
                            <span className="font-mono text-[11px] text-slate-300">
                              {r.matching_finding_ids.length} findings, {r.matching_incident_ids.length} inc
                            </span>
                          </td>
                          <td className="py-3 px-3 text-slate-400 font-mono text-[11px]">
                            {formatIsoDate(r.start_time)}
                          </td>
                          <td className="py-3 px-3 text-right">
                            <button
                              onClick={() => {
                                setSelectedRun(r);
                                setIsRunModalOpen(true);
                              }}
                              className="px-2.5 py-1 rounded text-[11px] font-semibold bg-surface-elevated hover:bg-slate-700 text-purple-300 border border-border hover:border-purple-500/50 transition-colors"
                            >
                              Inspect Evidence
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {/* Pagination Controls */}
            {filteredSimulationRuns.length > simPageSize && (
              <div className="flex items-center justify-between pt-3 border-t border-border text-xs text-slate-400">
                <div>
                  Showing {(simPage - 1) * simPageSize + 1} to{' '}
                  {Math.min(simPage * simPageSize, filteredSimulationRuns.length)} of{' '}
                  {filteredSimulationRuns.length} runs
                </div>
                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setSimPage((p) => Math.max(1, p - 1))}
                    disabled={simPage === 1}
                    className="px-3 py-1 rounded bg-surface-elevated border border-border hover:bg-slate-700 disabled:opacity-40"
                  >
                    Previous
                  </button>
                  <span className="font-mono text-[11px]">
                    Page {simPage} of {totalSimPages}
                  </span>
                  <button
                    onClick={() => setSimPage((p) => Math.min(totalSimPages, p + 1))}
                    disabled={simPage === totalSimPages}
                    className="px-3 py-1 rounded bg-surface-elevated border border-border hover:bg-slate-700 disabled:opacity-40"
                  >
                    Next
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* SECTION E: Safe Purple-Team CLI Guidance Card */}
          <div className="rounded-xl border border-border bg-[#0b101d] p-5 space-y-4">
            <div className="flex items-center space-x-2.5">
              <Terminal className="w-4 h-4 text-purple-400" />
              <h3 className="text-sm font-bold text-white">
                Purple-Team Operator CLI Reference (`waliya-sim`)
              </h3>
            </div>
            <p className="text-xs text-slate-400">
              Run deterministic purple-team validations using the standalone CLI. Telemetry is tagged with unique trace IDs and marked <code className="text-purple-300">synthetic: true</code>. Simulations are strictly prevented from triggering autonomous host containment or privileged response actions.
            </p>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 rounded-lg bg-surface border border-border flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 block mb-0.5 font-sans">Run single attack scenario</span>
                  <span className="text-purple-300">python3 -m waliya_sim run brute-force</span>
                </div>
                <button
                  onClick={() => handleCopy('python3 -m waliya_sim run brute-force', 'cli-bf')}
                  className="p-1.5 rounded bg-surface-elevated hover:bg-slate-700 text-slate-300 ml-2"
                  title="Copy command"
                >
                  {copiedId === 'cli-bf' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>

              <div className="p-3 rounded-lg bg-surface border border-border flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 block mb-0.5 font-sans">Run negative boundary suppression test</span>
                  <span className="text-purple-300">python3 -m waliya_sim run brute-force --negative</span>
                </div>
                <button
                  onClick={() => handleCopy('python3 -m waliya_sim run brute-force --negative', 'cli-bf-neg')}
                  className="p-1.5 rounded bg-surface-elevated hover:bg-slate-700 text-slate-300 ml-2"
                  title="Copy command"
                >
                  {copiedId === 'cli-bf-neg' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>

              <div className="p-3 rounded-lg bg-surface border border-border flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 block mb-0.5 font-sans">Run entire defensive validation matrix</span>
                  <span className="text-purple-300">python3 -m waliya_sim matrix</span>
                </div>
                <button
                  onClick={() => handleCopy('python3 -m waliya_sim matrix', 'cli-mat')}
                  className="p-1.5 rounded bg-surface-elevated hover:bg-slate-700 text-slate-300 ml-2"
                  title="Copy command"
                >
                  {copiedId === 'cli-mat' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>

              <div className="p-3 rounded-lg bg-surface border border-border flex items-center justify-between">
                <div>
                  <span className="text-[10px] text-slate-500 block mb-0.5 font-sans">Inspect platform coverage CLI report</span>
                  <span className="text-purple-300">python3 -m waliya_sim coverage</span>
                </div>
                <button
                  onClick={() => handleCopy('python3 -m waliya_sim coverage', 'cli-cov')}
                  className="p-1.5 rounded bg-surface-elevated hover:bg-slate-700 text-slate-300 ml-2"
                  title="Copy command"
                >
                  {copiedId === 'cli-cov' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
                </button>
              </div>
            </div>

            <div className="p-3 rounded-lg bg-surface/50 border border-purple-900/30 text-[11px] text-slate-400 flex items-start space-x-2">
              <ShieldCheck className="w-4 h-4 text-purple-400 shrink-0 mt-0.5" />
              <span>
                <strong>Closed-Loop Safety Guarantee:</strong> Telemetry is submitted through production ingestion APIs. The backend verifies findings directly in PostgreSQL before certifying verdicts. Simulated events never affect operational response policies or host connectivity.
              </span>
            </div>
          </div>
        </div>
      )}

      {/* Rule Create/Edit Modal */}
      {isEditorOpen && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/40 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl bg-white border border-gray-200 rounded-lg shadow-xl p-6 relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setIsEditorOpen(false)}
              className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-gray-900 mb-1">
              {editingRule.id ? 'Edit Detection Rule' : 'Create Versioned Detection Rule'}
            </h3>
            <p className="text-xs text-gray-500 mb-4">
              Validated against AST condition operators. Content is never executed as arbitrary code.
            </p>

            {editorError && (
              <div className="mb-4 p-3 rounded-lg bg-red-950/60 border border-red-800/50 text-red-300 text-xs flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{editorError}</span>
              </div>
            )}

            <form onSubmit={handleSaveRule} className="space-y-4 text-xs">
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1 font-medium">Rule ID</label>
                  <input
                    type="text"
                    value={editingRule.rule_id || ''}
                    onChange={(e) => setEditingRule({ ...editingRule, rule_id: e.target.value })}
                    placeholder="e.g. RULE-PROC-005"
                    className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-white font-mono uppercase focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
                <div>
                  <label className="block text-slate-300 mb-1 font-medium">Version</label>
                  <input
                    type="number"
                    min={1}
                    value={editingRule.version || 1}
                    onChange={(e) => setEditingRule({ ...editingRule, version: Number(e.target.value) })}
                    className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-white font-mono focus:outline-none focus:ring-1 focus:ring-blue-500"
                  />
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">Rule Name</label>
                <input
                  type="text"
                  value={editingRule.name || ''}
                  onChange={(e) => setEditingRule({ ...editingRule, name: e.target.value })}
                  placeholder="e.g. Suspicious Reverse Shell Execution"
                  className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">Description</label>
                <textarea
                  value={editingRule.description || ''}
                  onChange={(e) => setEditingRule({ ...editingRule, description: e.target.value })}
                  rows={2}
                  className="w-full bg-surface border border-border rounded-lg p-2.5 text-white focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-slate-300 mb-1 font-medium">Severity</label>
                  <select
                    value={editingRule.severity}
                    onChange={(e) => setEditingRule({ ...editingRule, severity: e.target.value as Severity })}
                    className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-white focus:outline-none"
                  >
                    <option value="CRITICAL">CRITICAL</option>
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                    <option value="INFORMATIONAL">INFORMATIONAL</option>
                  </select>
                </div>
                <div>
                  <label className="block text-slate-300 mb-1 font-medium">Event Type</label>
                  <select
                    value={editingRule.event_type}
                    onChange={(e) => setEditingRule({ ...editingRule, event_type: e.target.value as EventType })}
                    className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-white focus:outline-none"
                  >
                    <option value="PROCESS_EXECUTION">PROCESS_EXECUTION</option>
                    <option value="AUTHENTICATION">AUTHENTICATION</option>
                    <option value="FILE_INTEGRITY">FILE_INTEGRITY</option>
                    <option value="NETWORK_CONNECTION">NETWORK_CONNECTION</option>
                    <option value="SYSTEM_LOG">SYSTEM_LOG</option>
                  </select>
                </div>
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">
                  MITRE ATT&CK IDs (comma-separated)
                </label>
                <input
                  type="text"
                  value={editorMitreStr}
                  onChange={(e) => setEditorMitreStr(e.target.value)}
                  placeholder="e.g. T1059.004, T1548.003"
                  className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-white font-mono uppercase focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div>
                <label className="block text-slate-300 mb-1 font-medium">
                  Conditions AST (JSON Array)
                </label>
                <span className="text-[10px] text-slate-500 block mb-1">
                  Supported operators: ==, !=, in, not_in, contains, startswith, endswith, &gt;, &lt;, &gt;=, &lt;=, regex
                </span>
                <textarea
                  value={editorConditionsJson}
                  onChange={(e) => setEditorConditionsJson(e.target.value)}
                  rows={5}
                  className="w-full bg-surface border border-border rounded-lg p-2.5 text-white font-mono text-[11px] focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsEditorOpen(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:bg-surface-elevated font-medium"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={editorSubmitting}
                  className="px-5 py-2 rounded-lg font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow disabled:opacity-50"
                >
                  {editorSubmitting ? 'Saving...' : 'Save & Register Rule'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Rule Dry-Run Tester Modal */}
      {isTesterOpen && testingRule && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/40 backdrop-blur-sm p-4">
          <div className="w-full max-w-2xl bg-white border border-gray-200 rounded-lg shadow-xl p-6 relative max-h-[90vh] overflow-y-auto">
            <button
              onClick={() => setIsTesterOpen(false)}
              className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center space-x-2 mb-1">
              <Play className="w-4 h-4 text-blue-600" />
              <h3 className="text-base font-bold text-gray-900">
                Dry-Run Rule Evaluation: {testingRule.rule_id}
              </h3>
            </div>
            <p className="text-xs text-slate-400 mb-4">
              Simulates rule evaluation against a sample event envelope without persisting findings.
            </p>

            {testError && (
              <div className="mb-4 p-3 rounded-lg bg-red-950/60 border border-red-800/50 text-red-300 text-xs flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 shrink-0" />
                <span>{testError}</span>
              </div>
            )}

            <div className="space-y-4 text-xs">
              <div>
                <label className="block text-slate-300 mb-1 font-medium">
                  Sample Security Event Envelope (JSON)
                </label>
                <textarea
                  value={sampleEventJson}
                  onChange={(e) => setSampleEventJson(e.target.value)}
                  rows={8}
                  className="w-full bg-surface border border-border rounded-lg p-2.5 text-white font-mono text-[11px] focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>

              {testResult && (
                <div
                  className={`p-4 rounded-xl border space-y-2 ${
                    testResult.matched
                      ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-300'
                      : 'bg-amber-950/30 border-amber-800/80 text-amber-300'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center space-x-2 font-bold text-sm">
                      {testResult.matched ? (
                        <>
                          <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                          <span>RULE TRIGGERED (MATCH CONFIRMED)</span>
                        </>
                      ) : (
                        <>
                          <XCircle className="w-5 h-5 text-amber-400" />
                          <span>NO MATCH (CONDITIONS NOT SATISFIED)</span>
                        </>
                      )}
                    </div>
                    <span className="font-mono text-xs">
                      {testResult.execution_time_ms.toFixed(3)} ms
                    </span>
                  </div>

                  <div className="text-[11px] font-mono">
                    Matched Conditions: {testResult.matched_conditions} / {testResult.total_conditions}
                  </div>

                  <div className="bg-surface/80 p-2.5 rounded border border-border/60 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-36">
                    {JSON.stringify(testResult.details || {}, null, 2)}
                  </div>
                </div>
              )}

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsTesterOpen(false)}
                  className="px-4 py-2 rounded-lg text-slate-400 hover:bg-surface-elevated font-medium"
                >
                  Close
                </button>
                <button
                  onClick={handleRunTest}
                  disabled={testLoading}
                  className="flex items-center space-x-1.5 px-5 py-2 rounded-lg font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow disabled:opacity-50"
                >
                  <Play className={`w-3.5 h-3.5 ${testLoading ? 'animate-spin' : ''}`} />
                  <span>{testLoading ? 'Evaluating...' : 'Run Dry-Run Evaluation'}</span>
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Tab 5: Threat Intelligence Feeds & Ingestion */}
      {activeTab === 'feeds' && (
        <div className="space-y-6">
          {/* Top Control & Notification Bar */}
          <div className="p-4 rounded-xl border border-border bg-surface flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="flex items-center space-x-2">
                <Globe className="w-5 h-5 text-emerald-400" />
                <h3 className="text-sm font-bold text-white tracking-wide">
                  Threat Intelligence Feed Connectors
                </h3>
                <span className="text-[10px] font-mono bg-emerald-950/80 border border-emerald-800/60 px-2 py-0.5 rounded text-emerald-300">
                  Read-Only C2 & Malware Intelligence
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Synchronize external community feeds from abuse.ch (ThreatFox, URLhaus) into Waliya-IR's offline indicator matcher.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer bg-surface-elevated px-3 py-1.5 rounded-lg border border-border">
                <input
                  type="checkbox"
                  checked={dryRunOption}
                  onChange={(e) => setDryRunOption(e.target.checked)}
                  className="rounded border-border text-emerald-500 focus:ring-0"
                />
                <span>Dry-Run Preview</span>
              </label>

              <label className="flex items-center space-x-2 text-xs text-slate-300 cursor-pointer bg-surface-elevated px-3 py-1.5 rounded-lg border border-border">
                <input
                  type="checkbox"
                  checked={forceOption}
                  onChange={(e) => setForceOption(e.target.checked)}
                  className="rounded border-border text-red-500 focus:ring-0"
                />
                <span>Bypass Interval Guard</span>
              </label>

              <button
                onClick={() => {
                  loadFeedsData();
                  loadIndicators();
                }}
                disabled={feedsLoading}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-surface-elevated hover:bg-slate-700 text-slate-300 border border-border transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${feedsLoading ? 'animate-spin' : ''}`} />
                <span>Refresh Feeds</span>
              </button>
            </div>
          </div>

          {/* Alert / Notification Feedback */}
          {syncMessage && (
            <div
              className={`p-3 rounded-xl border text-xs flex items-center justify-between ${
                syncMessage.type === 'success'
                  ? 'bg-emerald-950/40 border-emerald-800/60 text-emerald-300'
                  : 'bg-red-950/40 border-red-800/60 text-red-300'
              }`}
            >
              <div className="flex items-center space-x-2">
                {syncMessage.type === 'success' ? (
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />
                ) : (
                  <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
                )}
                <span>{syncMessage.text}</span>
              </div>
              <button
                onClick={() => setSyncMessage(null)}
                className="text-slate-400 hover:text-white ml-2"
              >
                <X className="w-4 h-4" />
              </button>
            </div>
          )}

          {feedsError && (
            <div className="p-3 rounded-xl border border-red-800/60 bg-red-950/40 text-xs text-red-300 flex items-center space-x-2">
              <XCircle className="w-4 h-4 text-red-400 shrink-0" />
              <span>{feedsError}</span>
            </div>
          )}

          {/* Feed Cards Grid */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {feeds.map((feed) => {
              const isSyncing = syncingFeedId === feed.feed_id;
              const statusBadgeColor =
                feed.last_status === 'SUCCESS'
                  ? 'bg-emerald-950/80 border-emerald-800/60 text-emerald-300'
                  : feed.last_status === 'PARTIAL'
                  ? 'bg-yellow-950/80 border-yellow-800/60 text-yellow-300'
                  : feed.last_status === 'FAILED'
                  ? 'bg-red-950/80 border-red-800/60 text-red-300'
                  : 'bg-slate-900 border-border text-slate-400';

              return (
                <div
                  key={feed.feed_id}
                  className="p-5 rounded-xl border border-border bg-gradient-to-b from-surface to-surface-elevated/40 flex flex-col justify-between space-y-4 shadow-sm"
                >
                  <div className="space-y-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="space-y-1">
                        <div className="flex items-center space-x-2">
                          <Radio className="w-4 h-4 text-emerald-400" />
                          <h4 className="text-sm font-bold text-white">{feed.name}</h4>
                        </div>
                        <p className="text-xs text-slate-400">{feed.description}</p>
                      </div>

                      <div className="flex flex-col items-end space-y-1.5 shrink-0">
                        <span
                          className={`text-[11px] font-mono font-bold px-2.5 py-0.5 rounded border ${statusBadgeColor}`}
                        >
                          {feed.last_status === 'SUCCESS'
                            ? 'HEALTHY'
                            : feed.last_status === 'PARTIAL'
                            ? 'PARTIAL'
                            : feed.last_status === 'FAILED'
                            ? 'FAILED'
                            : 'NEVER RUN'}
                        </span>
                        <button
                          onClick={() => handleToggleFeed(feed.feed_id, feed.is_enabled)}
                          className={`text-[10px] font-semibold px-2 py-0.5 rounded transition-colors ${
                            feed.is_enabled
                              ? 'bg-emerald-900/50 text-emerald-300 hover:bg-emerald-900'
                              : 'bg-slate-800 text-slate-400 hover:bg-slate-700'
                          }`}
                        >
                          {feed.is_enabled ? '● Enabled' : '○ Disabled'}
                        </button>
                      </div>
                    </div>

                    {/* Feed Metrics */}
                    <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 pt-2 border-t border-border/60 text-xs">
                      <div className="p-2 rounded bg-surface/70 border border-border/40">
                        <span className="text-[10px] text-slate-500 uppercase block font-semibold">
                          Interval
                        </span>
                        <span className="font-mono text-slate-200">
                          {feed.refresh_interval_minutes}m
                        </span>
                      </div>
                      <div className="p-2 rounded bg-surface/70 border border-border/40">
                        <span className="text-[10px] text-slate-500 uppercase block font-semibold">
                          Active IOCs
                        </span>
                        <span className="font-mono font-bold text-emerald-400">
                          {(feed.indicators_count ?? 0).toLocaleString()}
                        </span>
                      </div>
                      <div className="p-2 rounded bg-surface/70 border border-border/40">
                        <span className="text-[10px] text-slate-500 uppercase block font-semibold">
                          Last Sync
                        </span>
                        <span className="font-mono text-slate-300 truncate block">
                          {feed.last_sync_at
                            ? new Date(feed.last_sync_at).toLocaleTimeString()
                            : 'Never'}
                        </span>
                      </div>
                      <div className="p-2 rounded bg-surface/70 border border-border/40">
                        <span className="text-[10px] text-slate-500 uppercase block font-semibold">
                          Successful
                        </span>
                        <span className="font-mono text-slate-300 truncate block">
                          {feed.last_successful_sync_at
                            ? new Date(feed.last_successful_sync_at).toLocaleDateString()
                            : 'None'}
                        </span>
                      </div>
                    </div>

                    {/* Error Summary (if present) */}
                    {feed.last_error_summary && (
                      <div className="p-2.5 rounded bg-red-950/30 border border-red-800/50 text-xs text-red-300 flex items-start space-x-2">
                        <AlertTriangle className="w-3.5 h-3.5 text-red-400 mt-0.5 shrink-0" />
                        <span className="truncate">{feed.last_error_summary}</span>
                      </div>
                    )}
                  </div>

                  {/* Action Footer */}
                  <div className="pt-2 flex items-center justify-between border-t border-border/60">
                    <span className="text-[11px] text-slate-500 font-mono">
                      Provider: <span className="text-slate-300 font-semibold">{feed.provider}</span>
                    </span>

                    <button
                      onClick={() => handleSyncFeed(feed.feed_id)}
                      disabled={isSyncing}
                      className="flex items-center space-x-1.5 px-4 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600 hover:bg-emerald-500 text-white shadow-sm transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isSyncing ? 'animate-spin' : ''}`} />
                      <span>
                        {isSyncing
                          ? 'Synchronizing...'
                          : dryRunOption
                          ? 'Preview Sync (Dry-Run)'
                          : 'Synchronize Now'}
                      </span>
                    </button>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Synchronization Executions Table */}
          <div className="p-5 rounded-xl border border-border bg-surface space-y-4">
            <div className="flex items-center justify-between">
              <div className="space-y-0.5">
                <h4 className="text-sm font-bold text-white">Recent Synchronization Runs</h4>
                <p className="text-xs text-slate-400">
                  Execution history, provenance metrics, and validation logs.
                </p>
              </div>
              <span className="text-xs font-mono text-slate-400">
                Showing last {syncRuns.length} executions
              </span>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-slate-400 uppercase font-mono text-[10px]">
                    <th className="py-2.5 px-3">Run ID</th>
                    <th className="py-2.5 px-3">Feed</th>
                    <th className="py-2.5 px-3">Started</th>
                    <th className="py-2.5 px-3">Status</th>
                    <th className="py-2.5 px-3 text-right">Fetched</th>
                    <th className="py-2.5 px-3 text-right">Inserted</th>
                    <th className="py-2.5 px-3 text-right">Updated</th>
                    <th className="py-2.5 px-3 text-right">Rejected</th>
                    <th className="py-2.5 px-3 text-right">Skipped</th>
                    <th className="py-2.5 px-3 text-center">Mode</th>
                    <th className="py-2.5 px-3">Diagnostics</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40">
                  {syncRunsLoading ? (
                    <tr>
                      <td colSpan={11} className="py-6 text-center text-slate-400 font-mono">
                        Loading synchronization execution logs...
                      </td>
                    </tr>
                  ) : syncRuns.length === 0 ? (
                    <tr>
                      <td colSpan={11} className="py-6 text-center text-slate-500 font-mono">
                        No synchronization history recorded yet. Execute a feed sync above.
                      </td>
                    </tr>
                  ) : (
                    syncRuns.map((r) => {
                      const statColor =
                        r.status === 'SUCCESS'
                          ? 'text-emerald-400 bg-emerald-950/60 border-emerald-800/60'
                          : r.status === 'PARTIAL'
                          ? 'text-yellow-400 bg-yellow-950/60 border-yellow-800/60'
                          : 'text-red-400 bg-red-950/60 border-red-800/60';

                      return (
                        <tr key={r.id} className="hover:bg-surface-elevated/40 transition-colors">
                          <td className="py-2.5 px-3 font-mono text-[11px] text-slate-400">
                            {r.id.slice(0, 8)}...
                          </td>
                          <td className="py-2.5 px-3 font-semibold text-white capitalize">
                            {r.feed_id}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400 font-mono text-[11px]">
                            {new Date(r.started_at).toLocaleString()}
                          </td>
                          <td className="py-2.5 px-3">
                            <span
                              className={`text-[10px] font-mono font-bold px-2 py-0.5 rounded border ${statColor}`}
                            >
                              {r.status}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-slate-300">
                            {r.fetched_count}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-emerald-400 font-semibold">
                            +{r.inserted_count}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-yellow-400">
                            ~{r.updated_count}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-red-400">
                            {r.rejected_count}
                          </td>
                          <td className="py-2.5 px-3 text-right font-mono text-slate-500">
                            {r.skipped_count}
                          </td>
                          <td className="py-2.5 px-3 text-center">
                            {r.is_dry_run ? (
                              <span className="text-[10px] font-mono text-yellow-300 bg-yellow-950/60 border border-yellow-800/60 px-1.5 py-0.2 rounded">
                                DRY-RUN
                              </span>
                            ) : (
                              <span className="text-[10px] font-mono text-emerald-300 bg-emerald-950/60 border border-emerald-800/60 px-1.5 py-0.2 rounded">
                                LIVE
                              </span>
                            )}
                          </td>
                          <td className="py-2.5 px-3 text-slate-400 text-[11px] max-w-xs truncate">
                            {r.error_summary || 'Synchronized cleanly'}
                          </td>
                        </tr>
                      );
                    })
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Active Threat Indicators Preview */}
          <div className="p-5 rounded-xl border border-border bg-surface space-y-4">
            <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-3">
              <div className="space-y-0.5">
                <div className="flex items-center space-x-2">
                  <Database className="w-4 h-4 text-emerald-400" />
                  <h4 className="text-sm font-bold text-white">Threat Indicator Catalog</h4>
                </div>
                <p className="text-xs text-slate-400">
                  Search normalized observables matched in memory and correlation graphs.
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className="relative min-w-[200px]">
                  <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
                  <input
                    type="text"
                    value={tiSearchQuery}
                    onChange={(e) => setTiSearchQuery(e.target.value)}
                    placeholder="Search observable, tag..."
                    className="w-full pl-9 pr-3 py-1.5 rounded-lg text-xs bg-surface-elevated border border-border text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
                  />
                </div>

                <select
                  value={tiTypeFilter}
                  onChange={(e) => setTiTypeFilter(e.target.value)}
                  className="px-3 py-1.5 rounded-lg text-xs bg-surface-elevated border border-border text-slate-300 focus:outline-none focus:border-emerald-500"
                >
                  <option value="ALL">All Types</option>
                  <option value="IPV4">IPv4</option>
                  <option value="IPV6">IPv6</option>
                  <option value="DOMAIN">Domain</option>
                  <option value="URL">URL</option>
                  <option value="SHA256">SHA-256</option>
                </select>

                <select
                  value={tiSourceFilter}
                  onChange={(e) => setTiSourceFilter(e.target.value)}
                  className="px-3 py-1.5 rounded-lg text-xs bg-surface-elevated border border-border text-slate-300 focus:outline-none focus:border-emerald-500"
                >
                  <option value="ALL">All Sources</option>
                  <option value="ThreatFox">ThreatFox</option>
                  <option value="URLhaus">URLhaus</option>
                  <option value="Manual">Manual / Internal</option>
                </select>
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-border text-slate-400 uppercase font-mono text-[10px]">
                    <th className="py-2.5 px-3">Observable Value</th>
                    <th className="py-2.5 px-3">Type</th>
                    <th className="py-2.5 px-3">Source Provider</th>
                    <th className="py-2.5 px-3 text-center">Confidence</th>
                    <th className="py-2.5 px-3">Threat Category</th>
                    <th className="py-2.5 px-3">Tags</th>
                    <th className="py-2.5 px-3">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/40 font-mono text-[11px]">
                  {tiIndicatorsLoading ? (
                    <tr>
                      <td colSpan={7} className="py-6 text-center text-slate-400">
                        Loading threat indicators...
                      </td>
                    </tr>
                  ) : tiIndicators.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="py-6 text-center text-slate-500">
                        No threat indicators match the current filter or search criteria.
                      </td>
                    </tr>
                  ) : (
                    tiIndicators.map((ind) => (
                      <tr key={ind.id} className="hover:bg-surface-elevated/40 transition-colors">
                        <td className="py-2.5 px-3 text-slate-200 font-bold max-w-sm truncate">
                          {ind.value}
                        </td>
                        <td className="py-2.5 px-3">
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface-elevated border border-border text-slate-300 font-sans">
                            {ind.indicator_type}
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-emerald-400 font-sans font-semibold">
                          {ind.source}
                        </td>
                        <td className="py-2.5 px-3 text-center">
                          <span
                            className={`text-[10px] font-bold px-1.5 py-0.5 rounded ${
                              ind.confidence >= 75
                                ? 'bg-red-950/80 border border-red-800 text-red-300'
                                : ind.confidence >= 50
                                ? 'bg-yellow-950/80 border border-yellow-800 text-yellow-300'
                                : 'bg-slate-800 text-slate-400'
                            }`}
                          >
                            {ind.confidence}%
                          </span>
                        </td>
                        <td className="py-2.5 px-3 text-slate-300 font-sans">
                          {ind.threat_category || 'N/A'}
                        </td>
                        <td className="py-2.5 px-3 text-slate-400 max-w-xs truncate font-sans">
                          {(ind.tags || []).join(', ') || 'None'}
                        </td>
                        <td className="py-2.5 px-3 font-sans">
                          {ind.is_active ? (
                            <span className="text-[10px] text-emerald-400 font-semibold">
                              ● Active
                            </span>
                          ) : (
                            <span className="text-[10px] text-slate-500">○ Inactive</span>
                          )}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-border/40 font-mono">
              <span>Showing {tiIndicators.length} of {tiIndicatorsTotal} matching indicators</span>
              <span>100% Offline Matching Active</span>
            </div>
          </div>
        </div>
      )}


      {/* Simulation Run Details & Evidence Modal */}
      {isRunModalOpen && selectedRun && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-gray-900/40 backdrop-blur-sm p-4">
          <div className="w-full max-w-3xl bg-white border border-gray-200 rounded-lg shadow-xl p-6 relative max-h-[92vh] overflow-y-auto space-y-5">
            <button
              onClick={() => setIsRunModalOpen(false)}
              className="absolute top-4 right-4 text-gray-400 hover:text-gray-600"
            >
              <X className="w-5 h-5" />
            </button>

            {/* Header & Badges */}
            <div>
              <div className="flex items-center space-x-2 mb-1">
                <Target className="w-5 h-5 text-purple-600" />
                <h3 className="text-base font-bold text-gray-900">
                  Simulation Evidence & Audit Trail: {selectedRun.scenario_name}
                </h3>
              </div>
              <p className="text-xs text-gray-500">
                Detailed server-verified execution record comparing expected vs observed outcomes
              </p>
            </div>

            {/* Synthetic Isolation Banner */}
            <div className="p-3 rounded-lg bg-purple-950/40 border border-purple-800/60 text-xs text-purple-200 flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-4 h-4 text-purple-400 shrink-0" />
                <span>
                  <strong>SYNTHETIC PURPLE-TEAM SIMULATION:</strong> Telemetry tagged with <code className="bg-purple-900/50 px-1 py-0.5 rounded">synthetic: true</code>. Isolated from live endpoint containment.
                </span>
              </div>
              <span className="font-mono text-[10px] text-purple-300">
                Trace: {selectedRun.trace_id.slice(0, 8)}...
              </span>
            </div>

            {/* Metadata Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs bg-surface p-3.5 rounded-lg border border-border">
              <div>
                <span className="text-slate-500 block text-[10px]">Run ID</span>
                <div className="flex items-center space-x-1 font-mono text-white text-[11px] truncate">
                  <span title={selectedRun.run_id}>{selectedRun.run_id.slice(0, 14)}...</span>
                  <button
                    onClick={() => handleCopy(selectedRun.run_id, 'modal-run-id')}
                    className="text-slate-400 hover:text-white"
                    title="Copy Run ID"
                  >
                    {copiedId === 'modal-run-id' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">Trace ID</span>
                <div className="flex items-center space-x-1 font-mono text-white text-[11px] truncate">
                  <span title={selectedRun.trace_id}>{selectedRun.trace_id.slice(0, 14)}...</span>
                  <button
                    onClick={() => handleCopy(selectedRun.trace_id, 'modal-trace-id')}
                    className="text-slate-400 hover:text-white"
                    title="Copy Trace ID"
                  >
                    {copiedId === 'modal-trace-id' ? <Check className="w-3 h-3 text-emerald-400" /> : <Copy className="w-3 h-3" />}
                  </button>
                </div>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">Target Rule</span>
                <span className="font-mono text-slate-300 text-[11px]">{selectedRun.target_rule_id}</span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">MITRE Techniques</span>
                <span className="font-mono text-blue-400 text-[11px]">
                  {selectedRun.mitre_attack_ids.join(', ') || 'N/A'}
                </span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">Boundary Type</span>
                <span className="font-medium text-white text-[11px]">
                  {selectedRun.is_negative_test ? 'Negative Boundary (Benign)' : 'Positive Attack Trigger'}
                </span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">Duration</span>
                <span className="font-mono text-slate-300 text-[11px]">
                  {selectedRun.duration_seconds != null ? `${selectedRun.duration_seconds.toFixed(2)}s` : 'N/A'}
                </span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">Telemetry Events</span>
                <span className="font-mono text-slate-300 text-[11px]">
                  {selectedRun.events_accepted_count} / {selectedRun.events_submitted_count} Accepted
                </span>
              </div>

              <div>
                <span className="text-slate-500 block text-[10px]">Verification Latency</span>
                <span className="font-mono text-emerald-400 text-[11px]">
                  {selectedRun.latency_seconds != null ? `${selectedRun.latency_seconds.toFixed(3)}s` : 'N/A'}
                </span>
              </div>
            </div>

            {/* Validation Outcome Verdict Card */}
            <div
              className={`p-4 rounded-xl border space-y-3 ${
                selectedRun.status === 'PASSED'
                  ? 'bg-emerald-950/20 border-emerald-800/80'
                  : selectedRun.status === 'FAILED'
                  ? 'bg-red-950/20 border-red-800/80'
                  : 'bg-amber-950/20 border-amber-800/80'
              }`}
            >
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  {selectedRun.status === 'PASSED' ? (
                    <CheckCircle2 className="w-5 h-5 text-emerald-400" />
                  ) : selectedRun.status === 'FAILED' ? (
                    <XCircle className="w-5 h-5 text-red-400" />
                  ) : (
                    <AlertTriangle className="w-5 h-5 text-amber-400" />
                  )}
                  <span className="font-bold text-sm text-white">
                    VERDICT: {selectedRun.status}
                  </span>
                </div>
                <span className="text-[10px] font-mono text-slate-400">
                  {selectedRun.latency_notes || 'Latency measured against database timestamps'}
                </span>
              </div>

              {/* Side-by-side comparison */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-xs pt-1">
                <div className="p-3 rounded-lg bg-surface/80 border border-border">
                  <span className="text-[10px] text-slate-400 block font-semibold mb-1">
                    EXPECTED OUTCOME
                  </span>
                  <div className="text-white font-medium">
                    {selectedRun.expected_detection
                      ? 'Security Alert Finding Expected (Positive Trigger)'
                      : 'Suppression Expected (Negative Benign Boundary)'}
                  </div>
                </div>

                <div className="p-3 rounded-lg bg-surface/80 border border-border">
                  <span className="text-[10px] text-slate-400 block font-semibold mb-1">
                    OBSERVED BACKEND OUTCOME
                  </span>
                  <div className="text-white font-medium">
                    {selectedRun.observed_detection
                      ? 'Target Rule Triggered & Findings Recorded'
                      : 'No Matching Findings Recorded in PostgreSQL'}
                  </div>
                </div>
              </div>

              {selectedRun.summary && (
                <div className="p-2.5 rounded bg-surface/60 border border-border/60 text-xs text-slate-300 font-sans">
                  <strong>Verification Summary:</strong> {selectedRun.summary}
                </div>
              )}
            </div>

            {/* Database Findings Evidence */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Correlated Database Findings ({selectedRun.matching_finding_ids.length})
                </h4>
                <span className="text-[10px] text-slate-500">
                  Verified in PostgreSQL FindingModel
                </span>
              </div>

              {selectedRun.matching_finding_ids.length === 0 ? (
                <div className="p-3 rounded-lg bg-surface border border-border text-xs text-slate-500">
                  No matching findings recorded in the database. (Expected for negative boundary tests)
                </div>
              ) : (
                <div className="space-y-1.5">
                  {selectedRun.matching_finding_ids.map((fId) => (
                    <div
                      key={fId}
                      className="p-2.5 rounded-lg bg-surface border border-border flex items-center justify-between text-xs font-mono"
                    >
                      <span className="text-slate-300">{fId}</span>
                      <button
                        onClick={() => {
                          setActiveTab('findings');
                          setSearchQuery(fId);
                          setIsRunModalOpen(false);
                        }}
                        className="flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] bg-surface-elevated hover:bg-slate-700 text-blue-400 border border-border"
                      >
                        <span>View in Findings Tab</span>
                        <ArrowRight className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Correlated Incidents Evidence */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <h4 className="text-xs font-bold text-slate-300 uppercase tracking-wider">
                  Correlated Incident Records ({selectedRun.matching_incident_ids.length})
                </h4>
                <span className="text-[10px] text-slate-500">
                  Correlated in PostgreSQL IncidentModel
                </span>
              </div>

              {selectedRun.matching_incident_ids.length === 0 ? (
                <div className="p-3 rounded-lg bg-surface border border-border text-xs text-slate-500">
                  No correlated incidents generated for this run.
                </div>
              ) : (
                <div className="space-y-1.5">
                  {selectedRun.matching_incident_ids.map((incId) => (
                    <div
                      key={incId}
                      className="p-2.5 rounded-lg bg-surface border border-border flex items-center justify-between text-xs font-mono"
                    >
                      <span className="text-slate-300">{incId}</span>
                      {onSelectWorkspace && (
                        <button
                          onClick={() => {
                            onSelectWorkspace('investigation', incId);
                            setIsRunModalOpen(false);
                          }}
                          className="flex items-center space-x-1 px-2.5 py-1 rounded text-[10px] font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow"
                        >
                          <span>Inspect in Forensics Workspace</span>
                          <ExternalLink className="w-3 h-3 ml-1" />
                        </button>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Error Detail (if present) */}
            {selectedRun.error_detail && (
              <div className="p-3 rounded-lg bg-red-950/40 border border-red-800/60 text-xs text-red-300 space-y-1">
                <span className="font-bold block">Error Detail Reported:</span>
                <pre className="font-mono text-[11px] whitespace-pre-wrap">{selectedRun.error_detail}</pre>
              </div>
            )}

            {/* Raw JSON Record */}
            <details className="text-xs border border-border rounded-lg bg-surface">
              <summary className="p-2.5 text-slate-400 font-semibold cursor-pointer hover:text-white">
                View Raw Simulation Record JSON
              </summary>
              <pre className="p-3 text-[11px] font-mono text-slate-300 overflow-x-auto max-h-48 border-t border-border bg-[#090d18]">
                {JSON.stringify(selectedRun, null, 2)}
              </pre>
            </details>

            {/* Close footer */}
            <div className="flex items-center justify-end space-x-3 pt-2">
              <button
                onClick={() => setIsRunModalOpen(false)}
                className="px-5 py-2 rounded-lg text-xs font-semibold bg-surface-elevated hover:bg-slate-700 text-white border border-border"
              >
                Close Evidence Modal
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
