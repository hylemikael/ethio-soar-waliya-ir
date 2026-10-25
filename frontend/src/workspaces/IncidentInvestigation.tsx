import React, { useState, useEffect, useCallback, useMemo, useRef } from 'react';
import {
  Search,
  Network,
  Clock,
  Layers,
  ArrowRight,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  FileCheck,
  Download,
  Copy,
  Check,
  Activity,
  History,
  Lock,
  Tag,
  Sliders,
  X,
  ShieldAlert,
  ShieldCheck,
  Crosshair,
  ExternalLink,
  Info,
} from 'lucide-react';
import { apiClient, ApiError } from '../api/client';
import {
  IncidentSummary,
  IncidentDetail,
  IncidentEvidenceResponse,
  GraphSnapshot,
  Severity,
  IncidentStatus,
  IncidentThreatIntelSummary,
  IncidentAttackCoverageResponse,
  IncidentReconstructionResponse,
  ReconstructionObservationItem,
} from '../types';
import { AttackGraph } from '../components/AttackGraph';
import { EmptyState } from '../components/EmptyState';

interface IncidentInvestigationProps {
  initialIncidentId?: string | null;
  onOpenLogin?: () => void;
  isAuthenticated?: boolean;
}

export const IncidentInvestigation: React.FC<IncidentInvestigationProps> = ({
  initialIncidentId,
  onOpenLogin,
}) => {
  // Incident List state
  const [incidents, setIncidents] = useState<IncidentSummary[]>([]);
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(initialIncidentId || null);
  const [listLoading, setListLoading] = useState(true);
  const [listError, setListError] = useState<string | null>(null);

  // Filters state
  const [searchQuery, setSearchQuery] = useState('');
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  // Selected Incident Detail state
  const [incidentDetail, setIncidentDetail] = useState<IncidentDetail | null>(null);
  const [evidenceData, setEvidenceData] = useState<IncidentEvidenceResponse | null>(null);
  const [graphData, setGraphData] = useState<GraphSnapshot | null>(null);
  const [threatIntelSummary, setThreatIntelSummary] = useState<IncidentThreatIntelSummary | null>(null);
  const [mitreCoverage, setMitreCoverage] = useState<IncidentAttackCoverageResponse | null>(null);
  const [reconstructionData, setReconstructionData] = useState<IncidentReconstructionResponse | null>(null);
  const [selectedReconItem, setSelectedReconItem] = useState<ReconstructionObservationItem | null>(null);
  const [reconFilter, setReconFilter] = useState<'ALL' | 'EVENT' | 'FINDING'>('ALL');
  const [reconActiveView, setReconActiveView] = useState<'chronology' | 'progression'>('chronology');
  const [selectedTacticFilter, setSelectedTacticFilter] = useState<string>('ALL');
  const [detailLoading, setDetailLoading] = useState(false);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isGraphRefreshing, setIsGraphRefreshing] = useState(false);

  // Active Sub-Tab
  const [activeTab, setActiveTab] = useState<'graph' | 'timeline' | 'reconstruction' | 'evidence' | 'history' | 'threat-intel' | 'mitre'>('graph');

  // Timeline Entity Filter
  const [timelineEntityFilter, setTimelineEntityFilter] = useState<string>('');
  const [timelineSeverityFilter, setTimelineSeverityFilter] = useState<string>('ALL');

  // Modals state
  const [isStatusModalOpen, setIsStatusModalOpen] = useState(false);
  const [newStatus, setNewStatus] = useState<IncidentStatus>('INVESTIGATING');
  const [statusNote, setStatusNote] = useState('');
  const [statusSubmitting, setStatusSubmitting] = useState(false);

  const [isRiskModalOpen, setIsRiskModalOpen] = useState(false);
  const [isSealingEvidence, setIsSealingEvidence] = useState(false);
  const [copiedHash, setCopiedHash] = useState<string | null>(null);

  const isMountedRef = useRef(true);

  // Fetch Incident List
  const fetchIncidents = useCallback(async () => {
    try {
      setListLoading(true);
      setListError(null);
      const params: { status?: string; severity?: string } = {};
      if (statusFilter !== 'ALL') params.status = statusFilter;
      if (severityFilter !== 'ALL') params.severity = severityFilter;

      const data = await apiClient.listIncidents(params);
      if (isMountedRef.current) {
        setIncidents(data);

        // Auto-select first incident if none selected or if selected is not in list
        if (data.length > 0 && !selectedIncidentId) {
          setSelectedIncidentId(data[0].incident_id);
        }
      }
    } catch (err: unknown) {
      if (isMountedRef.current) {
        if (err instanceof ApiError && (err.status === 401 || err.status === 403)) {
          setListError('Administrative authentication required to inspect incident records.');
        } else {
          setListError('Unable to load incidents from backend.');
        }
      }
    } finally {
      if (isMountedRef.current) {
        setListLoading(false);
      }
    }
  }, [statusFilter, severityFilter, selectedIncidentId]);

  useEffect(() => {
    isMountedRef.current = true;
    fetchIncidents();
    return () => {
      isMountedRef.current = false;
    };
  }, [fetchIncidents]);

  // Load Full Details for Selected Incident
  const loadIncidentDetails = useCallback(async (id: string, isManualRefresh = false) => {
    if (!id) return;
    try {
      if (isManualRefresh) setIsRefreshing(true);
      else setDetailLoading(true);
      setDetailError(null);

      const [detail, evidence, graph, threatIntel, mitre, recon] = await Promise.all([
        apiClient.getIncident(id),
        apiClient.getIncidentEvidence(id),
        apiClient.getIncidentGraph(id),
        apiClient.getIncidentThreatIntel(id).catch(() => null),
        apiClient.getIncidentMitreCoverage(id).catch(() => null),
        apiClient.getIncidentReconstruction(id).catch(() => null),
      ]);

      if (isMountedRef.current) {
        setIncidentDetail(detail);
        setEvidenceData(evidence);
        setGraphData(graph);
        setThreatIntelSummary(threatIntel);
        setMitreCoverage(mitre);
        setReconstructionData(recon);
      }
    } catch (err: unknown) {
      if (isMountedRef.current) {
        if (err instanceof ApiError) {
          setDetailError(`Error loading incident forensics: ${err.message}`);
        } else {
          setDetailError('Failed to communicate with Waliya-IR backend.');
        }
      }
    } finally {
      if (isMountedRef.current) {
        setDetailLoading(false);
        setIsRefreshing(false);
      }
    }
  }, []);

  const handleRefreshGraph = useCallback(async () => {
    if (!selectedIncidentId) return;
    try {
      setIsGraphRefreshing(true);
      const [refreshed, refreshedMitre, refreshedRecon] = await Promise.all([
        apiClient.refreshIncidentGraph(selectedIncidentId),
        apiClient.getIncidentMitreCoverage(selectedIncidentId).catch(() => null),
        apiClient.getIncidentReconstruction(selectedIncidentId).catch(() => null),
      ]);
      if (isMountedRef.current) {
        setGraphData(refreshed);
        if (refreshedMitre) {
          setMitreCoverage(refreshedMitre);
        }
        if (refreshedRecon) {
          setReconstructionData(refreshedRecon);
        }
      }
    } catch (err: unknown) {
      console.error('Failed to refresh incident attack graph:', err);
    } finally {
      if (isMountedRef.current) {
        setIsGraphRefreshing(false);
      }
    }
  }, [selectedIncidentId]);

  useEffect(() => {
    if (selectedIncidentId) {
      loadIncidentDetails(selectedIncidentId);
    } else {
      setIncidentDetail(null);
      setEvidenceData(null);
      setGraphData(null);
      setThreatIntelSummary(null);
      setMitreCoverage(null);
      setReconstructionData(null);
    }
  }, [selectedIncidentId, loadIncidentDetails]);

  // Filtered incidents in queue
  const filteredIncidents = useMemo(() => {
    return incidents.filter((inc) => {
      const q = searchQuery.toLowerCase().trim();
      const matchesSearch =
        !q ||
        inc.title.toLowerCase().includes(q) ||
        String(inc.incident_number).includes(q) ||
        inc.incident_id.toLowerCase().includes(q);
      return matchesSearch;
    });
  }, [incidents, searchQuery]);

  // Filtered timeline entries
  const filteredTimeline = useMemo(() => {
    if (!evidenceData?.timeline) return [];
    return evidenceData.timeline.filter((item) => {
      if (timelineSeverityFilter !== 'ALL' && item.severity !== timelineSeverityFilter) {
        return false;
      }
      if (timelineEntityFilter) {
        const needle = timelineEntityFilter.toLowerCase();
        const explStr = JSON.stringify(item.explanation || {}).toLowerCase();
        const payloadStr = JSON.stringify(item.normalized_payload || {}).toLowerCase();
        const ruleStr = (item.rule_name || '').toLowerCase();
        return explStr.includes(needle) || payloadStr.includes(needle) || ruleStr.includes(needle);
      }
      return true;
    });
  }, [evidenceData, timelineEntityFilter, timelineSeverityFilter]);

  // Filtered reconstruction timeline entries
  const filteredReconTimeline = useMemo(() => {
    if (!reconstructionData?.timeline) return [];
    return reconstructionData.timeline.filter((item) => {
      if (reconFilter === 'EVENT') return !item.is_interpretation;
      if (reconFilter === 'FINDING') return item.is_interpretation;
      return true;
    });
  }, [reconstructionData, reconFilter]);

  // Filtered MITRE techniques by tactic
  const filteredTechniques = useMemo(() => {
    if (!mitreCoverage?.techniques) return [];
    if (selectedTacticFilter === 'ALL') return mitreCoverage.techniques;
    return mitreCoverage.techniques.filter((t) => t.tactics.includes(selectedTacticFilter));
  }, [mitreCoverage, selectedTacticFilter]);

  // Handle status update
  const handleStatusSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!incidentDetail) return;
    setStatusSubmitting(true);
    try {
      await apiClient.updateIncidentStatus(incidentDetail.incident_id, newStatus, statusNote);
      setIsStatusModalOpen(false);
      setStatusNote('');
      // Refresh current incident and incident list
      await Promise.all([
        loadIncidentDetails(incidentDetail.incident_id, true),
        fetchIncidents(),
      ]);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to update incident status');
    } finally {
      setStatusSubmitting(false);
    }
  };

  // Handle evidence sealing
  const handleSealEvidence = async () => {
    if (!incidentDetail) return;
    setIsSealingEvidence(true);
    try {
      await apiClient.sealIncidentEvidence(incidentDetail.incident_id);
      await loadIncidentDetails(incidentDetail.incident_id, true);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Evidence sealing failed');
    } finally {
      setIsSealingEvidence(false);
    }
  };

  // Handle dossier export
  const handleExportDossier = async () => {
    if (!incidentDetail) return;
    try {
      const dossier = await apiClient.exportIncidentDossier(incidentDetail.incident_id);
      const blob = new Blob([JSON.stringify(dossier, null, 2)], {
        type: 'application/json',
      });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `waliya-incident-#${incidentDetail.incident_number}-dossier.json`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Failed to export forensic dossier');
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedHash(text);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  const getSeverityBadge = (sev: Severity) => {
    switch (sev) {
      case 'CRITICAL':
        return 'bg-red-950/80 text-red-300 border-red-800';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-300 border-orange-800';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-800';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-300 border-blue-800';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getStatusBadge = (st: IncidentStatus) => {
    switch (st) {
      case 'OPEN':
        return 'bg-red-950 text-red-400 border-red-800';
      case 'INVESTIGATING':
        return 'bg-amber-950 text-amber-400 border-amber-800';
      case 'CONTAINED':
        return 'bg-purple-950 text-purple-400 border-purple-800';
      case 'RESOLVED':
        return 'bg-emerald-950 text-emerald-400 border-emerald-800';
      case 'CLOSED':
        return 'bg-slate-900 text-slate-400 border-slate-700';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-400';
    if (score >= 60) return 'text-orange-400';
    if (score >= 40) return 'text-yellow-400';
    return 'text-emerald-400';
  };

  return (
    <div className="space-y-6">
      {/* Auth warning banner if unauthenticated */}
      {listError && (
        <div className="p-4 rounded-xl border border-blue-500/30 bg-blue-950/30 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <Lock className="w-5 h-5 text-blue-400" />
            <div>
              <h4 className="text-sm font-semibold text-white">Administrator Authentication Required</h4>
              <p className="text-xs text-slate-400">{listError}</p>
            </div>
          </div>
          {onOpenLogin && (
            <button
              onClick={onOpenLogin}
              className="px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow transition-colors"
            >
              Sign In to Inspect Incidents
            </button>
          )}
        </div>
      )}

      {/* Main Split Layout: Left Queue (1 col), Right Forensics (2 cols) */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 items-start">
        {/* Left Pane: Incident Queue & Filters */}
        <div className="rounded-xl border border-border bg-surface p-4 space-y-4">
          <div className="flex items-center justify-between pb-3 border-b border-border">
            <div className="flex items-center space-x-2">
              <Layers className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-semibold text-white">Incident Forensics Queue</h2>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-xs font-mono text-slate-400 bg-surface-elevated px-2 py-0.5 rounded border border-border">
                {filteredIncidents.length} / {incidents.length}
              </span>
              <button
                onClick={fetchIncidents}
                title="Refresh Queue"
                className="p-1 rounded text-slate-400 hover:text-white hover:bg-surface-elevated transition-colors"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${listLoading ? 'animate-spin' : ''}`} />
              </button>
            </div>
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-3 top-3 text-slate-500" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search title, ID, number..."
              className="w-full pl-9 pr-8 py-2 bg-surface-elevated border border-border rounded-lg text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery('')}
                className="absolute right-2.5 top-2.5 text-slate-500 hover:text-white"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          {/* Filter Bars */}
          <div className="space-y-2">
            {/* Severity Filter Pills */}
            <div className="flex items-center space-x-1 overflow-x-auto pb-1 text-[11px]">
              {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                <button
                  key={sev}
                  onClick={() => setSeverityFilter(sev)}
                  className={`px-2.5 py-1 rounded text-[10px] font-semibold transition-colors shrink-0 ${
                    severityFilter === sev
                      ? 'bg-blue-600 text-white'
                      : 'bg-surface-elevated text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {sev}
                </button>
              ))}
            </div>

            {/* Status Filter Dropdown */}
            <div className="flex items-center space-x-2 text-xs">
              <span className="text-slate-400 text-[11px]">Status:</span>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="flex-1 bg-surface-elevated border border-border rounded px-2 py-1 text-xs text-slate-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
              >
                <option value="ALL">All Statuses</option>
                <option value="OPEN">OPEN</option>
                <option value="INVESTIGATING">INVESTIGATING</option>
                <option value="CONTAINED">CONTAINED</option>
                <option value="RESOLVED">RESOLVED</option>
                <option value="CLOSED">CLOSED</option>
              </select>
            </div>
          </div>

          {/* Incident Queue List */}
          <div className="space-y-2 max-h-[680px] overflow-y-auto pr-1">
            {listLoading && incidents.length === 0 ? (
              <div className="space-y-2 animate-pulse">
                {[1, 2, 3].map((i) => (
                  <div key={i} className="h-20 bg-surface-elevated rounded-lg border border-border" />
                ))}
              </div>
            ) : filteredIncidents.length === 0 ? (
              <EmptyState
                icon={<Search className="w-5 h-5" />}
                title="No Matching Incidents"
                description="Adjust your search query or filter settings to view correlated security incidents."
              />
            ) : (
              filteredIncidents.map((inc) => {
                const isSelected = selectedIncidentId === inc.incident_id;
                return (
                  <div
                    key={inc.incident_id}
                    onClick={() => setSelectedIncidentId(inc.incident_id)}
                    className={`p-3 rounded-lg border cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-blue-950/40 border-blue-500/80 shadow-md ring-1 ring-blue-500/30'
                        : 'bg-surface-elevated/40 border-border/80 hover:bg-surface-elevated/70'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1.5">
                      <div className="flex items-center space-x-1.5">
                        <span className="font-mono text-xs font-bold text-white">
                          #{inc.incident_number}
                        </span>
                        {(inc.is_simulation || inc.title.startsWith("[SIMULATION]")) && (
                          <span className="px-1.5 py-0.2 rounded text-[9px] font-bold bg-purple-950 text-purple-300 border border-purple-800/60 font-mono">
                            SIMULATED
                          </span>
                        )}
                      </div>
                      <div className="flex items-center space-x-1.5">
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                            inc.severity
                          )}`}
                        >
                          {inc.severity}
                        </span>
                        <span
                          className={`px-1.5 py-0.5 rounded text-[10px] font-semibold border ${getStatusBadge(
                            inc.status
                          )}`}
                        >
                          {inc.status}
                        </span>
                      </div>
                    </div>

                    <h4 className="text-xs font-semibold text-slate-200 line-clamp-1 mb-1.5">
                      {inc.title}
                    </h4>

                    <div className="flex items-center justify-between text-[11px] text-slate-400 font-mono">
                      <span>
                        Risk:{' '}
                        <span className={`font-bold ${getRiskScoreColor(inc.composite_risk_score)}`}>
                          {inc.composite_risk_score.toFixed(1)}/100
                        </span>
                      </span>
                      <span>{inc.findings_count} findings</span>
                    </div>

                    <div className="text-[10px] text-slate-500 mt-1 flex items-center justify-between">
                      <span>
                        {inc.last_seen ? new Date(inc.last_seen).toLocaleDateString() : 'Active'}
                      </span>
                      <span className="text-blue-400 hover:underline flex items-center space-x-0.5">
                        <span>Details</span>
                        <ArrowRight className="w-3 h-3" />
                      </span>
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Pane: Incident Details & Forensic Workspace */}
        <div className="lg:col-span-2 space-y-5">
          {detailError && (
            <div className="p-4 rounded-xl border border-red-500/40 bg-red-950/40 text-red-300 text-xs flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <AlertTriangle className="w-4 h-4 text-red-400" />
                <span>{detailError}</span>
              </div>
              <button
                onClick={() => selectedIncidentId && loadIncidentDetails(selectedIncidentId, true)}
                className="px-2.5 py-1 rounded bg-red-900/50 hover:bg-red-900 text-white font-medium"
              >
                Retry
              </button>
            </div>
          )}
          {!selectedIncidentId || !incidentDetail ? (
            <div className="rounded-xl border border-border bg-surface p-12 text-center">
              <Network className="w-10 h-10 text-slate-500 mx-auto mb-3" />
              <h3 className="text-base font-bold text-white">No Incident Selected</h3>
              <p className="text-xs text-slate-400 max-w-md mx-auto mt-1">
                Select a security incident from the queue to explore its NetworkX entity attack graph, chronological forensic timeline, explainable risk score, and tamper-evident evidence manifest.
              </p>
            </div>
          ) : detailLoading ? (
            <div className="space-y-4 animate-pulse">
              <div className="h-32 bg-surface rounded-xl border border-border" />
              <div className="h-96 bg-surface rounded-xl border border-border" />
            </div>
          ) : (
            <>
              {/* Incident Header Card */}
              <div className="rounded-xl border border-border bg-surface p-5 space-y-4 shadow-sm">
                <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center space-x-2.5 mb-1.5">
                      <span className="font-mono text-sm font-black text-blue-400 bg-blue-950/60 border border-blue-800/60 px-2 py-0.5 rounded">
                        INCIDENT #{incidentDetail.incident_number}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-bold border ${getSeverityBadge(
                          incidentDetail.severity
                        )}`}
                      >
                        {incidentDetail.severity}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-semibold border ${getStatusBadge(
                          incidentDetail.status
                        )}`}
                      >
                        {incidentDetail.status}
                      </span>
                      {(incidentDetail.is_simulation || incidentDetail.title.startsWith("[SIMULATION]")) && (
                        <span className="px-2 py-0.5 rounded text-xs font-bold bg-purple-950 text-purple-300 border border-purple-800/80 font-mono">
                          SYNTHETIC SIMULATION
                        </span>
                      )}
                    </div>
                    <h2 className="text-lg font-bold text-white">{incidentDetail.title}</h2>
                    {(incidentDetail.is_simulation || incidentDetail.title.startsWith("[SIMULATION]")) && (
                      <div className="mt-1.5 p-2 rounded bg-purple-950/40 border border-purple-800/50 text-[11px] text-purple-300">
                        <strong>Simulated Purple-Team Activity:</strong> Generated from isolated synthetic telemetry trace. Autonomous response actions are strictly prohibited.
                      </div>
                    )}
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                      {incidentDetail.description || 'Automated multi-finding correlated security incident.'}
                    </p>
                  </div>

                  {/* Actions: Status change, Risk Explanation, Refresh */}
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() => {
                        setNewStatus(incidentDetail.status);
                        setIsStatusModalOpen(true);
                      }}
                      className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-surface-elevated hover:bg-slate-700 text-slate-200 border border-border transition-colors shadow-sm"
                    >
                      <Sliders className="w-3.5 h-3.5 text-blue-400" />
                      <span>Transition Status</span>
                    </button>

                    <button
                      onClick={() => setIsRiskModalOpen(true)}
                      className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600/15 hover:bg-blue-600/25 text-blue-300 border border-blue-500/40 transition-colors shadow-sm"
                    >
                      <Activity className="w-3.5 h-3.5 text-blue-400" />
                      <span>
                        Risk: {incidentDetail.composite_risk_score.toFixed(1)}/100
                      </span>
                    </button>

                    <button
                      onClick={() => loadIncidentDetails(incidentDetail.incident_id, true)}
                      disabled={isRefreshing}
                      title="Refresh Incident Forensics"
                      className="p-2 rounded-lg bg-surface-elevated hover:bg-slate-700 text-slate-300 border border-border transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isRefreshing ? 'animate-spin' : ''}`} />
                    </button>
                  </div>
                </div>

                {/* Metadata Row: Timestamps, Entities, MITRE ATT&CK */}
                <div className="pt-3 border-t border-border grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
                  <div>
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">First Seen</span>
                    <span className="text-slate-300 font-mono text-[11px]">
                      {incidentDetail.first_seen ? new Date(incidentDetail.first_seen).toLocaleString() : 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">Last Seen</span>
                    <span className="text-slate-300 font-mono text-[11px]">
                      {incidentDetail.last_seen ? new Date(incidentDetail.last_seen).toLocaleString() : 'N/A'}
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">Findings Linked</span>
                    <span className="text-blue-400 font-bold font-mono">
                      {incidentDetail.findings_count} security alerts
                    </span>
                  </div>
                  <div>
                    <span className="text-[10px] uppercase font-mono text-slate-500 block">Assigned Analyst</span>
                    <span className="text-slate-300 font-mono text-[11px]">
                      {incidentDetail.assigned_to || 'Unassigned (Triage)'}
                    </span>
                  </div>
                </div>

                {/* Affected Entities & MITRE ATT&CK Tags */}
                <div className="pt-2 flex flex-wrap items-center gap-2 text-xs">
                  <span className="text-[11px] font-mono text-slate-400 flex items-center space-x-1">
                    <Tag className="w-3 h-3 text-slate-500" />
                    <span>Entities:</span>
                  </span>
                  {incidentDetail.affected_entities.length === 0 ? (
                    <span className="text-[11px] text-slate-500">None extracted</span>
                  ) : (
                    incidentDetail.affected_entities.map((ent) => (
                      <button
                        key={ent}
                        onClick={() => {
                          setTimelineEntityFilter(ent);
                          setActiveTab('timeline');
                        }}
                        title={`Filter timeline to ${ent}`}
                        className="px-2 py-0.5 rounded bg-surface-elevated hover:bg-slate-700 text-cyan-300 border border-border text-[11px] font-mono transition-colors"
                      >
                        {ent}
                      </button>
                    ))
                  )}

                  {incidentDetail.mitre_attack_ids && incidentDetail.mitre_attack_ids.length > 0 && (
                    <>
                      <span className="text-slate-600">|</span>
                      <span className="text-[11px] font-mono text-slate-400">MITRE:</span>
                      {incidentDetail.mitre_attack_ids.map((tid) => (
                        <span
                          key={tid}
                          className="px-2 py-0.5 rounded bg-purple-950/70 text-purple-300 border border-purple-800/60 text-[11px] font-mono font-semibold"
                        >
                          {tid}
                        </span>
                      ))}
                    </>
                  )}
                </div>
              </div>

              {/* Sub-Navigation Tabs */}
              <div className="flex items-center space-x-2 border-b border-border pb-1">
                <button
                  onClick={() => setActiveTab('graph')}
                  className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
                    activeTab === 'graph'
                      ? 'border-blue-500 text-blue-400 bg-surface'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
                  }`}
                >
                  <Network className="w-3.5 h-3.5" />
                  <span>Interactive Attack Graph</span>
                  <span className="text-[10px] font-mono bg-surface-elevated px-1.5 py-0.2 rounded text-slate-400">
                    {graphData?.nodes?.length || 0}
                  </span>
                </button>

                <button
                  onClick={() => setActiveTab('timeline')}
                  className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
                    activeTab === 'timeline'
                      ? 'border-blue-500 text-blue-400 bg-surface'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
                  }`}
                >
                  <Clock className="w-3.5 h-3.5" />
                  <span>Forensic Timeline</span>
                  <span className="text-[10px] font-mono bg-surface-elevated px-1.5 py-0.2 rounded text-slate-400">
                    {evidenceData?.timeline?.length || 0}
                  </span>
                </button>

                <button
                  onClick={() => setActiveTab('reconstruction')}
                  className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
                    activeTab === 'reconstruction'
                      ? 'border-emerald-500 text-emerald-400 bg-surface'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
                  }`}
                >
                  <Layers className="w-3.5 h-3.5 text-emerald-400" />
                  <span>Incident Reconstruction</span>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                      (reconstructionData?.coverage_summary?.total_observations || 0) > 0
                        ? 'bg-emerald-950/80 text-emerald-400 border border-emerald-800'
                        : 'bg-surface-elevated text-slate-400'
                    }`}
                  >
                    {reconstructionData?.coverage_summary?.total_observations || 0}
                  </span>
                </button>

                <button
                  onClick={() => setActiveTab('evidence')}
                  className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
                    activeTab === 'evidence'
                      ? 'border-blue-500 text-blue-400 bg-surface'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
                  }`}
                >
                  <FileCheck className="w-3.5 h-3.5" />
                  <span>Evidence Manifest & Integrity</span>
                  {evidenceData?.evidence_manifest?.is_verified ? (
                    <span className="text-[10px] font-bold text-emerald-400 bg-emerald-950/80 px-1.5 py-0.2 rounded border border-emerald-800">
                      VERIFIED
                    </span>
                  ) : (
                    <span className="text-[10px] font-medium text-amber-400 bg-amber-950/80 px-1.5 py-0.2 rounded border border-amber-800">
                      UNSEALED
                    </span>
                  )}
                </button>

                <button
                  onClick={() => setActiveTab('history')}
                  className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
                    activeTab === 'history'
                      ? 'border-blue-500 text-blue-400 bg-surface'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
                  }`}
                >
                  <History className="w-3.5 h-3.5" />
                  <span>Investigation Audit Trail</span>
                </button>

                <button
                  onClick={() => setActiveTab('threat-intel')}
                  className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
                    activeTab === 'threat-intel'
                      ? 'border-rose-500 text-rose-400 bg-surface'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
                  }`}
                >
                  <ShieldAlert className="w-3.5 h-3.5 text-rose-400" />
                  <span>Threat Intelligence</span>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                      (threatIntelSummary?.matches?.length || 0) > 0
                        ? 'bg-rose-950/80 text-rose-400 border border-rose-800'
                        : 'bg-surface-elevated text-slate-400'
                    }`}
                  >
                    {threatIntelSummary?.matches?.length || 0}
                  </span>
                </button>

                <button
                  onClick={() => setActiveTab('mitre')}
                  className={`flex items-center space-x-1.5 px-4 py-2 rounded-t-lg text-xs font-semibold transition-colors border-b-2 ${
                    activeTab === 'mitre'
                      ? 'border-purple-500 text-purple-400 bg-surface'
                      : 'border-transparent text-slate-400 hover:text-slate-200 hover:bg-surface/50'
                  }`}
                >
                  <Crosshair className="w-3.5 h-3.5 text-purple-400" />
                  <span>MITRE ATT&CK</span>
                  <span
                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                      (mitreCoverage?.distinct_techniques_count || 0) > 0
                        ? 'bg-purple-950/80 text-purple-400 border border-purple-800'
                        : 'bg-surface-elevated text-slate-400'
                    }`}
                  >
                    {mitreCoverage?.distinct_techniques_count || 0}
                  </span>
                </button>
              </div>

              {/* Sub-Tab 1: Interactive Attack Graph */}
              {activeTab === 'graph' && (
                <div className="space-y-4">
                  <AttackGraph
                    graph={graphData || incidentDetail.graph_snapshot}
                    onSelectEntityForTimeline={(entityId) => {
                      setTimelineEntityFilter(entityId);
                      setActiveTab('timeline');
                    }}
                    onSelectEventForTimeline={(eventId) => {
                      setTimelineEntityFilter(eventId);
                      setActiveTab('timeline');
                    }}
                    onRefreshGraph={handleRefreshGraph}
                    isRefreshing={isGraphRefreshing}
                  />
                </div>
              )}

              {/* Sub-Tab 2: Forensic Timeline */}
              {activeTab === 'timeline' && (
                <div className="rounded-xl border border-border bg-surface p-5 space-y-4">
                  {/* Timeline Filter Controls */}
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border gap-3">
                    <div className="flex items-center space-x-2">
                      <Clock className="w-4 h-4 text-blue-400" />
                      <h3 className="text-sm font-semibold text-white">Chronological Forensic Sequence</h3>
                    </div>

                    <div className="flex items-center space-x-2">
                      {timelineEntityFilter && (
                        <div className="flex items-center space-x-1 bg-cyan-950 text-cyan-300 border border-cyan-800 px-2 py-1 rounded text-xs">
                          <span>Filtered: {timelineEntityFilter}</span>
                          <button
                            onClick={() => setTimelineEntityFilter('')}
                            className="hover:text-white"
                          >
                            <X className="w-3 h-3" />
                          </button>
                        </div>
                      )}

                      <select
                        value={timelineSeverityFilter}
                        onChange={(e) => setTimelineSeverityFilter(e.target.value)}
                        className="bg-surface-elevated border border-border rounded px-2 py-1 text-xs text-slate-300 focus:outline-none"
                      >
                        <option value="ALL">All Severities</option>
                        <option value="CRITICAL">CRITICAL</option>
                        <option value="HIGH">HIGH</option>
                        <option value="MEDIUM">MEDIUM</option>
                        <option value="LOW">LOW</option>
                      </select>
                    </div>
                  </div>

                  {filteredTimeline.length === 0 ? (
                    <EmptyState
                      icon={<Clock className="w-6 h-6" />}
                      title="No Matching Events Found"
                      description="No forensic telemetry matches the selected entity or severity filter."
                    />
                  ) : (
                    <div className="space-y-3 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-border/60">
                      {filteredTimeline.map((item) => (
                        <div key={item.finding_id} className="relative pl-8 space-y-1.5">
                          {/* Timeline dot */}
                          <div
                            className={`absolute left-2 top-1.5 w-3.5 h-3.5 rounded-full border-2 bg-surface ${
                              item.severity === 'CRITICAL'
                                ? 'border-red-500'
                                : item.severity === 'HIGH'
                                ? 'border-orange-500'
                                : item.severity === 'MEDIUM'
                                ? 'border-yellow-500'
                                : 'border-blue-500'
                            }`}
                          />

                          <div className="p-3 rounded-lg bg-surface-elevated/40 border border-border/80 space-y-2 hover:bg-surface-elevated/70 transition-colors">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 text-xs">
                              <div className="flex items-center space-x-2">
                                <span
                                  className={`px-1.5 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                                    item.severity
                                  )}`}
                                >
                                  {item.severity}
                                </span>
                                <span className="font-semibold text-white">
                                  {item.rule_name || 'Telemetry Observation'}
                                </span>
                                <span className="text-slate-400 font-mono text-[11px]">
                                  [{item.event_type}]
                                </span>
                              </div>
                              <div className="text-[11px] text-slate-400 font-mono">
                                {item.timestamp ? new Date(item.timestamp).toLocaleString() : 'N/A'}
                              </div>
                            </div>

                            {/* MITRE Tags if rule has them */}
                            {item.mitre_attack_ids && item.mitre_attack_ids.length > 0 && (
                              <div className="flex items-center space-x-1.5">
                                {item.mitre_attack_ids.map((m) => (
                                  <span
                                    key={m}
                                    className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-purple-950 text-purple-300 border border-purple-800"
                                  >
                                    {m}
                                  </span>
                                ))}
                              </div>
                            )}

                            {/* Explanation details */}
                            {item.explanation && Object.keys(item.explanation).length > 0 && (
                              <div className="text-xs text-slate-300 font-mono bg-surface p-2 rounded border border-border/60 overflow-x-auto text-[11px]">
                                {typeof item.explanation === 'object'
                                  ? JSON.stringify(item.explanation, null, 2)
                                  : String(item.explanation)}
                              </div>
                            )}

                            {/* Integrity digest & shortcut */}
                            <div className="flex items-center justify-between text-[10px] text-slate-500 pt-1 border-t border-border/40 font-mono">
                              <span className="truncate max-w-sm">
                                SHA-256: {item.sha256_hash.substring(0, 16)}...
                              </span>
                              <button
                                onClick={() => {
                                  setActiveTab('graph');
                                }}
                                className="text-blue-400 hover:text-blue-300 hover:underline"
                              >
                                View in Attack Graph &rarr;
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 3: Evidence Manifest & Integrity */}
              {activeTab === 'evidence' && (
                <div className="rounded-xl border border-border bg-surface p-5 space-y-5">
                  <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border gap-3">
                    <div>
                      <h3 className="text-sm font-semibold text-white">
                        Cryptographic Evidence Manifest & Chain-of-Custody
                      </h3>
                      <p className="text-xs text-slate-400">
                        Tamper-evident verification comparing database SHA-256 digests against collected telemetry artifacts.
                      </p>
                    </div>

                    <div className="flex items-center space-x-2">
                      <button
                        onClick={handleSealEvidence}
                        disabled={isSealingEvidence}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/40 transition-colors disabled:opacity-50"
                      >
                        <Lock className="w-3.5 h-3.5" />
                        <span>{isSealingEvidence ? 'Sealing...' : 'Seal Manifest'}</span>
                      </button>

                      <button
                        onClick={handleExportDossier}
                        className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow transition-colors"
                      >
                        <Download className="w-3.5 h-3.5" />
                        <span>Export Dossier (.json)</span>
                      </button>
                    </div>
                  </div>

                  {/* Verification Status Banner */}
                  <div
                    className={`p-4 rounded-lg border flex items-center justify-between ${
                      evidenceData?.evidence_manifest?.is_verified
                        ? 'bg-emerald-950/30 border-emerald-800/80 text-emerald-300'
                        : evidenceData?.evidence_manifest?.status === 'TAMPER_DETECTED'
                        ? 'bg-red-950/40 border-red-800/80 text-red-300'
                        : 'bg-amber-950/30 border-amber-800/80 text-amber-300'
                    }`}
                  >
                    <div className="flex items-center space-x-3">
                      {evidenceData?.evidence_manifest?.is_verified ? (
                        <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0" />
                      )}
                      <div>
                        <div className="text-xs font-bold uppercase tracking-wider">
                          Integrity Status: {evidenceData?.evidence_manifest?.status || 'UNSEALED'}
                        </div>
                        <p className="text-[11px] text-slate-400 mt-0.5">
                          {evidenceData?.evidence_manifest?.is_verified
                            ? 'All artifact SHA-256 digests match the stored cryptographic manifest root. No evidence tampering detected.'
                            : 'This evidence package has not yet been cryptographically sealed into the database audit ledger.'}
                        </p>
                      </div>
                    </div>

                    <div className="text-right text-xs font-mono">
                      <span className="text-slate-400 block text-[10px]">Total Artifacts</span>
                      <span className="text-base font-bold text-white">
                        {evidenceData?.evidence_manifest?.total_items || 0}
                      </span>
                    </div>
                  </div>

                  {/* Manifest Hashes Card */}
                  <div className="p-3 bg-surface-elevated/40 rounded-lg border border-border/80 space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Calculated Manifest Hash:</span>
                      <div className="flex items-center space-x-2">
                        <span className="text-white bg-surface px-2 py-0.5 rounded border border-border">
                          {evidenceData?.evidence_manifest?.manifest_hash || 'N/A'}
                        </span>
                        {evidenceData?.evidence_manifest?.manifest_hash && (
                          <button
                            onClick={() =>
                              copyToClipboard(evidenceData.evidence_manifest.manifest_hash!)
                            }
                            className="text-slate-400 hover:text-white"
                          >
                            {copiedHash === evidenceData.evidence_manifest.manifest_hash ? (
                              <Check className="w-3.5 h-3.5 text-emerald-400" />
                            ) : (
                              <Copy className="w-3.5 h-3.5" />
                            )}
                          </button>
                        )}
                      </div>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Durable Stored Hash:</span>
                      <span className="text-slate-300 bg-surface px-2 py-0.5 rounded border border-border">
                        {evidenceData?.evidence_manifest?.stored_hash || 'Unsealed (None)'}
                      </span>
                    </div>
                  </div>

                  {/* Evidence Items Table */}
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead>
                        <tr className="border-b border-border text-slate-400 font-semibold">
                          <th className="pb-2.5">EVIDENCE ARTIFACT</th>
                          <th className="pb-2.5">TYPE</th>
                          <th className="pb-2.5">SHA-256 DIGEST</th>
                          <th className="pb-2.5 text-right">COLLECTED AT</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border/60">
                        {evidenceData?.evidence_manifest?.items?.map((item) => (
                          <tr key={item.evidence_id} className="hover:bg-surface-elevated/40">
                            <td className="py-2.5">
                              <div className="font-semibold text-white">{item.description}</div>
                              <div className="text-[10px] text-slate-500 font-mono">
                                ID: {item.evidence_id}
                              </div>
                            </td>
                            <td className="py-2.5">
                              <span className="inline-block px-2 py-0.5 rounded bg-surface-elevated text-cyan-300 font-mono text-[10px] border border-border">
                                {item.evidence_type}
                              </span>
                            </td>
                            <td className="py-2.5 font-mono text-[11px] text-slate-300">
                              <div className="flex items-center space-x-1.5">
                                <span>{item.sha256_hash.substring(0, 24)}...</span>
                                <button
                                  onClick={() => copyToClipboard(item.sha256_hash)}
                                  className="text-slate-500 hover:text-white"
                                  title="Copy full SHA-256 digest"
                                >
                                  {copiedHash === item.sha256_hash ? (
                                    <Check className="w-3 h-3 text-emerald-400" />
                                  ) : (
                                    <Copy className="w-3 h-3" />
                                  )}
                                </button>
                              </div>
                            </td>
                            <td className="py-2.5 text-right text-slate-400 font-mono text-[11px]">
                              {item.collected_at ? new Date(item.collected_at).toLocaleTimeString() : 'N/A'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Sub-Tab 4: Audit & Investigation History */}
              {activeTab === 'history' && (
                <div className="rounded-xl border border-border bg-surface p-5 space-y-4">
                  <div className="flex items-center space-x-2 pb-3 border-b border-border">
                    <History className="w-4 h-4 text-purple-400" />
                    <h3 className="text-sm font-semibold text-white">
                      Immutable Investigation Audit Trail
                    </h3>
                  </div>

                  {!incidentDetail.update_history || incidentDetail.update_history.length === 0 ? (
                    <EmptyState
                      icon={<History className="w-6 h-6" />}
                      title="No Audit History"
                      description="No administrative or correlation actions have been logged for this incident yet."
                    />
                  ) : (
                    <div className="space-y-3">
                      {incidentDetail.update_history.map((record, i) => (
                        <div
                          key={i}
                          className="p-3 bg-surface-elevated/40 rounded-lg border border-border/80 flex items-start justify-between text-xs font-mono"
                        >
                          <div className="space-y-1">
                            <span className="font-bold text-white uppercase text-[11px] px-1.5 py-0.5 rounded bg-surface border border-border">
                              {String(record.action || 'UPDATE')}
                            </span>
                            {Boolean(record.note) && (
                              <p className="text-slate-300 font-sans text-xs mt-1">
                                Note: &ldquo;{String(record.note)}&rdquo;
                              </p>
                            )}
                            {Boolean(record.previous_status && record.new_status) && (
                              <p className="text-slate-400 text-[11px]">
                                Status transition: {String(record.previous_status)} &rarr;{' '}
                                <strong className="text-white">{String(record.new_status)}</strong>
                              </p>
                            )}
                            {Boolean(record.manifest_hash) && (
                              <p className="text-emerald-400 text-[10px]">
                                Manifest sealed: {String(record.manifest_hash)}
                              </p>
                            )}
                          </div>
                          <span className="text-[10px] text-slate-500 whitespace-nowrap ml-3">
                            {record.timestamp ? new Date(String(record.timestamp)).toLocaleString() : 'N/A'}
                          </span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 5: Threat Intelligence & Provenance */}
              {activeTab === 'threat-intel' && (
                <div className="space-y-4">
                  {/* Summary Metric Header */}
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-0.5">Matched Indicators</span>
                      <span className="text-xl font-bold font-mono text-white">
                        {threatIntelSummary?.total_matched_indicators ?? 0}
                      </span>
                    </div>
                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-0.5">Max Confidence</span>
                      <span className="text-xl font-bold font-mono text-amber-400">
                        {threatIntelSummary?.max_confidence ?? 0}%
                      </span>
                    </div>
                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-0.5">Risk Score Bonus</span>
                      <span className="text-xl font-bold font-mono text-rose-400">
                        +{threatIntelSummary?.threat_intel_bonus?.toFixed(1) ?? '0.0'} pts
                      </span>
                    </div>
                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase text-slate-400 block mb-0.5">Classification</span>
                      <div className="flex items-center space-x-1.5 mt-1">
                        <span className="text-xs font-mono font-bold text-emerald-400">
                          {threatIntelSummary?.confirmed_matches_count ?? 0} Confirmed
                        </span>
                        <span className="text-xs text-slate-500">/</span>
                        <span className="text-xs font-mono text-slate-400">
                          {threatIntelSummary?.heuristic_findings_count ?? 0} Heuristic
                        </span>
                      </div>
                    </div>
                  </div>

                  {/* Decision rationale explanation banner */}
                  {threatIntelSummary?.decision_reason && (
                    <div className="p-3 rounded-lg border border-border/80 bg-surface-elevated/40 text-xs font-mono text-slate-300">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block mb-0.5">Correlation Impact:</span>
                      {threatIntelSummary.decision_reason}
                    </div>
                  )}

                  {/* Indicator Cards List */}
                  {(!threatIntelSummary?.matches || threatIntelSummary.matches.length === 0) ? (
                    <div className="rounded-xl border border-border bg-surface p-8 text-center">
                      <ShieldCheck className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
                      <h4 className="text-sm font-bold text-white">No Threat Intelligence Matches</h4>
                      <p className="text-xs text-slate-400 mt-1 max-w-md mx-auto">
                        None of the observables in this incident matched active indicators from ThreatFox, URLhaus, or internal threat databases.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {threatIntelSummary.matches.map((match, idx) => (
                        <div
                          key={match.indicator_id || idx}
                          className="rounded-xl border border-border/80 bg-surface p-4 space-y-3"
                        >
                          <div className="flex flex-wrap items-center justify-between gap-2">
                            <div className="flex items-center space-x-2">
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold uppercase bg-blue-500/20 text-blue-400 border border-blue-500/30">
                                {match.indicator_type}
                              </span>
                              <span className="font-mono text-xs font-bold text-white break-all">
                                {match.value}
                              </span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-purple-500/15 text-purple-300 border border-purple-500/30">
                                {match.provenance_label}
                              </span>
                              <span className={`px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                match.is_expired
                                  ? 'bg-red-500/15 text-red-400 border border-red-500/30'
                                  : match.is_active
                                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30'
                                  : 'bg-slate-500/15 text-slate-400 border border-slate-500/30'
                              }`}>
                                {match.is_expired ? 'EXPIRED' : match.is_active ? 'ACTIVE' : 'DEACTIVATED'}
                              </span>
                              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-emerald-500/20 text-emerald-300 border border-emerald-500/40">
                                CONFIRMED MATCH
                              </span>
                            </div>
                          </div>

                          {/* Detail metadata row */}
                          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs font-mono bg-surface-elevated/30 p-2.5 rounded-lg border border-border/50">
                            <div>
                              <span className="text-[10px] text-slate-400 block">Current Confidence</span>
                              <span className="text-amber-400 font-bold">{match.current_confidence}%</span>
                              {match.confidence_at_match !== match.current_confidence && (
                                <span className="text-[10px] text-slate-500 ml-1">
                                  (was {match.confidence_at_match}%)
                                </span>
                              )}
                            </div>
                            <div>
                              <span className="text-[10px] text-slate-400 block">Severity</span>
                              <span className={`font-bold ${
                                match.severity === 'CRITICAL' ? 'text-red-400' :
                                match.severity === 'HIGH' ? 'text-rose-400' :
                                match.severity === 'MEDIUM' ? 'text-amber-400' : 'text-blue-400'
                              }`}>
                                {match.severity}
                              </span>
                            </div>
                            <div>
                              <span className="text-[10px] text-slate-400 block">Category / Actor</span>
                              <span className="text-white truncate block">
                                {match.threat_category || 'General Malicious'}
                                {match.threat_actor ? ` (${match.threat_actor})` : ''}
                              </span>
                            </div>
                            <div>
                              <span className="text-[10px] text-slate-400 block">Matched At</span>
                              <span className="text-slate-300 text-[11px]">
                                {match.matched_at ? new Date(match.matched_at).toLocaleTimeString() : 'N/A'}
                              </span>
                            </div>
                          </div>

                          {/* Investigative explanation note */}
                          <p className="text-xs text-slate-300 leading-relaxed font-sans bg-surface-elevated/20 p-2.5 rounded border border-border/40">
                            {match.investigative_note}
                          </p>

                          {/* Footer Tags & Lifecycle timestamps */}
                          <div className="flex flex-wrap items-center justify-between text-[11px] font-mono text-slate-400 pt-1">
                            <div className="flex items-center space-x-1.5 flex-wrap">
                              {match.tags && match.tags.map((t, tidx) => (
                                <span key={tidx} className="bg-surface-elevated px-1.5 py-0.5 rounded text-[10px] text-slate-300">
                                  #{t}
                                </span>
                              ))}
                            </div>
                            <div className="flex items-center space-x-3 text-[10px] text-slate-500">
                              {match.first_seen && (
                                <span>First seen: {new Date(match.first_seen).toLocaleDateString()}</span>
                              )}
                              {match.expires_at && (
                                <span>Expires: {new Date(match.expires_at).toLocaleDateString()}</span>
                              )}
                              {match.last_decayed_at && (
                                <span className="text-amber-400/80">Decayed: {new Date(match.last_decayed_at).toLocaleDateString()}</span>
                              )}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 6: Evidence-Backed MITRE ATT&CK Coverage */}
              {activeTab === 'mitre' && (
                <div className="space-y-6">
                  {/* Limitations Warning Banner */}
                  <div className="p-3.5 bg-blue-950/30 border border-blue-500/30 rounded-xl flex items-start space-x-3 text-xs text-blue-200">
                    <Info className="w-4 h-4 text-blue-400 mt-0.5 shrink-0" />
                    <div className="space-y-1">
                      <span className="font-bold text-white uppercase tracking-wider text-[11px] block">
                        Evidence-Backed ATT&CK Coverage & Detection Scope
                      </span>
                      <p className="text-slate-300 leading-relaxed text-[11px]">
                        Technique mappings reflect verified telemetry and rule findings only. Absence of a mapping does not imply absence of malicious activity. Mappings do not guarantee causal or chronological sequence.
                      </p>
                    </div>
                  </div>

                  {/* Metric Overview Cards */}
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    <div className="p-4 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider mb-1">
                        Catalog Version
                      </span>
                      <div className="flex items-baseline space-x-2">
                        <span className="text-2xl font-bold font-mono text-purple-400">
                          {mitreCoverage?.catalog_version || 'v15.1'}
                        </span>
                        <span className="text-xs text-slate-400">Enterprise</span>
                      </div>
                      <span className="text-[11px] text-slate-500 block mt-1">
                        {mitreCoverage?.distinct_techniques_count ?? 0} Distinct Techniques
                      </span>
                    </div>

                    <div className="p-4 bg-surface rounded-xl border border-emerald-500/30">
                      <span className="text-[10px] uppercase font-bold text-emerald-400 block tracking-wider mb-1">
                        Mapped Findings
                      </span>
                      <div className="flex items-baseline space-x-2">
                        <span className="text-2xl font-bold font-mono text-emerald-400">
                          {mitreCoverage?.mapped_findings_count ?? 0}
                        </span>
                        <span className="text-xs text-emerald-500/80 font-medium">Evidence-Backed</span>
                      </div>
                      <span className="text-[11px] text-slate-500 block mt-1">
                        Verified with sensor events
                      </span>
                    </div>

                    <div className="p-4 bg-surface rounded-xl border border-amber-500/30">
                      <span className="text-[10px] uppercase font-bold text-amber-400 block tracking-wider mb-1">
                        Unmapped Findings
                      </span>
                      <div className="flex items-baseline space-x-2">
                        <span className="text-2xl font-bold font-mono text-amber-400">
                          {mitreCoverage?.unmapped_findings_count ?? 0}
                        </span>
                        <span className="text-xs text-amber-500/80 font-medium">Heuristic / Anomaly</span>
                      </div>
                      <span className="text-[11px] text-slate-500 block mt-1">
                        No speculative tags
                      </span>
                    </div>

                    <div className="p-4 bg-surface rounded-xl border border-slate-700">
                      <span className="text-[10px] uppercase font-bold text-slate-400 block tracking-wider mb-1">
                        Insufficient Evidence
                      </span>
                      <div className="flex items-baseline space-x-2">
                        <span className="text-2xl font-bold font-mono text-slate-300">
                          {mitreCoverage?.insufficient_evidence_count ?? 0}
                        </span>
                        <span className="text-xs text-slate-500 font-medium">Metadata-only</span>
                      </div>
                      <span className="text-[11px] text-slate-500 block mt-1">
                        Lacks backing telemetry
                      </span>
                    </div>
                  </div>

                  {/* Tactics Filter Bar */}
                  {mitreCoverage && Object.keys(mitreCoverage.tactics || {}).length > 0 && (
                    <div className="flex items-center space-x-2 overflow-x-auto pb-1 text-xs">
                      <span className="text-slate-400 text-[11px] uppercase font-mono shrink-0">Filter Tactic:</span>
                      <button
                        onClick={() => setSelectedTacticFilter('ALL')}
                        className={`px-3 py-1 rounded-full text-xs font-medium transition-colors shrink-0 ${
                          selectedTacticFilter === 'ALL'
                            ? 'bg-purple-600 text-white'
                            : 'bg-surface hover:bg-surface-elevated text-slate-300 border border-border'
                        }`}
                      >
                        All Tactics ({mitreCoverage.techniques?.length || 0})
                      </button>
                      {Object.entries(mitreCoverage.tactics).map(([tacticName, techs]) => (
                        <button
                          key={tacticName}
                          onClick={() => setSelectedTacticFilter(tacticName)}
                          className={`px-3 py-1 rounded-full text-xs font-medium transition-colors shrink-0 ${
                            selectedTacticFilter === tacticName
                              ? 'bg-purple-600 text-white'
                              : 'bg-surface hover:bg-surface-elevated text-slate-300 border border-border'
                          }`}
                        >
                          {tacticName} ({techs.length})
                        </button>
                      ))}
                    </div>
                  )}

                  {/* Filtered Techniques List */}
                  <div className="space-y-3">
                    <h3 className="text-xs font-bold uppercase tracking-wider text-slate-300 font-mono">
                      Adversary Techniques ({filteredTechniques.length}):
                    </h3>
                    {filteredTechniques.length === 0 ? (
                      <div className="p-8 bg-surface rounded-xl border border-border text-center text-slate-400 text-xs">
                        No MITRE ATT&CK techniques found for this selection.
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {filteredTechniques.map((tech) => (
                          <div
                            key={tech.technique_id}
                            className={`p-4 rounded-xl border bg-surface/90 flex flex-col justify-between space-y-3 ${
                              tech.mapping_state === 'MAPPED'
                                ? 'border-emerald-500/40 hover:border-emerald-500'
                                : 'border-slate-700 hover:border-slate-500'
                            } transition-colors`}
                          >
                            <div>
                              <div className="flex items-center justify-between">
                                <div className="flex items-center space-x-2">
                                  <span className="font-mono text-sm font-bold text-white bg-purple-950/70 border border-purple-500/50 px-2 py-0.5 rounded">
                                    {tech.technique_id}
                                  </span>
                                  <span
                                    className={`text-[10px] font-bold px-2 py-0.5 rounded uppercase font-mono ${
                                      tech.mapping_state === 'MAPPED'
                                        ? 'bg-emerald-950/70 text-emerald-400 border border-emerald-800'
                                        : 'bg-slate-800 text-slate-400 border border-slate-700'
                                    }`}
                                  >
                                    {tech.mapping_state}
                                  </span>
                                </div>
                                <span className="text-xs font-mono font-bold text-slate-400">
                                  {tech.confidence}% Conf.
                                </span>
                              </div>

                              <h4 className="text-sm font-semibold text-white mt-2">
                                {tech.technique_name}
                              </h4>

                              <div className="flex flex-wrap gap-1 mt-1.5">
                                {tech.tactics.map((tac) => (
                                  <span
                                    key={tac}
                                    className="text-[10px] font-mono bg-surface-elevated text-purple-300 px-2 py-0.5 rounded border border-border"
                                  >
                                    {tac}
                                  </span>
                                ))}
                              </div>

                              <p className="text-xs text-slate-300 mt-2 leading-relaxed bg-surface-elevated/50 p-2 rounded border border-border/40">
                                {tech.rationale}
                              </p>
                            </div>

                            <div className="pt-2 border-t border-border flex items-center justify-between text-xs">
                              {tech.evidence_event_ids && tech.evidence_event_ids.length > 0 ? (
                                <div className="flex items-center space-x-1.5">
                                  <span className="text-[11px] text-slate-400">Evidence:</span>
                                  <button
                                    onClick={() => {
                                      const evId = tech.evidence_event_ids[0];
                                      setTimelineEntityFilter(evId);
                                      setActiveTab('timeline');
                                    }}
                                    className="text-[11px] font-mono text-cyan-400 hover:text-cyan-200 underline font-semibold"
                                    title="Inspect evidence on timeline"
                                  >
                                    {tech.evidence_event_ids.length} Event Record(s)
                                  </button>
                                </div>
                              ) : (
                                <span className="text-[11px] text-slate-500 italic">No backing event record</span>
                              )}

                              {tech.reference_url && (
                                <a
                                  href={tech.reference_url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="flex items-center space-x-1 text-purple-400 hover:text-purple-200 font-mono text-[11px]"
                                >
                                  <span>ATT&CK Doc</span>
                                  <ExternalLink className="w-3 h-3" />
                                </a>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>

                  {/* Unmapped Findings Section */}
                  {mitreCoverage && mitreCoverage.unmapped_findings && mitreCoverage.unmapped_findings.length > 0 && (
                    <div className="p-4 bg-amber-950/20 border border-amber-500/30 rounded-xl space-y-3">
                      <div className="flex items-center space-x-2">
                        <AlertTriangle className="w-4 h-4 text-amber-400" />
                        <h4 className="text-xs font-bold text-amber-300 uppercase tracking-wider font-mono">
                          Unmapped Findings ({mitreCoverage.unmapped_findings.length})
                        </h4>
                      </div>
                      <p className="text-xs text-slate-300 leading-relaxed">
                        The following findings were triggered by behavioral anomalies or statistical baselines that do not carry explicit MITRE ATT&CK technique tags. Waliya-IR deliberately avoids speculative mapping.
                      </p>
                      <div className="space-y-2">
                        {mitreCoverage.unmapped_findings.map((uf) => (
                          <div
                            key={uf.finding_id}
                            className="p-3 bg-surface rounded-lg border border-border flex flex-col md:flex-row md:items-center justify-between text-xs gap-2"
                          >
                            <div>
                              <span className="font-mono text-cyan-300 font-bold block">{uf.rule_id}</span>
                              <span className="text-white font-medium">{uf.finding_title}</span>
                              <p className="text-[11px] text-slate-400 mt-0.5">{uf.reason}</p>
                            </div>
                            {uf.evidence_event_ids && uf.evidence_event_ids.length > 0 && (
                              <button
                                onClick={() => {
                                  setTimelineEntityFilter(uf.evidence_event_ids[0]);
                                  setActiveTab('timeline');
                                }}
                                className="px-2.5 py-1 rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 text-[11px] font-mono shrink-0 font-semibold"
                              >
                                View Event Evidence
                              </button>
                            )}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Limitations Section */}
                  {mitreCoverage && mitreCoverage.limitations && mitreCoverage.limitations.length > 0 && (
                    <div className="p-4 bg-surface rounded-xl border border-border space-y-2">
                      <span className="text-[10px] font-mono uppercase font-bold text-slate-400 block tracking-wider">
                        Platform Transparency & Coverage Boundaries
                      </span>
                      <ul className="space-y-1 text-xs text-slate-400 list-disc list-inside">
                        {mitreCoverage.limitations.map((lim, idx) => (
                          <li key={idx} className="leading-relaxed">
                            {lim}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              )}

              {/* Sub-Tab 7: Unified Incident Reconstruction & Forensic Integrity */}
              {activeTab === 'reconstruction' && (
                <div className="space-y-6">
                  {/* Integrity Banner */}
                  {reconstructionData?.consistency_report && (
                    <div
                      className={`p-4 rounded-xl border flex items-start space-x-3.5 ${
                        reconstructionData.consistency_report.is_consistent
                          ? 'bg-emerald-950/20 border-emerald-500/30 text-emerald-200'
                          : 'bg-rose-950/30 border-rose-500/40 text-rose-200'
                      }`}
                    >
                      {reconstructionData.consistency_report.is_consistent ? (
                        <CheckCircle2 className="w-5 h-5 text-emerald-400 mt-0.5 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-rose-400 mt-0.5 shrink-0" />
                      )}
                      <div className="space-y-1.5 flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-semibold text-sm">
                            {reconstructionData.consistency_report.is_consistent
                              ? 'Cross-Layer Evidence Integrity Verified'
                              : 'Cross-Layer Evidence Inconsistencies Detected'}
                          </span>
                          <span className="text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-surface border border-border text-slate-300">
                            {reconstructionData.consistency_report.checks_run} Automated Checks Run
                          </span>
                        </div>
                        <p className="text-xs text-slate-300 leading-relaxed">
                          {reconstructionData.consistency_report.is_consistent
                            ? 'All 12 consistency validations passed: Entity references, evidence provenance, attack path validity, ATT&CK catalog mapping, simulation isolation, and immutable timestamps.'
                            : 'One or more cross-layer consistency checks failed. Review discrepancies below.'}
                        </p>
                        {reconstructionData.consistency_report.inconsistencies.length > 0 && (
                          <div className="mt-2 space-y-1">
                            {reconstructionData.consistency_report.inconsistencies.map((err, idx) => (
                              <div
                                key={idx}
                                className="text-[11px] font-mono bg-rose-950/50 p-2 rounded border border-rose-800/40 text-rose-300"
                              >
                                {err}
                              </div>
                            ))}
                          </div>
                        )}
                        {reconstructionData.consistency_report.warnings.length > 0 && (
                          <div className="mt-1 space-y-1">
                            {reconstructionData.consistency_report.warnings.map((warn, idx) => (
                              <div
                                key={idx}
                                className="text-[11px] text-amber-300/90 flex items-center space-x-1.5"
                              >
                                <span className="font-mono text-amber-400 font-bold">•</span>
                                <span>{warn}</span>
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Summary Metric Cards */}
                  <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase font-bold text-slate-400 block tracking-wider">
                        Observations
                      </span>
                      <span className="text-xl font-bold font-mono text-white mt-1 block">
                        {reconstructionData?.coverage_summary?.total_observations || 0}
                      </span>
                      <span className="text-[10px] text-slate-400 mt-0.5 block">Chronological items</span>
                    </div>

                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase font-bold text-blue-400 block tracking-wider">
                        Direct Telemetry
                      </span>
                      <span className="text-xl font-bold font-mono text-blue-300 mt-1 block">
                        {reconstructionData?.coverage_summary?.chronological_events_count || 0}
                      </span>
                      <span className="text-[10px] text-slate-400 mt-0.5 block">Raw events</span>
                    </div>

                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase font-bold text-purple-400 block tracking-wider">
                        Findings
                      </span>
                      <span className="text-xl font-bold font-mono text-purple-300 mt-1 block">
                        {reconstructionData?.coverage_summary?.correlated_findings_count || 0}
                      </span>
                      <span className="text-[10px] text-slate-400 mt-0.5 block">Rule interpretations</span>
                    </div>

                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase font-bold text-amber-400 block tracking-wider">
                        ATT&CK Mapped
                      </span>
                      <span className="text-xl font-bold font-mono text-amber-300 mt-1 block">
                        {reconstructionData?.coverage_summary?.mapped_techniques_count || 0}
                      </span>
                      <span className="text-[10px] text-slate-400 mt-0.5 block">Backed techniques</span>
                    </div>

                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase font-bold text-emerald-400 block tracking-wider">
                        Graph Entities
                      </span>
                      <span className="text-xl font-bold font-mono text-emerald-300 mt-1 block">
                        {reconstructionData?.coverage_summary?.graph_entities_count || 0}
                      </span>
                      <span className="text-[10px] text-slate-400 mt-0.5 block">Correlated nodes</span>
                    </div>

                    <div className="p-3 bg-surface rounded-xl border border-border">
                      <span className="text-[10px] font-mono uppercase font-bold text-rose-400 block tracking-wider">
                        Candidate Paths
                      </span>
                      <span className="text-xl font-bold font-mono text-rose-300 mt-1 block">
                        {reconstructionData?.coverage_summary?.candidate_attack_paths_count || 0}
                      </span>
                      <span className="text-[10px] text-slate-400 mt-0.5 block">Hypotheses</span>
                    </div>
                  </div>

                  {/* Distinction Banner: Chronology vs Attack Progression */}
                  <div className="p-3.5 bg-surface-elevated/70 border border-border rounded-xl space-y-2">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center space-x-2">
                        <Info className="w-4 h-4 text-emerald-400 shrink-0" />
                        <span className="text-xs font-semibold text-slate-200">
                          Forensic Investigation Perspective
                        </span>
                      </div>
                      <div className="flex items-center space-x-1.5 bg-surface p-1 rounded-lg border border-border">
                        <button
                          onClick={() => setReconActiveView('chronology')}
                          className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                            reconActiveView === 'chronology'
                              ? 'bg-blue-600 text-white shadow'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          Observed Chronology
                        </button>
                        <button
                          onClick={() => setReconActiveView('progression')}
                          className={`px-3 py-1 rounded text-xs font-semibold transition-colors ${
                            reconActiveView === 'progression'
                              ? 'bg-purple-600 text-white shadow'
                              : 'text-slate-400 hover:text-white'
                          }`}
                        >
                          Candidate Attack Progression ({reconstructionData?.candidate_progressions?.length || 0})
                        </button>
                      </div>
                    </div>
                    <p className="text-[11px] text-slate-400 leading-relaxed">
                      <strong className="text-slate-300">Important distinction:</strong>{' '}
                      {reconActiveView === 'chronology'
                        ? 'Observed Chronology displays recorded telemetry events and findings in verified arrival order without assuming causality.'
                        : 'Candidate Attack Progression represents structural reachability discovered in the entity correlation graph. Reachability indicates potential pathways but does not prove a single confirmed causal execution chain.'}
                    </p>
                  </div>

                  {/* View 1: Observed Chronology */}
                  {reconActiveView === 'chronology' && (
                    <div className="space-y-4">
                      {/* Sub-Filter Bar */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-2">
                          <span className="text-xs font-semibold text-slate-400">Filter Observations:</span>
                          {(['ALL', 'EVENT', 'FINDING'] as const).map((filterType) => (
                            <button
                              key={filterType}
                              onClick={() => setReconFilter(filterType)}
                              className={`px-2.5 py-1 rounded text-xs font-semibold border transition-colors ${
                                reconFilter === filterType
                                  ? 'bg-surface-elevated text-white border-blue-500'
                                  : 'bg-surface text-slate-400 border-border hover:text-slate-200'
                              }`}
                            >
                              {filterType === 'ALL'
                                ? 'All Observations'
                                : filterType === 'EVENT'
                                ? 'Direct Telemetry'
                                : 'Correlated Findings'}
                            </button>
                          ))}
                        </div>
                        <span className="text-xs text-slate-400 font-mono">
                          Showing {filteredReconTimeline.length} of{' '}
                          {reconstructionData?.timeline?.length || 0} items
                        </span>
                      </div>

                      {/* Chronological Feed */}
                      {filteredReconTimeline.length === 0 ? (
                        <div className="p-8 bg-surface rounded-xl border border-border text-center text-slate-400 text-sm">
                          No observations match the selected filter.
                        </div>
                      ) : (
                        <div className="space-y-3">
                          {filteredReconTimeline.map((item) => (
                            <div
                              key={item.item_id}
                              className={`p-4 rounded-xl border transition-all ${
                                selectedReconItem?.item_id === item.item_id
                                  ? 'bg-surface-elevated border-blue-500 ring-1 ring-blue-500/50'
                                  : 'bg-surface border-border hover:border-slate-600'
                              }`}
                            >
                              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-border/50">
                                <div className="flex flex-wrap items-center gap-2">
                                  {/* Timestamp */}
                                  <span className="text-xs font-mono font-bold text-slate-300 bg-surface-elevated px-2 py-0.5 rounded border border-border">
                                    {item.timestamp ? new Date(item.timestamp).toISOString() : 'Timestamp Missing'}
                                  </span>
                                  {/* Evidence Type */}
                                  <span
                                    className={`text-[10px] font-mono px-2 py-0.5 rounded font-bold border ${
                                      item.is_interpretation
                                        ? 'bg-purple-950/80 text-purple-400 border-purple-800'
                                        : 'bg-blue-950/80 text-blue-400 border-blue-800'
                                    }`}
                                  >
                                    {item.is_interpretation
                                      ? 'CORRELATED FINDING (INTERPRETATION)'
                                      : 'DIRECT TELEMETRY (FACTUAL EVIDENCE)'}
                                  </span>
                                  {/* Severity */}
                                  <span
                                    className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold uppercase ${
                                      item.severity === 'CRITICAL'
                                        ? 'bg-rose-950/80 text-rose-400 border border-rose-800'
                                        : item.severity === 'HIGH'
                                        ? 'bg-orange-950/80 text-orange-400 border border-orange-800'
                                        : item.severity === 'MEDIUM'
                                        ? 'bg-amber-950/80 text-amber-400 border border-amber-800'
                                        : 'bg-slate-800 text-slate-300'
                                    }`}
                                  >
                                    {item.severity}
                                  </span>
                                  {/* Source */}
                                  <span className="text-[10px] font-mono text-slate-400 bg-surface px-1.5 py-0.5 rounded border border-border">
                                    src: {item.source}
                                  </span>
                                </div>

                                <button
                                  onClick={() => setSelectedReconItem(item)}
                                  className="px-2.5 py-1 text-xs font-semibold rounded bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 shrink-0 self-start sm:self-auto"
                                >
                                  Inspect Evidence
                                </button>
                              </div>

                              <div className="mt-2.5 space-y-2">
                                <div className="text-sm font-semibold text-white">{item.title}</div>
                                <p className="text-xs text-slate-300 leading-relaxed">{item.explanation}</p>

                                {/* Associated Entities & MITRE badges */}
                                <div className="flex flex-wrap items-center gap-1.5 pt-1">
                                  {item.associated_entity_ids.map((ent) => (
                                    <span
                                      key={ent}
                                      className="text-[10px] font-mono bg-surface-elevated text-slate-300 px-1.5 py-0.5 rounded border border-border"
                                    >
                                      {ent}
                                    </span>
                                  ))}

                                  {item.associated_graph_edges.map((edge, eidx) => (
                                    <span
                                      key={eidx}
                                      className="text-[10px] font-mono bg-emerald-950/40 text-emerald-300 px-1.5 py-0.5 rounded border border-emerald-800/40"
                                    >
                                      {edge}
                                    </span>
                                  ))}

                                  {item.mitre_techniques.map((tech) => (
                                    <span
                                      key={tech.technique_id}
                                      className="text-[10px] font-mono bg-purple-950/60 text-purple-300 px-1.5 py-0.5 rounded border border-purple-800/50 font-bold"
                                    >
                                      {tech.technique_id} - {tech.technique_name}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  )}

                  {/* View 2: Candidate Attack Progression */}
                  {reconActiveView === 'progression' && (
                    <div className="space-y-4">
                      {(!reconstructionData?.candidate_progressions ||
                        reconstructionData.candidate_progressions.length === 0) ? (
                        <div className="p-8 bg-surface rounded-xl border border-border text-center text-slate-400 text-sm">
                          No candidate attack paths discovered in current incident entity graph.
                        </div>
                      ) : (
                        reconstructionData.candidate_progressions.map((prog) => (
                          <div key={prog.path_id} className="p-4 bg-surface rounded-xl border border-border space-y-3">
                            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-2 border-b border-border">
                              <div className="flex items-center space-x-2">
                                <span className="text-xs font-mono font-bold text-white bg-surface-elevated px-2 py-0.5 rounded border border-border">
                                  Path: {prog.path_id}
                                </span>
                                <span className="text-xs text-slate-300">
                                  {prog.entry_node} <ArrowRight className="inline w-3 h-3 mx-1 text-slate-400" />{' '}
                                  {prog.target_node}
                                </span>
                              </div>
                              <div className="flex items-center space-x-2">
                                <span className="text-[10px] font-mono text-slate-400 bg-surface-elevated px-2 py-0.5 rounded border border-border">
                                  {prog.hop_count} Hops
                                </span>
                                <span className="text-[10px] font-mono font-bold text-purple-400 bg-purple-950/80 px-2 py-0.5 rounded border border-purple-800">
                                  Confidence: {Math.round(prog.confidence * 100)}%
                                </span>
                              </div>
                            </div>

                            <p className="text-xs text-slate-400 italic bg-surface-elevated/40 p-2 rounded border border-border/50">
                              {prog.disclaimer}
                            </p>

                            {/* Progression Steps */}
                            <div className="space-y-2">
                              <span className="text-[10px] font-mono uppercase font-bold text-slate-400 block tracking-wider">
                                Traversal Steps
                              </span>
                              <div className="space-y-1.5">
                                {prog.steps.map((st) => (
                                  <div
                                    key={st.step_order}
                                    className="p-2.5 bg-surface-elevated rounded-lg border border-border flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs"
                                  >
                                    <div className="flex items-center space-x-2">
                                      <span className="font-mono text-slate-500 font-bold shrink-0">
                                        #{st.step_order}
                                      </span>
                                      <span className="font-mono text-blue-300 font-semibold">{st.source}</span>
                                      <span className="text-slate-400 font-mono text-[10px] px-1.5 py-0.5 rounded bg-surface border border-border">
                                        -[{st.relation}]-&gt;
                                      </span>
                                      <span className="font-mono text-emerald-300 font-semibold">{st.target}</span>
                                    </div>

                                    {st.mitre_techniques && st.mitre_techniques.length > 0 && (
                                      <div className="flex flex-wrap items-center gap-1">
                                        {st.mitre_techniques.map((mt) => (
                                          <span
                                            key={mt.technique_id}
                                            className="text-[10px] font-mono bg-purple-950/60 text-purple-300 px-1.5 py-0.5 rounded border border-purple-800/40"
                                          >
                                            {mt.technique_id}
                                          </span>
                                        ))}
                                      </div>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                        ))
                      )}
                    </div>
                  )}

                  {/* Incomplete Evidence & Limitations */}
                  <div className="p-4 bg-surface rounded-xl border border-border space-y-3">
                    <span className="text-[10px] font-mono uppercase font-bold text-slate-400 block tracking-wider">
                      Transparent Evidentiary Boundaries & Incomplete Records
                    </span>

                    {reconstructionData?.incomplete_evidence?.uncertainties &&
                      reconstructionData.incomplete_evidence.uncertainties.length > 0 && (
                        <div className="space-y-1.5">
                          {reconstructionData.incomplete_evidence.uncertainties.map((unc, uidx) => (
                            <div key={uidx} className="text-xs text-amber-300/90 flex items-start space-x-2">
                              <span className="font-mono text-amber-400 font-bold mt-0.5">•</span>
                              <span className="leading-relaxed">{unc}</span>
                            </div>
                          ))}
                        </div>
                      )}

                    {reconstructionData?.limitations && (
                      <ul className="space-y-1 text-xs text-slate-400 list-disc list-inside pt-1">
                        {reconstructionData.limitations.map((lim, lidx) => (
                          <li key={lidx} className="leading-relaxed">
                            {lim}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Forensic Evidence Detail Drawer */}
      {selectedReconItem && (
        <div className="fixed inset-0 z-50 flex items-center justify-end bg-black/60 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg h-full bg-[#0d1322] border-l border-border shadow-2xl p-6 overflow-y-auto space-y-5">
            <div className="flex items-center justify-between pb-3 border-b border-border">
              <div className="space-y-0.5">
                <span className="text-[10px] font-mono uppercase font-bold text-slate-400">
                  Forensic Observation Details
                </span>
                <h3 className="text-sm font-bold text-white">{selectedReconItem.title}</h3>
              </div>
              <button
                onClick={() => setSelectedReconItem(null)}
                className="text-slate-400 hover:text-white p-1 rounded hover:bg-surface"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Factual vs Interpretation Banner */}
            <div
              className={`p-3 rounded-lg border text-xs leading-relaxed ${
                selectedReconItem.is_interpretation
                  ? 'bg-purple-950/40 border-purple-500/30 text-purple-200'
                  : 'bg-blue-950/40 border-blue-500/30 text-blue-200'
              }`}
            >
              <strong>
                {selectedReconItem.is_interpretation
                  ? 'Analytic Detection Finding:'
                  : 'Direct Telemetry Event:'}
              </strong>{' '}
              {selectedReconItem.is_interpretation
                ? 'This record represents a rule-based evaluation or behavioral model interpretation.'
                : 'This record represents raw immutable telemetry captured from monitored endpoint infrastructure.'}
            </div>

            {/* Properties */}
            <div className="space-y-3 text-xs">
              <div>
                <span className="text-slate-400 block text-[10px] font-mono uppercase font-bold">Identifier</span>
                <span className="font-mono text-slate-200 break-all">{selectedReconItem.item_id}</span>
              </div>

              <div>
                <span className="text-slate-400 block text-[10px] font-mono uppercase font-bold">Timestamp</span>
                <span className="font-mono text-slate-200">
                  {selectedReconItem.timestamp
                    ? new Date(selectedReconItem.timestamp).toISOString()
                    : 'Not Available'}
                </span>
              </div>

              <div>
                <span className="text-slate-400 block text-[10px] font-mono uppercase font-bold">Source Component</span>
                <span className="font-mono text-slate-200">{selectedReconItem.source}</span>
              </div>

              <div>
                <span className="text-slate-400 block text-[10px] font-mono uppercase font-bold">Explanation</span>
                <p className="text-slate-200 leading-relaxed mt-0.5">{selectedReconItem.explanation}</p>
              </div>

              {selectedReconItem.associated_entity_ids.length > 0 && (
                <div>
                  <span className="text-slate-400 block text-[10px] font-mono uppercase font-bold">
                    Associated Entities
                  </span>
                  <div className="flex flex-wrap gap-1 mt-1">
                    {selectedReconItem.associated_entity_ids.map((ent) => (
                      <span
                        key={ent}
                        className="font-mono text-[11px] bg-surface text-slate-200 px-2 py-0.5 rounded border border-border"
                      >
                        {ent}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedReconItem.mitre_techniques.length > 0 && (
                <div>
                  <span className="text-slate-400 block text-[10px] font-mono uppercase font-bold">
                    MITRE ATT&CK Techniques
                  </span>
                  <div className="space-y-1.5 mt-1">
                    {selectedReconItem.mitre_techniques.map((tech) => (
                      <div
                        key={tech.technique_id}
                        className="p-2 bg-surface rounded border border-purple-500/30 flex items-center justify-between"
                      >
                        <span className="font-mono text-purple-300 font-bold">
                          {tech.technique_id} - {tech.technique_name}
                        </span>
                        {tech.reference_url && (
                          <a
                            href={tech.reference_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-purple-400 hover:text-purple-300 inline-flex items-center space-x-1"
                          >
                            <ExternalLink className="w-3 h-3" />
                          </a>
                        )}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {Object.keys(selectedReconItem.raw_attributes).length > 0 && (
                <div>
                  <span className="text-slate-400 block text-[10px] font-mono uppercase font-bold">
                    Telemetry Attributes
                  </span>
                  <pre className="mt-1 p-2 bg-surface rounded border border-border font-mono text-[11px] text-slate-300 overflow-x-auto">
                    {JSON.stringify(selectedReconItem.raw_attributes, null, 2)}
                  </pre>
                </div>
              )}
            </div>

            {/* Quick-Jump Actions */}
            <div className="pt-4 border-t border-border space-y-2">
              <span className="text-[10px] font-mono uppercase font-bold text-slate-400 block">
                Quick-Jump Investigation Actions
              </span>
              <div className="grid grid-cols-2 gap-2">
                <button
                  onClick={() => {
                    setTimelineEntityFilter(selectedReconItem.item_id);
                    setActiveTab('timeline');
                    setSelectedReconItem(null);
                  }}
                  className="px-3 py-2 bg-blue-600/20 hover:bg-blue-600/30 text-blue-300 border border-blue-500/30 rounded text-xs font-semibold"
                >
                  Jump to Timeline
                </button>
                <button
                  onClick={() => {
                    setActiveTab('graph');
                    setSelectedReconItem(null);
                  }}
                  className="px-3 py-2 bg-emerald-600/20 hover:bg-emerald-600/30 text-emerald-300 border border-emerald-500/30 rounded text-xs font-semibold"
                >
                  Jump to Attack Graph
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Status Transition Modal */}
      {isStatusModalOpen && incidentDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="w-full max-w-md bg-[#0d1322] border border-border rounded-xl shadow-2xl p-6 relative">
            <button
              onClick={() => setIsStatusModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <h3 className="text-base font-bold text-white mb-1">
              Transition Status: #{incidentDetail.incident_number}
            </h3>
            <p className="text-xs text-slate-400 mb-4">
              Current lifecycle state: <strong className="text-white">{incidentDetail.status}</strong>
            </p>

            <form onSubmit={handleStatusSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Target Status
                </label>
                <select
                  value={newStatus}
                  onChange={(e) => setNewStatus(e.target.value as IncidentStatus)}
                  className="w-full bg-surface border border-border rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                >
                  <option value="OPEN">OPEN</option>
                  <option value="INVESTIGATING">INVESTIGATING</option>
                  <option value="CONTAINED">CONTAINED</option>
                  <option value="RESOLVED">RESOLVED</option>
                  <option value="CLOSED">CLOSED</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1.5">
                  Investigation Note (Optional)
                </label>
                <textarea
                  value={statusNote}
                  onChange={(e) => setStatusNote(e.target.value)}
                  placeholder="Provide forensic findings, containment rationale, or mitigation details..."
                  rows={3}
                  maxLength={1000}
                  className="w-full bg-surface border border-border rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none"
                />
              </div>

              {(newStatus === 'RESOLVED' || newStatus === 'CLOSED') && (
                <div className="p-3 bg-amber-950/40 border border-amber-800/60 rounded-lg text-[11px] text-amber-300">
                  Resolving or closing this incident records a closure timestamp in the audit ledger.
                </div>
              )}

              <div className="flex items-center justify-end space-x-3 pt-2">
                <button
                  type="button"
                  onClick={() => setIsStatusModalOpen(false)}
                  className="px-4 py-2 rounded-lg text-xs font-medium text-slate-400 hover:bg-surface-elevated"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={statusSubmitting}
                  className="px-5 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50"
                >
                  {statusSubmitting ? 'Updating...' : 'Confirm Transition'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Explainable Risk Modal */}
      {isRiskModalOpen && incidentDetail && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4">
          <div className="w-full max-w-lg bg-[#0d1322] border border-border rounded-xl shadow-2xl p-6 relative">
            <button
              onClick={() => setIsRiskModalOpen(false)}
              className="absolute top-4 right-4 text-slate-400 hover:text-white"
            >
              <X className="w-5 h-5" />
            </button>

            <div className="flex items-center space-x-3 mb-4">
              <div className="p-2.5 rounded-lg bg-blue-600/15 border border-blue-500/30 text-blue-400">
                <Activity className="w-6 h-6" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">
                  Explainable Risk Score Breakdown
                </h3>
                <p className="text-xs text-slate-400">
                  Mathematical derivation for Incident #{incidentDetail.incident_number}
                </p>
              </div>
            </div>

            <div className="space-y-4">
              <div className="p-3.5 rounded-lg bg-blue-950/40 border border-blue-800/60 flex items-center justify-between">
                <span className="text-xs font-semibold text-white">Composite Risk Score</span>
                <span
                  className={`text-2xl font-black font-mono ${getRiskScoreColor(
                    incidentDetail.composite_risk_score
                  )}`}
                >
                  {incidentDetail.composite_risk_score.toFixed(1)} / 100.0
                </span>
              </div>

              {/* Factors Grid */}
              <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
                <div className="p-2.5 bg-surface rounded border border-border/60">
                  <span className="text-slate-400 block text-[10px]">Base Severity & Weight</span>
                  <span className="text-white font-bold">
                    {incidentDetail.risk_explanation.base_severity || 'LOW'} (
                    {incidentDetail.risk_explanation.base_weight || 30.0})
                  </span>
                </div>
                <div className="p-2.5 bg-surface rounded border border-border/60">
                  <span className="text-slate-400 block text-[10px]">Confidence Factor</span>
                  <span className="text-cyan-400 font-bold">
                    {incidentDetail.risk_explanation.confidence_factor ?? 1.0}
                  </span>
                </div>
                <div className="p-2.5 bg-surface rounded border border-border/60">
                  <span className="text-slate-400 block text-[10px]">Multi-Entity Multiplier</span>
                  <span className="text-purple-400 font-bold">
                    {incidentDetail.risk_explanation.multi_entity_multiplier ?? 1.0}x
                  </span>
                </div>
                <div className="p-2.5 bg-surface rounded border border-border/60">
                  <span className="text-slate-400 block text-[10px]">Multi-Stage ATT&CK Bonus</span>
                  <span className="text-amber-400 font-bold">
                    +{incidentDetail.risk_explanation.multi_stage_bonus ?? 0.0}
                  </span>
                </div>
                <div className="p-2.5 bg-surface rounded border border-border/60">
                  <span className="text-slate-400 block text-[10px]">Behavioral Anomaly Bonus</span>
                  <span className="text-rose-400 font-bold">
                    +{incidentDetail.risk_explanation.anomaly_bonus ?? 0.0}
                  </span>
                </div>
                <div className="p-2.5 bg-surface rounded border border-border/60">
                  <span className="text-slate-400 block text-[10px]">Threat Intel Bonus</span>
                  <span className="text-rose-400 font-bold">
                    +{incidentDetail.risk_explanation.threat_intel_bonus ?? 0.0}
                    {incidentDetail.risk_explanation.threat_intel_confidence ? ` (${incidentDetail.risk_explanation.threat_intel_confidence}%)` : ''}
                  </span>
                </div>
                <div className="p-2.5 bg-surface rounded border border-border/60">
                  <span className="text-slate-400 block text-[10px]">Asset Importance Bonus</span>
                  <span className="text-emerald-400 font-bold">
                    +{incidentDetail.risk_explanation.asset_importance_bonus ?? 0.0}
                    {incidentDetail.risk_explanation.asset_criticality ? ` [${incidentDetail.risk_explanation.asset_criticality}]` : ''}
                  </span>
                </div>
                <div className="p-2.5 bg-surface rounded border border-border/60">
                  <span className="text-slate-400 block text-[10px]">Unique / Raw Findings</span>
                  <span className="text-blue-400 font-bold">
                    {incidentDetail.risk_explanation.unique_findings_count ?? incidentDetail.findings_count} /{' '}
                    {incidentDetail.risk_explanation.raw_findings_count ?? incidentDetail.findings_count}
                  </span>
                </div>
              </div>

              {/* Matched Threat Intelligence Indicators in Modal */}
              {threatIntelSummary && threatIntelSummary.matches && threatIntelSummary.matches.length > 0 && (
                <div className="p-3 bg-surface rounded-lg border border-border/60 space-y-2">
                  <span className="text-[10px] uppercase font-mono text-rose-400 font-bold block">
                    Associated Threat Intelligence Matches ({threatIntelSummary.matches.length}):
                  </span>
                  <div className="space-y-1.5 max-h-36 overflow-y-auto pr-1">
                    {threatIntelSummary.matches.map((m, idx) => (
                      <div key={idx} className="flex items-center justify-between text-xs font-mono p-1.5 bg-surface-elevated/40 rounded border border-border/40">
                        <div className="flex items-center space-x-2 truncate">
                          <span className="text-[9px] px-1 py-0.2 bg-blue-500/20 text-blue-400 rounded">
                            {m.indicator_type}
                          </span>
                          <span className="text-white truncate max-w-[200px]">{m.value}</span>
                        </div>
                        <div className="flex items-center space-x-2 text-[10px] whitespace-nowrap">
                          <span className="text-purple-400">{m.source}</span>
                          <span className="text-amber-400 font-bold">{m.current_confidence}%</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Human-readable rationale */}
              <div className="p-3 bg-surface-elevated/40 rounded border border-border/60">
                <span className="text-[10px] uppercase font-mono text-slate-400 block mb-1">
                  Decision Rationale:
                </span>
                <p className="text-xs text-slate-300 leading-relaxed font-sans">
                  {incidentDetail.risk_explanation.decision_reason ||
                    'Score derived from baseline alerts, entity diversity, and MITRE kill-chain coverage.'}
                </p>
              </div>

              <div className="flex justify-end pt-2">
                <button
                  onClick={() => setIsRiskModalOpen(false)}
                  className="px-5 py-2 rounded-lg text-xs font-semibold bg-surface-elevated hover:bg-slate-700 text-white border border-border"
                >
                  Close
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};
