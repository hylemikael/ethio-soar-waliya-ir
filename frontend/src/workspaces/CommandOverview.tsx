import React, { useState, useEffect, useCallback, useRef } from 'react';
import {
  Activity,
  Radio,
  HardDrive,
  ShieldAlert,
  ShieldCheck,
  AlertOctagon,
  RefreshCw,
  ArrowRight,
  Database,
  Cpu,
  Layers,
  Lock,
  Clock,
  CheckCircle2,
  AlertTriangle,
} from 'lucide-react';
import { apiClient, ApiError } from '../api/client';
import { SystemOverviewResponse, SystemDiagnosticsResponse, Severity } from '../types';
import { WorkspaceId } from '../components/Header';
import { EmptyState } from '../components/EmptyState';

interface CommandOverviewProps {
  onSelectWorkspace: (workspace: WorkspaceId, incidentId?: string) => void;
  onOpenLogin: () => void;
  isAuthenticated: boolean;
}

export const CommandOverview: React.FC<CommandOverviewProps> = ({
  onSelectWorkspace,
  onOpenLogin,
  isAuthenticated,
}) => {
  const [overview, setOverview] = useState<SystemOverviewResponse | null>(null);
  const [diagnostics, setDiagnostics] = useState<SystemDiagnosticsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [authRequired, setAuthRequired] = useState(false);
  const isFetchingRef = useRef(false);

  const fetchOverview = useCallback(async (isManual = false) => {
    if (isFetchingRef.current) return;
    isFetchingRef.current = true;

    if (isManual) {
      setRefreshing(true);
    }

    try {
      const data = await apiClient.getOverview();
      setOverview(data);
      setError(null);
      setAuthRequired(false);

      try {
        const diagData = await apiClient.getSystemDiagnostics();
        setDiagnostics(diagData);
      } catch {
        // Diagnostics requires admin auth; handle gracefully
      }
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 401 || err.status === 403) {
          setAuthRequired(true);
          setError('Administrative authentication required to view live operational overview.');
        } else {
          setError(`Backend service error: ${err.message}`);
        }
      } else {
        setError('Unable to connect to Waliya-IR backend services.');
      }
    } finally {
      setLoading(false);
      setRefreshing(false);
      isFetchingRef.current = false;
    }
  }, []);

  useEffect(() => {
    fetchOverview();
    const timer = setInterval(() => {
      fetchOverview();
    }, 15000);

    return () => {
      clearInterval(timer);
    };
  }, [fetchOverview]);

  // Re-fetch when authentication state changes
  useEffect(() => {
    if (isAuthenticated) {
      fetchOverview(true);
    }
  }, [isAuthenticated, fetchOverview]);

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

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-600 font-bold';
    if (score >= 60) return 'text-amber-600 font-semibold';
    if (score >= 40) return 'text-yellow-600 font-medium';
    return 'text-emerald-600';
  };

  if (loading && !overview) {
    return (
      <div className="space-y-6">
        <div className="h-24 bg-gray-50 rounded-lg border border-gray-200 animate-pulse" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-28 bg-gray-50 rounded-lg border border-gray-200 animate-pulse" />
          ))}
        </div>
        <div className="h-64 bg-gray-50 rounded-lg border border-gray-200 animate-pulse" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Auth Banner if unauthenticated */}
      {authRequired && (
        <div className="p-4 rounded-lg border border-blue-200 bg-blue-50/60 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded bg-blue-100 text-blue-700">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-semibold text-gray-900">Administrator Authentication Required</h4>
              <p className="text-xs text-gray-600">
                Live operational telemetry and incident metrics require an authenticated session.
              </p>
            </div>
          </div>
          <button
            onClick={onOpenLogin}
            className="flex items-center space-x-1.5 px-3.5 py-2 rounded text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white shadow-sm transition-colors"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Sign In to Unlock Live Data</span>
          </button>
        </div>
      )}

      {/* Backend Unreachable Banner */}
      {error && !authRequired && (
        <div className="p-4 rounded-lg border border-red-200 bg-red-50/60 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="w-5 h-5 text-red-600" />
            <div>
              <h4 className="text-sm font-semibold text-gray-900">Telemetry Pipeline Warning</h4>
              <p className="text-xs text-red-700">{error}</p>
            </div>
          </div>
          <button
            onClick={() => fetchOverview(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-medium bg-white hover:bg-red-50 text-red-700 border border-red-300 transition-colors shadow-sm"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Retry</span>
          </button>
        </div>
      )}

      {/* Security Posture Banner */}
      {overview && (
        <div
          className={`p-4 rounded-lg border bg-white shadow-sm transition-all ${
            overview.security_posture === 'CRITICAL'
              ? 'border-l-4 border-l-red-600 border-gray-200 bg-red-50/20'
              : overview.security_posture === 'ELEVATED'
              ? 'border-l-4 border-l-amber-500 border-gray-200 bg-amber-50/20'
              : 'border-l-4 border-l-emerald-600 border-gray-200'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <div
                className={`p-2.5 rounded-lg border ${
                  overview.security_posture === 'CRITICAL'
                    ? 'bg-red-50 text-red-700 border-red-200'
                    : overview.security_posture === 'ELEVATED'
                    ? 'bg-amber-50 text-amber-700 border-amber-200'
                    : 'bg-emerald-50 text-emerald-700 border-emerald-200'
                }`}
              >
                {overview.security_posture === 'CRITICAL' ? (
                  <ShieldAlert className="w-7 h-7" />
                ) : overview.security_posture === 'ELEVATED' ? (
                  <AlertOctagon className="w-7 h-7" />
                ) : (
                  <ShieldCheck className="w-7 h-7" />
                )}
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs uppercase tracking-wider text-gray-500 font-medium">
                    Defensive Posture:
                  </span>
                  <span
                    className={`text-xs font-bold px-2 py-0.5 rounded border uppercase ${
                      overview.security_posture === 'CRITICAL'
                        ? 'bg-red-100 text-red-800 border-red-200'
                        : overview.security_posture === 'ELEVATED'
                        ? 'bg-amber-100 text-amber-800 border-amber-200'
                        : 'bg-emerald-100 text-emerald-800 border-emerald-200'
                    }`}
                  >
                    {overview.security_posture}
                  </span>
                </div>
                <p className="text-sm font-semibold text-gray-900 mt-1">{overview.posture_reason}</p>
                <div className="flex items-center space-x-3 text-xs text-gray-500 mt-1">
                  <span className="flex items-center space-x-1">
                    <Clock className="w-3 h-3 text-gray-400" />
                    <span>Updated: {new Date(overview.generated_at).toLocaleTimeString()}</span>
                  </span>
                  <span>&bull;</span>
                  <span>Polling: 15s</span>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={() => fetchOverview(true)}
                disabled={refreshing}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded text-xs font-medium bg-white hover:bg-gray-50 text-gray-700 border border-gray-300 shadow-sm transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${refreshing ? 'animate-spin' : ''}`} />
                <span>{refreshing ? 'Refreshing...' : 'Refresh'}</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Top Stat Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {/* Agents Card */}
        <div className="p-4 rounded-lg border border-gray-200 bg-white shadow-sm">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-medium text-gray-500">Connected Agents</span>
            <Radio className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-gray-900">
              {overview ? overview.agents.online : 0}
            </span>
            <span className="text-xs text-gray-500">
              / {overview ? overview.agents.total : 0} registered
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            {overview
              ? `${overview.agents.percentage_healthy}% healthy (${overview.agents.degraded} degraded, ${overview.agents.offline} offline)`
              : 'Active Linux endpoint sensors'}
          </p>
        </div>

        {/* Telemetry Ingestion Card */}
        <div className="p-4 rounded-lg border border-gray-200 bg-white shadow-sm">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-medium text-gray-500">24h Ingested Events</span>
            <Activity className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-bold text-gray-900">
            {(overview?.events_24h?.total_24h ?? 0).toLocaleString()}
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Normalized across FIM, process, auth & network
          </p>
        </div>

        {/* Active Incidents Card */}
        <div className="p-4 rounded-lg border border-gray-200 bg-white shadow-sm">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-medium text-gray-500">Active Incidents</span>
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                overview && overview.incidents.open_count + overview.incidents.investigating_count > 0
                  ? 'bg-amber-500'
                  : 'bg-emerald-500'
              }`}
            />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-gray-900">
              {overview
                ? overview.incidents.open_count + overview.incidents.investigating_count
                : 0}
            </span>
            <span className="text-xs text-gray-500">
              / {overview ? overview.incidents.total : 0} total
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            {overview
              ? `${overview.incidents.open_count} open, ${overview.incidents.investigating_count} investigating`
              : 'Requiring analyst investigation'}
          </p>
        </div>

        {/* Containment Actions Card */}
        <div className="p-4 rounded-lg border border-gray-200 bg-white shadow-sm">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs font-medium text-gray-500">Containment Actions</span>
            <HardDrive className="w-4 h-4 text-blue-600" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-gray-900">
              {overview ? overview.responses.total_actions : 0}
            </span>
            <span className="text-xs text-gray-500">
              ({overview?.responses.by_status['VERIFIED_CONTAINED'] || 0} verified)
            </span>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Cryptographically signed SOAR responses
          </p>
        </div>
      </div>

      {/* Pipeline & Infrastructure Stream Health */}
      <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-gray-200 mb-4 gap-2">
          <div className="flex items-center space-x-2.5">
            <Database className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-semibold text-gray-900">Stream Pipeline & Outbox Telemetry</h3>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-gray-600 bg-gray-50 px-2 py-0.5 rounded border border-gray-200">
              {overview?.pipeline.stream_name || 'stream:telemetry:raw'}
            </span>
            <span
              className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-xs font-medium border ${
                overview?.pipeline.stream_status === 'HEALTHY'
                  ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                  : 'bg-amber-50 text-amber-700 border-amber-200'
              }`}
            >
              {overview?.pipeline.stream_status === 'HEALTHY' ? (
                <CheckCircle2 className="w-3.5 h-3.5" />
              ) : (
                <AlertTriangle className="w-3.5 h-3.5" />
              )}
              <span>{overview?.pipeline.stream_status || 'UNKNOWN'}</span>
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
            <span className="text-gray-500 block mb-1">Redis Stream Length</span>
            <span className="text-base font-bold text-gray-900 font-mono">
              {overview?.pipeline.stream_length !== null && overview?.pipeline.stream_length !== undefined
                ? overview.pipeline.stream_length.toLocaleString()
                : 'N/A'}
            </span>
          </div>
          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
            <span className="text-gray-500 block mb-1">Outbox Pending</span>
            <span className="text-base font-bold text-amber-600 font-mono">
              {overview?.pipeline.outbox_pending ?? 0}
            </span>
          </div>
          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
            <span className="text-gray-500 block mb-1">Outbox Published</span>
            <span className="text-base font-bold text-emerald-600 font-mono">
              {overview?.pipeline.outbox_published ?? 0}
            </span>
          </div>
          <div className="p-3 bg-gray-50 rounded-lg border border-gray-200">
            <span className="text-gray-500 block mb-1">Detection Rules Active</span>
            <span className="text-base font-bold text-blue-600 font-mono">
              {overview?.rules.active_rules ?? 0} / {overview?.rules.total_rules ?? 0}
            </span>
          </div>
        </div>
      </div>

      {/* Operational Diagnostics & Infrastructure Health */}
      {diagnostics && (
        <div className="rounded-lg border border-gray-200 bg-white p-5 space-y-4 shadow-sm">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-gray-200 gap-2">
            <div className="flex items-center space-x-2.5">
              <Activity className="w-4 h-4 text-blue-600" />
              <h3 className="text-sm font-semibold text-gray-900">Production Operational Diagnostics</h3>
              <span className="text-xs text-gray-500 font-mono">
                (Uptime: {Math.floor(diagnostics.uptime_seconds / 3600)}h {Math.floor((diagnostics.uptime_seconds % 3600) / 60)}m)
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <span
                className={`inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded text-xs font-medium border ${
                  diagnostics.status === 'HEALTHY'
                    ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                    : diagnostics.status === 'DEGRADED'
                    ? 'bg-amber-50 text-amber-700 border-amber-200'
                    : 'bg-red-50 text-red-700 border-red-200'
                }`}
              >
                {diagnostics.status === 'HEALTHY' ? (
                  <CheckCircle2 className="w-3.5 h-3.5" />
                ) : (
                  <AlertTriangle className="w-3.5 h-3.5" />
                )}
                <span>SYSTEM: {diagnostics.status}</span>
              </span>
            </div>
          </div>

          {/* Subsystems Dependency Health Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 text-xs">
            {Object.entries(diagnostics.dependencies).map(([key, dep]) => (
              <div
                key={key}
                className="p-3 bg-gray-50 rounded-lg border border-gray-200 flex flex-col justify-between space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-medium text-gray-800 truncate" title={dep.name}>
                    {dep.name}
                  </span>
                  <span
                    className={`w-2 h-2 rounded-full ${
                      dep.status === 'HEALTHY'
                        ? 'bg-emerald-500'
                        : dep.status === 'DEGRADED'
                        ? 'bg-amber-500'
                        : 'bg-red-500'
                    }`}
                    title={dep.status}
                  />
                </div>
                <div className="text-xs text-gray-500 truncate" title={dep.message || ''}>
                  {dep.status}
                </div>
                <div className="text-[11px] text-gray-500 font-mono">
                  {dep.latency_ms !== null && dep.latency_ms !== undefined
                    ? `${dep.latency_ms.toFixed(1)} ms`
                    : dep.details && typeof dep.details.active_workers_count === 'number'
                    ? `${dep.details.active_workers_count} worker(s)`
                    : 'Active'}
                </div>
              </div>
            ))}
          </div>

          {/* Worker Status & Backlogs Details */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-1">
            {/* Background Workers & Lag */}
            <div className="p-3.5 bg-gray-50 rounded-lg border border-gray-200 text-xs space-y-2">
              <div className="flex items-center justify-between text-gray-800 font-medium border-b border-gray-200 pb-1.5">
                <span>Detection Consumer Workers</span>
                <span className="font-mono text-xs text-gray-500">
                  Lag: {diagnostics.backlogs.telemetry_stream_lag} | PEL: {diagnostics.backlogs.telemetry_pel_size}
                </span>
              </div>
              {diagnostics.telemetry_workers.length === 0 ? (
                <div className="text-gray-500 text-xs italic">
                  No consumer worker heartbeats detected.
                </div>
              ) : (
                <div className="space-y-1.5 max-h-28 overflow-y-auto">
                  {diagnostics.telemetry_workers.map((w) => (
                    <div key={w.worker_id} className="flex items-center justify-between text-xs font-mono bg-white px-2 py-1 rounded border border-gray-200">
                      <span className="text-gray-900 truncate max-w-[140px]">{w.worker_id}</span>
                      <span className="text-gray-500">
                        HB: {w.heartbeat_age_seconds !== null ? `${w.heartbeat_age_seconds}s ago` : 'never'}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        w.status === 'HEALTHY' ? 'text-emerald-700 bg-emerald-50' : 'text-amber-700 bg-amber-50'
                      }`}>
                        {w.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Integration Backlogs & Stalled Operations */}
            <div className="p-3.5 bg-gray-50 rounded-lg border border-gray-200 text-xs space-y-2">
              <div className="flex items-center justify-between text-gray-800 font-medium border-b border-gray-200 pb-1.5">
                <span>Operational Backlogs & Stalled Workflows</span>
                <span className={`font-mono text-xs ${
                  diagnostics.stalled_operations.stalled_executing_plans_count > 0 ||
                  diagnostics.stalled_operations.uncertain_actions_count > 0
                    ? 'text-amber-600 font-bold'
                    : 'text-emerald-600'
                }`}>
                  {diagnostics.stalled_operations.stalled_executing_plans_count +
                    diagnostics.stalled_operations.uncertain_actions_count}{' '}
                  Stalled
                </span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center pt-0.5">
                <div className="p-1.5 bg-white rounded border border-gray-200">
                  <span className="block text-[10px] text-gray-500">Outbound Backlog</span>
                  <span className="font-mono font-bold text-gray-900 text-xs">
                    {diagnostics.backlogs.outbound_notifications_pending} pending
                  </span>
                </div>
                <div className="p-1.5 bg-white rounded border border-gray-200">
                  <span className="block text-[10px] text-gray-500">Outbound Retries</span>
                  <span className={`font-mono font-bold text-xs ${
                    diagnostics.backlogs.outbound_notifications_retrying > 0 ? 'text-amber-600' : 'text-gray-700'
                  }`}>
                    {diagnostics.backlogs.outbound_notifications_retrying} retrying
                  </span>
                </div>
                <div className="p-1.5 bg-white rounded border border-gray-200">
                  <span className="block text-[10px] text-gray-500">Dead-Letter Queue</span>
                  <span className={`font-mono font-bold text-xs ${
                    diagnostics.backlogs.outbound_notifications_dead_letter > 0 ? 'text-red-600' : 'text-emerald-600'
                  }`}>
                    {diagnostics.backlogs.outbound_notifications_dead_letter} DLQ
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Main Section: Recent Incidents Table & Telemetry Breakdown */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recent Incidents Table (2 Cols) */}
        <div className="lg:col-span-2 rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
          <div className="flex items-center justify-between pb-3 border-b border-gray-200 mb-4">
            <div className="flex items-center space-x-2">
              <Layers className="w-4 h-4 text-blue-600" />
              <h3 className="text-sm font-semibold text-gray-900">Correlated Incident Forensics</h3>
            </div>
            <button
              onClick={() => onSelectWorkspace('investigation')}
              className="flex items-center space-x-1 text-xs text-blue-600 hover:text-blue-800 font-medium transition-colors"
            >
              <span>View Forensics Workspace</span>
              <ArrowRight className="w-3.5 h-3.5" />
            </button>
          </div>

          {!overview || overview.incidents.recent_activity.length === 0 ? (
            <EmptyState
              icon={<Cpu className="w-6 h-6" />}
              title="No Active Incidents"
              description="No correlated security incidents have been triggered. The detection pipeline is analyzing incoming telemetry against MITRE ATT&CK detection rules."
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead>
                  <tr className="border-b border-gray-200 text-gray-500 font-medium bg-gray-50/50">
                    <th className="py-2.5 px-3">INCIDENT</th>
                    <th className="py-2.5 px-2">SEVERITY</th>
                    <th className="py-2.5 px-2">RISK SCORE</th>
                    <th className="py-2.5 px-2">FINDINGS</th>
                    <th className="py-2.5 px-2">STATUS</th>
                    <th className="py-2.5 px-3 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {overview.incidents.recent_activity.map((inc) => (
                    <tr key={inc.incident_id} className="hover:bg-gray-50/80 transition-colors">
                      <td className="py-3 px-3">
                        <div className="font-medium text-gray-900">
                          #{inc.incident_number} {inc.title}
                        </div>
                        <div className="text-xs text-gray-500">
                          {inc.last_seen ? new Date(inc.last_seen).toLocaleString() : 'Recent'}
                        </div>
                      </td>
                      <td className="py-3 px-2">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[11px] font-medium border ${getSeverityBadge(
                            inc.severity
                          )}`}
                        >
                          {inc.severity}
                        </span>
                      </td>
                      <td className="py-3 px-2 font-mono">
                        <span className={getRiskScoreColor(inc.composite_risk_score)}>
                          {inc.composite_risk_score.toFixed(1)}
                        </span>
                      </td>
                      <td className="py-3 px-2 text-gray-700 font-mono">
                        {inc.findings_count}
                      </td>
                      <td className="py-3 px-2">
                        <span className="inline-block px-2 py-0.5 rounded text-[11px] font-medium bg-gray-100 text-gray-700 border border-gray-200">
                          {inc.status}
                        </span>
                      </td>
                      <td className="py-3 px-3 text-right">
                        <button
                          onClick={() => onSelectWorkspace('investigation', inc.incident_id)}
                          className="px-2.5 py-1 rounded bg-blue-50 hover:bg-blue-100 text-blue-700 border border-blue-200 text-xs font-medium transition-colors"
                        >
                          Investigate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Breakdown Panel: Findings by Severity & Telemetry by Type (1 Col) */}
        <div className="space-y-6">
          {/* Findings by Severity */}
          <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
            <h4 className="text-xs font-semibold text-gray-900 uppercase tracking-wider mb-3">
              Findings by Severity ({overview?.findings.total ?? 0})
            </h4>
            <div className="space-y-2.5 text-xs">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'] as Severity[]).map((sev) => {
                const count = overview?.findings.by_severity[sev] || 0;
                const total = overview?.findings.total || 1;
                const pct = Math.round((count / total) * 100);
                return (
                  <div key={sev} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-600">{sev}</span>
                      <span className="font-mono text-gray-900 font-medium">{count}</span>
                    </div>
                    <div className="w-full h-1.5 bg-gray-100 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          sev === 'CRITICAL'
                            ? 'bg-red-500'
                            : sev === 'HIGH'
                            ? 'bg-amber-500'
                            : sev === 'MEDIUM'
                            ? 'bg-blue-500'
                            : sev === 'LOW'
                            ? 'bg-gray-400'
                            : 'bg-gray-300'
                        }`}
                        style={{ width: `${overview?.findings.total ? pct : 0}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* 24h Ingestion by Event Type */}
          <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
            <h4 className="text-xs font-semibold text-gray-900 uppercase tracking-wider mb-3">
              Event Types (24h)
            </h4>
            <div className="space-y-2 text-xs">
              {[
                { key: 'FILE_INTEGRITY', label: 'File Integrity (FIM)' },
                { key: 'PROCESS_EXECUTION', label: 'Process Execution' },
                { key: 'AUTHENTICATION', label: 'Authentication' },
                { key: 'NETWORK_CONNECTION', label: 'Network Connection' },
                { key: 'SYSTEM_LOG', label: 'System Log' },
              ].map((et) => {
                const count = overview?.events_24h.by_type[et.key] || 0;
                return (
                  <div
                    key={et.key}
                    className="flex items-center justify-between p-2 rounded bg-gray-50 border border-gray-200"
                  >
                    <span className="text-gray-700 text-xs">{et.label}</span>
                    <span className="font-mono text-xs font-semibold text-blue-700">
                      {count.toLocaleString()}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Recent Containment Actions Feed */}
      <div className="rounded-lg border border-gray-200 bg-white p-5 shadow-sm">
        <div className="flex items-center justify-between pb-3 border-b border-gray-200 mb-4">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-blue-600" />
            <h3 className="text-sm font-semibold text-gray-900">Recent SOAR Containment Actions</h3>
          </div>
          <button
            onClick={() => onSelectWorkspace('soar')}
            className="flex items-center space-x-1 text-xs text-blue-600 hover:text-blue-800 font-medium transition-colors"
          >
            <span>View SOAR & Audit Ledger</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        {!overview || overview.responses.recent_actions.length === 0 ? (
          <EmptyState
            icon={<HardDrive className="w-6 h-6" />}
            title="No Containment Actions Executed"
            description="When automated or analyst-approved playbooks trigger endpoint containment commands (e.g. process isolation, network quarantine), verified records will appear here."
          />
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            {overview.responses.recent_actions.map((act) => (
              <div
                key={act.command_id}
                className="p-3 rounded-lg bg-gray-50 border border-gray-200 flex flex-col justify-between space-y-2 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-gray-900 uppercase text-xs">
                    {act.action}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[11px] font-medium border ${
                      act.status === 'VERIFIED_CONTAINED'
                        ? 'bg-emerald-50 text-emerald-700 border-emerald-200'
                        : act.status === 'VERIFICATION_INCONCLUSIVE'
                        ? 'bg-amber-50 text-amber-700 border-amber-200'
                        : act.status === 'FAILED'
                        ? 'bg-red-50 text-red-700 border-red-200'
                        : 'bg-blue-50 text-blue-700 border-blue-200'
                    }`}
                  >
                    {act.status}
                  </span>
                </div>
                <div className="text-xs text-gray-600 font-mono">
                  Agent: {act.agent_id.substring(0, 8)}...
                </div>
                <div className="text-[11px] text-gray-500">
                  {new Date(act.issued_at).toLocaleString()}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};