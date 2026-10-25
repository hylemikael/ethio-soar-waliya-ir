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
        return 'bg-red-950/80 text-red-300 border-red-800/80';
      case 'HIGH':
        return 'bg-orange-950/80 text-orange-300 border-orange-800/80';
      case 'MEDIUM':
        return 'bg-yellow-950/80 text-yellow-300 border-yellow-800/80';
      case 'LOW':
        return 'bg-blue-950/80 text-blue-300 border-blue-800/80';
      default:
        return 'bg-slate-800 text-slate-300 border-slate-700';
    }
  };

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-400 font-bold';
    if (score >= 60) return 'text-orange-400 font-semibold';
    if (score >= 40) return 'text-yellow-400 font-medium';
    return 'text-emerald-400';
  };

  if (loading && !overview) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-24 bg-surface rounded-xl border border-border" />
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {[1, 2, 3, 4].map((i) => (
            <div key={i} className="h-32 bg-surface rounded-xl border border-border" />
          ))}
        </div>
        <div className="h-64 bg-surface rounded-xl border border-border" />
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Auth Banner if unauthenticated */}
      {authRequired && (
        <div className="p-4 rounded-xl border border-blue-500/30 bg-blue-950/30 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-blue-600/20 text-blue-400">
              <Lock className="w-5 h-5" />
            </div>
            <div>
              <h4 className="text-sm font-semibold text-white">Administrator Authentication Required</h4>
              <p className="text-xs text-slate-400">
                Live operational telemetry and incident metrics require an authenticated session.
              </p>
            </div>
          </div>
          <button
            onClick={onOpenLogin}
            className="flex items-center space-x-1.5 px-4 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-md transition-colors"
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Sign In to Unlock Live Data</span>
          </button>
        </div>
      )}

      {/* Backend Unreachable Banner */}
      {error && !authRequired && (
        <div className="p-4 rounded-xl border border-red-500/30 bg-red-950/30 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <div>
              <h4 className="text-sm font-semibold text-white">Telemetry Pipeline Warning</h4>
              <p className="text-xs text-red-300">{error}</p>
            </div>
          </div>
          <button
            onClick={() => fetchOverview(true)}
            className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-red-900/40 hover:bg-red-900/60 text-red-200 border border-red-800 transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Retry</span>
          </button>
        </div>
      )}

      {/* Security Posture Banner */}
      {overview && (
        <div
          className={`p-5 rounded-xl border transition-all ${
            overview.security_posture === 'CRITICAL'
              ? 'bg-gradient-to-r from-red-950/50 to-surface border-red-800/80'
              : overview.security_posture === 'ELEVATED'
              ? 'bg-gradient-to-r from-amber-950/50 to-surface border-amber-800/80'
              : 'bg-gradient-to-r from-emerald-950/40 to-surface border-emerald-800/60'
          }`}
        >
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div className="flex items-center space-x-4">
              <div
                className={`p-3 rounded-xl border ${
                  overview.security_posture === 'CRITICAL'
                    ? 'bg-red-600/20 text-red-400 border-red-500/40 animate-pulse'
                    : overview.security_posture === 'ELEVATED'
                    ? 'bg-amber-600/20 text-amber-400 border-amber-500/40'
                    : 'bg-emerald-600/20 text-emerald-400 border-emerald-500/40'
                }`}
              >
                {overview.security_posture === 'CRITICAL' ? (
                  <ShieldAlert className="w-8 h-8" />
                ) : overview.security_posture === 'ELEVATED' ? (
                  <AlertOctagon className="w-8 h-8" />
                ) : (
                  <ShieldCheck className="w-8 h-8" />
                )}
              </div>
              <div>
                <div className="flex items-center space-x-2">
                  <span className="text-xs font-mono uppercase tracking-wider text-slate-400">
                    Defensive Posture:
                  </span>
                  <span
                    className={`text-sm font-black px-2.5 py-0.5 rounded border uppercase ${
                      overview.security_posture === 'CRITICAL'
                        ? 'bg-red-950 text-red-300 border-red-700'
                        : overview.security_posture === 'ELEVATED'
                        ? 'bg-amber-950 text-amber-300 border-amber-700'
                        : 'bg-emerald-950 text-emerald-300 border-emerald-700'
                    }`}
                  >
                    {overview.security_posture}
                  </span>
                </div>
                <p className="text-sm font-semibold text-white mt-1">{overview.posture_reason}</p>
                <div className="flex items-center space-x-3 text-[11px] text-slate-400 mt-1">
                  <span className="flex items-center space-x-1">
                    <Clock className="w-3 h-3 text-slate-500" />
                    <span>Updated: {new Date(overview.generated_at).toLocaleTimeString()}</span>
                  </span>
                  <span>&bull;</span>
                  <span>Polling Interval: 15s</span>
                </div>
              </div>
            </div>

            <div className="flex items-center space-x-3">
              <button
                onClick={() => fetchOverview(true)}
                disabled={refreshing}
                className="flex items-center space-x-1.5 px-3.5 py-2 rounded-lg text-xs font-medium bg-surface-elevated hover:bg-slate-700 text-slate-200 border border-border transition-colors disabled:opacity-50"
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
        <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">Connected Agents</span>
            <Radio className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-white">
              {overview ? overview.agents.online : 0}
            </span>
            <span className="text-xs text-slate-400">
              / {overview ? overview.agents.total : 0} registered
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {overview
              ? `${overview.agents.percentage_healthy}% healthy (${overview.agents.degraded} degraded, ${overview.agents.offline} offline)`
              : 'Active Linux endpoint sensors'}
          </p>
        </div>

        {/* Telemetry Ingestion Card */}
        <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">24h Ingested Events</span>
            <Activity className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold text-white">
            {overview ? overview.events_24h.total_24h.toLocaleString() : 0}
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            Normalized across FIM, process, auth & network
          </p>
        </div>

        {/* Active Incidents Card */}
        <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">Active Incidents</span>
            <span
              className={`w-2.5 h-2.5 rounded-full ${
                overview && overview.incidents.open_count + overview.incidents.investigating_count > 0
                  ? 'bg-amber-400 animate-ping'
                  : 'bg-emerald-400'
              }`}
            />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-white">
              {overview
                ? overview.incidents.open_count + overview.incidents.investigating_count
                : 0}
            </span>
            <span className="text-xs text-slate-400">
              / {overview ? overview.incidents.total : 0} total
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            {overview
              ? `${overview.incidents.open_count} open, ${overview.incidents.investigating_count} investigating`
              : 'Requiring analyst investigation'}
          </p>
        </div>

        {/* Containment Actions Card */}
        <div className="p-4 rounded-xl border border-border bg-surface shadow-sm">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-medium text-slate-400">Containment Actions</span>
            <HardDrive className="w-4 h-4 text-purple-400" />
          </div>
          <div className="flex items-baseline space-x-2">
            <span className="text-2xl font-bold text-white">
              {overview ? overview.responses.total_actions : 0}
            </span>
            <span className="text-xs text-slate-400">
              ({overview?.responses.by_status['VERIFIED_CONTAINED'] || 0} verified)
            </span>
          </div>
          <p className="text-[11px] text-slate-500 mt-1">
            Cryptographically signed SOAR responses
          </p>
        </div>
      </div>

      {/* Pipeline & Infrastructure Stream Health */}
      <div className="rounded-xl border border-border bg-surface p-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border mb-4 gap-2">
          <div className="flex items-center space-x-2.5">
            <Database className="w-4 h-4 text-cyan-400" />
            <h3 className="text-sm font-semibold text-white">Stream Pipeline & Outbox Telemetry</h3>
          </div>
          <div className="flex items-center space-x-2">
            <span className="text-xs font-mono text-slate-400 bg-surface-elevated px-2 py-0.5 rounded border border-border">
              {overview?.pipeline.stream_name || 'stream:telemetry:raw'}
            </span>
            <span
              className={`inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[11px] font-semibold border ${
                overview?.pipeline.stream_status === 'HEALTHY'
                  ? 'bg-emerald-950/60 text-emerald-400 border-emerald-800/60'
                  : 'bg-amber-950/60 text-amber-400 border-amber-800/60'
              }`}
            >
              {overview?.pipeline.stream_status === 'HEALTHY' ? (
                <CheckCircle2 className="w-3 h-3" />
              ) : (
                <AlertTriangle className="w-3 h-3" />
              )}
              <span>{overview?.pipeline.stream_status || 'UNKNOWN'}</span>
            </span>
          </div>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
          <div className="p-3 bg-surface-elevated/40 rounded-lg border border-border/60">
            <span className="text-slate-400 block mb-1">Redis Stream Length</span>
            <span className="text-base font-bold text-white font-mono">
              {overview?.pipeline.stream_length !== null && overview?.pipeline.stream_length !== undefined
                ? overview.pipeline.stream_length.toLocaleString()
                : 'N/A'}
            </span>
          </div>
          <div className="p-3 bg-surface-elevated/40 rounded-lg border border-border/60">
            <span className="text-slate-400 block mb-1">Outbox Pending</span>
            <span className="text-base font-bold text-amber-400 font-mono">
              {overview?.pipeline.outbox_pending ?? 0}
            </span>
          </div>
          <div className="p-3 bg-surface-elevated/40 rounded-lg border border-border/60">
            <span className="text-slate-400 block mb-1">Outbox Published</span>
            <span className="text-base font-bold text-emerald-400 font-mono">
              {overview?.pipeline.outbox_published ?? 0}
            </span>
          </div>
          <div className="p-3 bg-surface-elevated/40 rounded-lg border border-border/60">
            <span className="text-slate-400 block mb-1">Detection Rules Active</span>
            <span className="text-base font-bold text-blue-400 font-mono">
              {overview?.rules.active_rules ?? 0} / {overview?.rules.total_rules ?? 0}
            </span>
          </div>
        </div>
      </div>

      {/* Operational Diagnostics & Infrastructure Health */}
      {diagnostics && (
        <div className="rounded-xl border border-border bg-surface p-5 space-y-4">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between pb-3 border-b border-border gap-2">
            <div className="flex items-center space-x-2.5">
              <Activity className="w-4 h-4 text-emerald-400" />
              <h3 className="text-sm font-semibold text-white">Production Operational Diagnostics</h3>
              <span className="text-[11px] text-slate-400 font-mono">
                (Uptime: {Math.floor(diagnostics.uptime_seconds / 3600)}h {Math.floor((diagnostics.uptime_seconds % 3600) / 60)}m)
              </span>
            </div>
            <div className="flex items-center space-x-2">
              <span
                className={`inline-flex items-center space-x-1.5 px-2.5 py-0.5 rounded text-xs font-semibold border ${
                  diagnostics.status === 'HEALTHY'
                    ? 'bg-emerald-950/80 text-emerald-300 border-emerald-800'
                    : diagnostics.status === 'DEGRADED'
                    ? 'bg-amber-950/80 text-amber-300 border-amber-800'
                    : 'bg-red-950/80 text-red-300 border-red-800'
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
                className="p-3 bg-surface-elevated/40 rounded-lg border border-border/60 flex flex-col justify-between space-y-1.5"
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-slate-300 truncate" title={dep.name}>
                    {dep.name}
                  </span>
                  <span
                    className={`w-2 h-2 rounded-full ${
                      dep.status === 'HEALTHY'
                        ? 'bg-emerald-400'
                        : dep.status === 'DEGRADED'
                        ? 'bg-amber-400'
                        : 'bg-red-400'
                    }`}
                    title={dep.status}
                  />
                </div>
                <div className="text-[11px] text-slate-400 truncate" title={dep.message || ''}>
                  {dep.status}
                </div>
                <div className="text-[10px] text-slate-500 font-mono">
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
            <div className="p-3.5 bg-surface-elevated/30 rounded-lg border border-border/50 text-xs space-y-2">
              <div className="flex items-center justify-between text-slate-300 font-semibold border-b border-border/40 pb-1.5">
                <span>Detection Consumer Workers</span>
                <span className="font-mono text-[11px] text-slate-400">
                  Lag: {diagnostics.backlogs.telemetry_stream_lag} | PEL: {diagnostics.backlogs.telemetry_pel_size}
                </span>
              </div>
              {diagnostics.telemetry_workers.length === 0 ? (
                <div className="text-slate-400 text-[11px] italic">
                  No consumer worker heartbeats detected.
                </div>
              ) : (
                <div className="space-y-1.5 max-h-28 overflow-y-auto">
                  {diagnostics.telemetry_workers.map((w) => (
                    <div key={w.worker_id} className="flex items-center justify-between text-[11px] font-mono bg-surface/50 px-2 py-1 rounded">
                      <span className="text-white truncate max-w-[140px]">{w.worker_id}</span>
                      <span className="text-slate-400">
                        HB: {w.heartbeat_age_seconds !== null ? `${w.heartbeat_age_seconds}s ago` : 'never'}
                      </span>
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                        w.status === 'HEALTHY' ? 'text-emerald-400' : 'text-amber-400'
                      }`}>
                        {w.status}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Integration Backlogs & Stalled Operations */}
            <div className="p-3.5 bg-surface-elevated/30 rounded-lg border border-border/50 text-xs space-y-2">
              <div className="flex items-center justify-between text-slate-300 font-semibold border-b border-border/40 pb-1.5">
                <span>Operational Backlogs & Stalled Workflows</span>
                <span className={`font-mono text-[11px] ${
                  diagnostics.stalled_operations.stalled_executing_plans_count > 0 ||
                  diagnostics.stalled_operations.uncertain_actions_count > 0
                    ? 'text-amber-400 font-bold'
                    : 'text-emerald-400'
                }`}>
                  {diagnostics.stalled_operations.stalled_executing_plans_count +
                    diagnostics.stalled_operations.uncertain_actions_count}{' '}
                  Stalled
                </span>
              </div>
              <div className="grid grid-cols-3 gap-2 text-center pt-0.5">
                <div className="p-1.5 bg-surface/40 rounded border border-border/40">
                  <span className="block text-[10px] text-slate-400">Outbound Backlog</span>
                  <span className="font-mono font-bold text-white text-xs">
                    {diagnostics.backlogs.outbound_notifications_pending} pending
                  </span>
                </div>
                <div className="p-1.5 bg-surface/40 rounded border border-border/40">
                  <span className="block text-[10px] text-slate-400">Outbound Retries</span>
                  <span className={`font-mono font-bold text-xs ${
                    diagnostics.backlogs.outbound_notifications_retrying > 0 ? 'text-amber-400' : 'text-slate-300'
                  }`}>
                    {diagnostics.backlogs.outbound_notifications_retrying} retrying
                  </span>
                </div>
                <div className="p-1.5 bg-surface/40 rounded border border-border/40">
                  <span className="block text-[10px] text-slate-400">Dead-Letter Queue</span>
                  <span className={`font-mono font-bold text-xs ${
                    diagnostics.backlogs.outbound_notifications_dead_letter > 0 ? 'text-red-400' : 'text-emerald-400'
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
        <div className="lg:col-span-2 rounded-xl border border-border bg-surface p-5">
          <div className="flex items-center justify-between pb-3 border-b border-border mb-4">
            <div className="flex items-center space-x-2">
              <Layers className="w-4 h-4 text-red-400" />
              <h3 className="text-sm font-semibold text-white">Correlated Incident Forensics</h3>
            </div>
            <button
              onClick={() => onSelectWorkspace('investigation')}
              className="flex items-center space-x-1 text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors"
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
                  <tr className="border-b border-border text-slate-400 font-semibold">
                    <th className="pb-2.5">INCIDENT</th>
                    <th className="pb-2.5">SEVERITY</th>
                    <th className="pb-2.5">RISK SCORE</th>
                    <th className="pb-2.5">FINDINGS</th>
                    <th className="pb-2.5">STATUS</th>
                    <th className="pb-2.5 text-right">ACTION</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border/60">
                  {overview.incidents.recent_activity.map((inc) => (
                    <tr key={inc.incident_id} className="hover:bg-surface-elevated/50 transition-colors">
                      <td className="py-3">
                        <div className="font-semibold text-white">
                          #{inc.incident_number} {inc.title}
                        </div>
                        <div className="text-[11px] text-slate-400">
                          {inc.last_seen ? new Date(inc.last_seen).toLocaleString() : 'Recent'}
                        </div>
                      </td>
                      <td className="py-3">
                        <span
                          className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold border ${getSeverityBadge(
                            inc.severity
                          )}`}
                        >
                          {inc.severity}
                        </span>
                      </td>
                      <td className="py-3 font-mono">
                        <span className={getRiskScoreColor(inc.composite_risk_score)}>
                          {inc.composite_risk_score.toFixed(1)}
                        </span>
                      </td>
                      <td className="py-3 text-slate-300 font-mono">
                        {inc.findings_count}
                      </td>
                      <td className="py-3">
                        <span className="inline-block px-2 py-0.5 rounded text-[10px] font-medium bg-surface-elevated text-slate-300 border border-border">
                          {inc.status}
                        </span>
                      </td>
                      <td className="py-3 text-right">
                        <button
                          onClick={() => onSelectWorkspace('investigation', inc.incident_id)}
                          className="px-2.5 py-1 rounded bg-blue-600/15 hover:bg-blue-600/25 text-blue-400 border border-blue-500/30 text-[11px] font-medium transition-colors"
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
          <div className="rounded-xl border border-border bg-surface p-5">
            <h4 className="text-xs font-semibold text-white uppercase tracking-wider mb-3">
              Findings by Severity ({overview?.findings.total ?? 0})
            </h4>
            <div className="space-y-2 text-xs">
              {(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'] as Severity[]).map((sev) => {
                const count = overview?.findings.by_severity[sev] || 0;
                const total = overview?.findings.total || 1;
                const pct = Math.round((count / total) * 100);
                return (
                  <div key={sev} className="space-y-1">
                    <div className="flex justify-between text-[11px]">
                      <span className="text-slate-400">{sev}</span>
                      <span className="font-mono text-white font-medium">{count}</span>
                    </div>
                    <div className="w-full h-1.5 bg-surface-elevated rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${
                          sev === 'CRITICAL'
                            ? 'bg-red-500'
                            : sev === 'HIGH'
                            ? 'bg-orange-500'
                            : sev === 'MEDIUM'
                            ? 'bg-yellow-500'
                            : sev === 'LOW'
                            ? 'bg-blue-500'
                            : 'bg-slate-500'
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
          <div className="rounded-xl border border-border bg-surface p-5">
            <h4 className="text-xs font-semibold text-white uppercase tracking-wider mb-3">
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
                    className="flex items-center justify-between p-2 rounded bg-surface-elevated/40 border border-border/40"
                  >
                    <span className="text-slate-300 text-[11px]">{et.label}</span>
                    <span className="font-mono text-xs font-semibold text-blue-400">
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
      <div className="rounded-xl border border-border bg-surface p-5">
        <div className="flex items-center justify-between pb-3 border-b border-border mb-4">
          <div className="flex items-center space-x-2">
            <ShieldCheck className="w-4 h-4 text-purple-400" />
            <h3 className="text-sm font-semibold text-white">Recent SOAR Containment Actions</h3>
          </div>
          <button
            onClick={() => onSelectWorkspace('soar')}
            className="flex items-center space-x-1 text-xs text-blue-400 hover:text-blue-300 font-medium transition-colors"
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
                className="p-3 rounded-lg bg-surface-elevated border border-border/70 flex flex-col justify-between space-y-2 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-bold text-white uppercase text-[11px]">
                    {act.action}
                  </span>
                  <span
                    className={`px-2 py-0.5 rounded text-[10px] font-semibold ${
                      act.status === 'VERIFIED_CONTAINED'
                        ? 'bg-emerald-950 text-emerald-300 border border-emerald-800'
                        : act.status === 'VERIFICATION_INCONCLUSIVE'
                        ? 'bg-amber-950 text-amber-300 border border-amber-800'
                        : act.status === 'FAILED'
                        ? 'bg-red-950 text-red-300 border border-red-800'
                        : 'bg-blue-950 text-blue-300 border border-blue-800'
                    }`}
                  >
                    {act.status}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 font-mono">
                  Agent: {act.agent_id.substring(0, 8)}...
                </div>
                <div className="text-[10px] text-slate-500">
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
