import React from 'react';
import { Shield, Activity, Search, Brain, Terminal, CheckCircle2, AlertTriangle, Lock, LogOut, UserCheck } from 'lucide-react';
import { LivenessResponse, SessionState } from '../types';

export type WorkspaceId = 'overview' | 'investigation' | 'detection' | 'soar';

interface HeaderProps {
  activeWorkspace: WorkspaceId;
  onSelectWorkspace: (workspace: WorkspaceId) => void;
  liveness: LivenessResponse | null;
  livenessError: boolean;
  session: SessionState | null;
  onOpenLogin: () => void;
  onLogout: () => void;
}

export const Header: React.FC<HeaderProps> = ({
  activeWorkspace,
  onSelectWorkspace,
  liveness,
  livenessError,
  session,
  onOpenLogin,
  onLogout,
}) => {
  const workspaces: { id: WorkspaceId; label: string; icon: React.ReactNode }[] = [
    { id: 'overview', label: '1. Command & Telemetry', icon: <Activity className="w-4 h-4" /> },
    { id: 'investigation', label: '2. Incident Forensics', icon: <Search className="w-4 h-4" /> },
    { id: 'detection', label: '3. Detection & Analytics', icon: <Brain className="w-4 h-4" /> },
    { id: 'soar', label: '4. SOAR & Audit Ledger', icon: <Terminal className="w-4 h-4" /> },
  ];

  return (
    <header className="border-b border-border bg-[#0d1322] px-6 py-3.5 sticky top-0 z-50">
      <div className="flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="p-2 rounded-lg bg-blue-600/10 border border-blue-500/20 text-blue-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold tracking-wider text-white text-base">WALIYA-IR</span>
              <span className="text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 border border-blue-800/40">
                v2.0
              </span>
            </div>
            <p className="text-xs text-slate-400">Ethio-SOAR Security Platform</p>
          </div>
        </div>

        {/* Workspace Navigation Tabs */}
        <nav className="flex items-center space-x-1 bg-surface border border-border p-1 rounded-lg">
          {workspaces.map((tab) => {
            const isActive = activeWorkspace === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onSelectWorkspace(tab.id)}
                className={`flex items-center space-x-2 px-3.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-surface-elevated'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Status & Session Indicators */}
        <div className="flex items-center space-x-3">
          {/* Backend Status Indicator */}
          <div className="flex items-center space-x-2 text-xs">
            {livenessError ? (
              <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-red-950/60 text-red-400 border border-red-800/50">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>API Offline</span>
              </span>
            ) : liveness ? (
              <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-emerald-950/60 text-emerald-400 border border-emerald-800/50">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Core Engine UP</span>
              </span>
            ) : (
              <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-slate-900 text-slate-400 border border-slate-800">
                <Activity className="w-3.5 h-3.5 animate-spin" />
                <span>Connecting...</span>
              </span>
            )}
          </div>

          {/* Browser Session Authentication Status */}
          {session?.authenticated ? (
            <div className="flex items-center space-x-2 pl-2 border-l border-border">
              <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-blue-950/70 text-blue-300 border border-blue-800/50 text-xs">
                <UserCheck className="w-3.5 h-3.5 text-blue-400" />
                <span className="font-mono">{session.actor || 'admin'}</span>
              </span>
              <button
                onClick={onLogout}
                title="Sign out of administrative session"
                className="flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-medium text-slate-400 hover:text-red-400 hover:bg-red-950/30 border border-border hover:border-red-800/50 transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign Out</span>
              </button>
            </div>
          ) : (
            <div className="pl-2 border-l border-border">
              <button
                onClick={onOpenLogin}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition-colors"
              >
                <Lock className="w-3.5 h-3.5" />
                <span>Sign In</span>
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
};
