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
    <header className="border-b border-gray-200 bg-white px-6 py-3 sticky top-0 z-50">
      <div className="flex items-center justify-between">
        {/* Brand */}
        <div className="flex items-center space-x-3">
          <div className="p-1.5 rounded-md bg-blue-50 border border-blue-100 text-blue-600">
            <Shield className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center space-x-2">
              <span className="font-bold tracking-tight text-gray-900 text-base">Waliya-IR</span>
              <span className="text-[10px] uppercase font-medium px-1.5 py-0.2 rounded bg-gray-100 text-gray-600 border border-gray-200">
                v2.0
              </span>
            </div>
            <p className="text-xs text-gray-500">Security Operations & Incident Response</p>
          </div>
        </div>

        {/* Workspace Navigation Tabs */}
        <nav className="flex items-center space-x-1 bg-gray-100 border border-gray-200 p-1 rounded-lg">
          {workspaces.map((tab) => {
            const isActive = activeWorkspace === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => onSelectWorkspace(tab.id)}
                className={`flex items-center space-x-2 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  isActive
                    ? 'bg-white text-gray-900 shadow-sm font-semibold'
                    : 'text-gray-600 hover:text-gray-900 hover:bg-gray-200/60'
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
              <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-red-50 text-red-700 border border-red-200">
                <AlertTriangle className="w-3.5 h-3.5" />
                <span>API Offline</span>
              </span>
            ) : liveness ? (
              <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-green-50 text-green-700 border border-green-200">
                <CheckCircle2 className="w-3.5 h-3.5" />
                <span>Core Engine UP</span>
              </span>
            ) : (
              <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-full bg-gray-100 text-gray-600 border border-gray-200">
                <Activity className="w-3.5 h-3.5 animate-spin" />
                <span>Connecting...</span>
              </span>
            )}
          </div>

          {/* Browser Session Authentication Status */}
          {session?.authenticated ? (
            <div className="flex items-center space-x-2 pl-2 border-l border-gray-200">
              <span className="inline-flex items-center space-x-1.5 px-2.5 py-1 rounded-md bg-gray-100 text-gray-800 border border-gray-200 text-xs">
                <UserCheck className="w-3.5 h-3.5 text-blue-600" />
                <span className="font-mono">{session.actor || 'admin'}</span>
              </span>
              <button
                onClick={onLogout}
                title="Sign out of administrative session"
                className="flex items-center space-x-1 px-2.5 py-1 rounded-md text-xs font-medium text-gray-600 hover:text-red-700 hover:bg-red-50 border border-gray-200 hover:border-red-200 transition-colors"
              >
                <LogOut className="w-3.5 h-3.5" />
                <span>Sign Out</span>
              </button>
            </div>
          ) : (
            <div className="pl-2 border-l border-gray-200">
              <button
                onClick={onOpenLogin}
                className="flex items-center space-x-1.5 px-3 py-1.5 rounded-md text-xs font-semibold bg-blue-600 hover:bg-blue-700 text-white shadow-sm transition-colors"
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
