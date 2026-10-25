import React, { useState, useEffect } from 'react';
import { Header, WorkspaceId } from './components/Header';
import { CommandOverview } from './workspaces/CommandOverview';
import { IncidentInvestigation } from './workspaces/IncidentInvestigation';
import { DetectionAnalytics } from './workspaces/DetectionAnalytics';
import { SoarAuditLedger } from './workspaces/SoarAuditLedger';
import { LoginModal } from './components/LoginModal';
import { apiClient } from './api/client';
import { LivenessResponse, SessionState } from './types';

export const App: React.FC = () => {
  const [activeWorkspace, setActiveWorkspace] = useState<WorkspaceId>('overview');
  const [selectedIncidentId, setSelectedIncidentId] = useState<string | null>(null);
  const [liveness, setLiveness] = useState<LivenessResponse | null>(null);
  const [livenessError, setLivenessError] = useState(false);
  const [session, setSession] = useState<SessionState | null>(null);
  const [isLoginModalOpen, setIsLoginModalOpen] = useState(false);

  // Check backend liveness periodically
  useEffect(() => {
    let isMounted = true;

    const checkLiveness = async () => {
      try {
        const res = await apiClient.getLiveness();
        if (isMounted) {
          setLiveness(res);
          setLivenessError(false);
        }
      } catch {
        if (isMounted) {
          setLivenessError(true);
        }
      }
    };

    checkLiveness();
    const interval = setInterval(checkLiveness, 10000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, []);

  // Check active session on initial load
  useEffect(() => {
    let isMounted = true;

    const checkSession = async () => {
      try {
        const state = await apiClient.getSession();
        if (isMounted && state.authenticated) {
          setSession(state);
        }
      } catch {
        // Unauthenticated or network error on startup is expected
      }
    };

    checkSession();
    return () => {
      isMounted = false;
    };
  }, []);

  const handleLogout = async () => {
    try {
      await apiClient.logout();
    } catch {
      // Logout even if network failed
    } finally {
      setSession(null);
    }
  };

  const handleSelectWorkspace = (workspace: WorkspaceId, incidentId?: string) => {
    setActiveWorkspace(workspace);
    if (incidentId) {
      setSelectedIncidentId(incidentId);
    }
  };

  return (
    <div className="min-h-screen flex flex-col bg-background text-slate-100">
      <Header
        activeWorkspace={activeWorkspace}
        onSelectWorkspace={handleSelectWorkspace}
        liveness={liveness}
        livenessError={livenessError}
        session={session}
        onOpenLogin={() => setIsLoginModalOpen(true)}
        onLogout={handleLogout}
      />

      <main className="flex-1 p-6 max-w-7xl w-full mx-auto">
        {activeWorkspace === 'overview' && (
          <CommandOverview
            onSelectWorkspace={handleSelectWorkspace}
            onOpenLogin={() => setIsLoginModalOpen(true)}
            isAuthenticated={Boolean(session?.authenticated)}
          />
        )}
        {activeWorkspace === 'investigation' && (
          <IncidentInvestigation
            initialIncidentId={selectedIncidentId}
            onOpenLogin={() => setIsLoginModalOpen(true)}
            isAuthenticated={Boolean(session?.authenticated)}
          />
        )}
        {activeWorkspace === 'detection' && (
          <DetectionAnalytics
            onOpenLogin={() => setIsLoginModalOpen(true)}
            isAuthenticated={Boolean(session?.authenticated)}
            onSelectWorkspace={handleSelectWorkspace}
          />
        )}
        {activeWorkspace === 'soar' && <SoarAuditLedger />}
      </main>

      <footer className="border-t border-border bg-[#0a0f1d] px-6 py-3 text-center text-xs text-slate-500">
        Waliya-IR Platform Architecture &bull; Competition-Grade Linux-First SOAR & Incident Response &bull; v2.0
      </footer>

      <LoginModal
        isOpen={isLoginModalOpen}
        onClose={() => setIsLoginModalOpen(false)}
        onSuccess={(newSession) => setSession(newSession)}
      />
    </div>
  );
};
