import React, { useState } from 'react';
import { Lock, ShieldAlert, KeyRound, X, AlertCircle } from 'lucide-react';
import { apiClient, ApiError } from '../api/client';
import { SessionState } from '../types';

interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (session: SessionState) => void;
}

export const LoginModal: React.FC<LoginModalProps> = ({ isOpen, onClose, onSuccess }) => {
  const [apiKey, setApiKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  if (!isOpen) return null;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!apiKey.trim()) {
      setError('Please enter the administrative key.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const res = await apiClient.login(apiKey.trim());
      onSuccess({
        authenticated: true,
        actor: res.actor,
        csrf_token: res.csrf_token,
      });
      setApiKey('');
      onClose();
    } catch (err: unknown) {
      if (err instanceof ApiError) {
        if (err.status === 429) {
          setError('Rate limit exceeded: Too many failed login attempts. Please wait before retrying.');
        } else if (err.status === 401) {
          setError('Invalid administrative credentials. Access denied.');
        } else {
          setError(err.message || 'Authentication failed. Please verify server connectivity.');
        }
      } else {
        setError('Network error connecting to Waliya-IR backend.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="w-full max-w-md bg-[#0d1322] border border-border rounded-xl shadow-2xl p-6 relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-slate-400 hover:text-white transition-colors"
          title="Close dialog"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center space-x-3 mb-4">
          <div className="p-2.5 rounded-lg bg-blue-600/15 border border-blue-500/30 text-blue-400">
            <Lock className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white">Administrator Authentication</h2>
            <p className="text-xs text-slate-400">Sign in to control Waliya-IR operations</p>
          </div>
        </div>

        <div className="mb-4 p-3 rounded-lg bg-blue-950/40 border border-blue-900/60 text-[11px] text-blue-300 flex items-start space-x-2">
          <KeyRound className="w-4 h-4 shrink-0 text-blue-400 mt-0.5" />
          <span>
            Sessions are established via short-lived, signed <strong>HttpOnly</strong> cookies with CSRF protection. Credentials are never written to browser storage or JavaScript memory.
          </span>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-red-950/50 border border-red-800/60 text-xs text-red-300 flex items-start space-x-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-400 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              Admin API Key / Credential
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Enter ADMIN_API_KEY..."
              autoFocus
              disabled={loading}
              className="w-full px-3.5 py-2.5 bg-surface border border-border rounded-lg text-sm text-white placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent transition-all"
            />
          </div>

          <div className="flex items-center justify-end space-x-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-4 py-2 rounded-lg text-xs font-medium text-slate-300 hover:bg-surface-elevated transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex items-center space-x-2 px-5 py-2 rounded-lg text-xs font-semibold bg-blue-600 hover:bg-blue-500 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
            >
              {loading ? (
                <>
                  <ShieldAlert className="w-3.5 h-3.5 animate-spin" />
                  <span>Verifying...</span>
                </>
              ) : (
                <>
                  <Lock className="w-3.5 h-3.5" />
                  <span>Authenticate Session</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
