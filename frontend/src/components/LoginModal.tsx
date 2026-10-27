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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4">
      <div className="w-full max-w-md bg-white border border-gray-200 rounded-lg shadow-xl p-6 relative">
        <button
          onClick={onClose}
          className="absolute top-4 right-4 text-gray-400 hover:text-gray-600 transition-colors"
          title="Close dialog"
        >
          <X className="w-5 h-5" />
        </button>

        <div className="flex items-center space-x-3 mb-4">
          <div className="p-2 rounded-md bg-blue-50 border border-blue-100 text-blue-600">
            <Lock className="w-5 h-5" />
          </div>
          <div>
            <h2 className="text-base font-semibold text-gray-900">Administrator Sign In</h2>
            <p className="text-xs text-gray-500">Sign in to manage incidents and execute responses</p>
          </div>
        </div>

        <div className="mb-4 p-3 rounded-md bg-blue-50 border border-blue-200 text-xs text-blue-800 flex items-start space-x-2">
          <KeyRound className="w-4 h-4 shrink-0 text-blue-600 mt-0.5" />
          <span>
            Sessions are established via signed <strong>HttpOnly</strong> cookies with CSRF protection.
          </span>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-md bg-red-50 border border-red-200 text-xs text-red-700 flex items-start space-x-2">
            <AlertCircle className="w-4 h-4 shrink-0 text-red-600 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-gray-700 mb-1">
              Admin API Key / Password
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder="Enter admin credentials..."
              autoFocus
              disabled={loading}
              className="w-full px-3 py-2 bg-white border border-gray-300 rounded-md text-sm text-gray-900 placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
          </div>

          <div className="flex items-center justify-end space-x-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              disabled={loading}
              className="px-3.5 py-1.5 rounded-md text-xs font-medium text-gray-700 border border-gray-300 hover:bg-gray-50 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={loading}
              className="flex items-center space-x-1.5 px-4 py-1.5 rounded-md text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors disabled:opacity-50"
            >
              {loading ? (
                <>
                  <ShieldAlert className="w-3.5 h-3.5 animate-spin" />
                  <span>Verifying...</span>
                </>
              ) : (
                <>
                  <Lock className="w-3.5 h-3.5" />
                  <span>Sign In</span>
                </>
              )}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
};
