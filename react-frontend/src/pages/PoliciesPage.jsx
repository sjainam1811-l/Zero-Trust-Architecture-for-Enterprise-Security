import React, { useState, useEffect } from 'react';
import { CheckCircle2, AlertCircle, Shield } from 'lucide-react';
import { apiClient } from '../../zero-trust-auth.jsx';

const DEFAULT_POLICIES = [
  {
    id: 'pol-01',
    name: 'Require MFA for Admin Operations',
    description: 'Enforces 6-digit rolling TOTP code verification on administrative endpoints.',
    condition: "role === 'admin' || path.startsWith('/admin')",
    action: 'CHALLENGE_MFA',
    enabled: true,
  },
  {
    id: 'pol-02',
    name: 'Disable Dormant Accounts (30+ Days)',
    description: 'Denies access and auto-locks account when last activity exceeds 30 days.',
    condition: 'days_inactive > 30',
    action: 'LOCKOUT_ACCOUNT',
    enabled: true,
  },
  {
    id: 'pol-03',
    name: 'Step-Up Challenge on Unknown Device',
    description: 'Challenges access when hardware fingerprint is not in the trusted list.',
    condition: '!is_trusted_device',
    action: 'CHALLENGE_DEVICE',
    enabled: true,
  },
  {
    id: 'pol-04',
    name: 'Single-Use Refresh Token Rotation',
    description: 'Revokes entire token family immediately if an old refresh token is reused.',
    condition: 'refresh_token_reused === true',
    action: 'REVOKE_ALL_TOKENS',
    enabled: true,
  },
  {
    id: 'pol-05',
    name: 'Brute-Force Rate Limiter & Lockout',
    description: 'Enforces HTTP 429 lockout after 5 consecutive failed login attempts.',
    condition: 'failed_attempts >= 5',
    action: 'RATE_LIMIT_429',
    enabled: true,
  },
];

export function PoliciesPage() {
  const [policies, setPolicies] = useState(DEFAULT_POLICIES);
  const [loading, setLoading] = useState(false);
  const [togglingId, setTogglingId] = useState(null);
  const [error, setError] = useState(null);
  const [msg, setMsg] = useState(null);

  const fetchPolicies = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await apiClient.get('/api/policies');
      if (res.data.policies && res.data.policies.length > 0) {
        setPolicies(res.data.policies);
      }
    } catch (err) {
      console.warn('Policies fetched with fallback:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchPolicies();
  }, []);

  const togglePolicy = async (id, currentEnabled) => {
    setTogglingId(id);
    setError(null);
    const nextState = !currentEnabled;
    // Optimistic UI update
    setPolicies((prev) =>
      prev.map((p) => (p.id === id ? { ...p, enabled: nextState } : p))
    );
    try {
      await apiClient.patch(`/api/policies/${id}/toggle`, { enabled: nextState });
      setMsg(`Policy ${id} is now ${nextState ? 'Active' : 'Disabled'}`);
      setTimeout(() => setMsg(null), 3000);
    } catch (err) {
      // Revert if failed
      setPolicies((prev) =>
        prev.map((p) => (p.id === id ? { ...p, enabled: currentEnabled } : p))
      );
      setError(err.response?.data?.error || 'Failed to toggle policy');
    } finally {
      setTogglingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Short Description */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary tracking-tight">Policies</h1>
        <p className="text-sm font-medium text-text-secondary mt-1">
          Zero-Trust access policies evaluated on every single client request.
        </p>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3 rounded-control pill-fail text-xs !justify-start">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span className="font-bold">{error}</span>
        </div>
      )}
      {msg && (
        <div className="p-3 rounded-control pill-pass text-xs !justify-start">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span className="font-bold">{msg}</span>
        </div>
      )}

      {/* Policies List */}
      <div className="bg-surface border border-border rounded-card divide-y divide-border shadow-xs">
        {policies.map((p) => (
          <div
            key={p.id}
            className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-4 hover:bg-raised/40 transition-colors"
          >
            <div className="space-y-1.5 min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-bold text-text-primary">{p.name}</span>
                <span className="font-mono text-xs text-text-muted font-semibold">({p.id})</span>
                <span className={p.enabled ? 'pill-pass font-bold !text-[11px] !py-0.5' : 'pill-fail font-bold !text-[11px] !py-0.5'}>
                  {p.enabled ? 'Active' : 'Disabled'}
                </span>
              </div>
              <p className="text-xs font-medium text-text-secondary">{p.description}</p>
              <div className="pt-0.5 flex flex-wrap items-center gap-2">
                <code className="text-xs font-mono font-semibold text-text-secondary bg-raised px-2 py-0.5 rounded border border-border">
                  {p.condition}
                </code>
                <span className="text-xs font-mono text-blue font-bold">
                  &rarr; {p.action}
                </span>
              </div>
            </div>

            {/* Clean Blue/Gray Toggle Switch */}
            <div className="flex items-center gap-3 shrink-0 sm:self-center">
              <button
                type="button"
                role="switch"
                disabled={togglingId === p.id}
                aria-checked={p.enabled}
                aria-label={`Toggle ${p.name}`}
                onClick={() => togglePolicy(p.id, p.enabled)}
                className={`w-11 h-6 rounded-full transition-colors relative cursor-pointer focus:outline-none border border-border ${
                  p.enabled ? 'bg-blue' : 'bg-slate-300'
                }`}
              >
                <span
                  className={`block w-4 h-4 bg-white rounded-full shadow-xs transition-transform absolute top-0.5 left-0.5 ${
                    p.enabled ? 'translate-x-5' : 'translate-x-0'
                  }`}
                />
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
