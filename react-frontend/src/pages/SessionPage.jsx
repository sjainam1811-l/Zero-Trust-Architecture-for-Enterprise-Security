import React, { useState } from 'react';
import {
  User,
  Copy,
  Check,
  Laptop,
} from 'lucide-react';
import { Badge } from '../components/common/Badge';

export function SessionPage({
  user,
  onTrustDevice,
  newDevice,
}) {
  const [copied, setCopied] = useState(false);

  const rawFingerprint = user?.fingerprint || 'Not available';
  const truncatedFingerprint = rawFingerprint.length > 28
    ? `${rawFingerprint.slice(0, 16)}...${rawFingerprint.slice(-12)}`
    : rawFingerprint;

  const handleCopy = () => {
    navigator.clipboard.writeText(rawFingerprint);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const role = user?.role || 'viewer';
  const userEmail = user?.email || (user?.userId && !user.userId.startsWith('usr_') ? user.userId : 'user@example.com');

  const rolePermissionsMap = {
    admin: ['read', 'write', 'delete', 'manage', 'audit'],
    editor: ['read', 'write'],
    viewer: ['read'],
    auditor: ['read', 'audit'],
  };

  const userPerms = rolePermissionsMap[role] || ['read'];
  const allPermissions = ['read', 'write', 'delete', 'manage', 'audit'];

  return (
    <div className="space-y-6">
      {/* Title & Short Description */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary tracking-tight">Login & Session</h1>
        <p className="text-sm font-medium text-text-secondary mt-1">
          Your current sign-in and token details verified by Zero Trust policy.
        </p>
      </div>

      {/* Untrusted Device Prompt Banner */}
      {newDevice && (
        <div className="p-4 bg-surface border border-border rounded-card flex items-center justify-between gap-4 shadow-xs">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-raised rounded-control text-text-secondary">
              <Laptop className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold text-text-primary">New device detected</div>
              <p className="text-xs text-text-secondary">
                This device is not in your trusted devices list yet.
              </p>
            </div>
          </div>
          <button
            onClick={onTrustDevice}
            className="btn-secondary shrink-0 font-bold"
          >
            Trust device
          </button>
        </div>
      )}

      {/* Verified Identity Card */}
      <div className="bg-surface border border-border rounded-card p-6 space-y-6 shadow-xs">
        <div className="flex items-center justify-between border-b border-border pb-4">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-full bg-blue-soft border border-blue/20 flex items-center justify-center text-blue">
              <User className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold text-text-primary">
                {userEmail}
              </div>
              <div className="text-xs font-semibold text-text-secondary capitalize">
                Role: {role}
              </div>
            </div>
          </div>
          <span className="pill-pass font-bold">Signed in</span>
        </div>

        {/* Identity Details Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs">
          <div className="p-3.5 bg-raised rounded-control border border-border space-y-1">
            <span className="text-text-secondary font-bold text-xs">Assigned role</span>
            <div className="flex items-center gap-2 pt-0.5">
              <Badge variant="blue">{role}</Badge>
            </div>
          </div>

          <div className="p-3.5 bg-raised rounded-control border border-border space-y-1">
            <span className="text-text-secondary font-bold text-xs">Device fingerprint</span>
            <div className="flex items-center justify-between gap-2 pt-0.5">
              <code className="font-mono text-text-secondary text-xs bg-surface px-2.5 py-1.5 rounded-control border border-border truncate flex-1 font-semibold">
                {truncatedFingerprint}
              </code>
              <button
                onClick={handleCopy}
                aria-label="Copy fingerprint"
                className="btn-secondary !h-8 !px-3 shrink-0 text-xs font-bold"
              >
                {copied ? <Check className="w-3.5 h-3.5 text-status-pass" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copied ? 'Copied' : 'Copy'}</span>
              </button>
            </div>
          </div>
        </div>

        {/* What your role can do - ONLY show assigned permissions, hide the rest per user request */}
        <div className="border-t border-border pt-4">
          <div className="text-xs font-bold uppercase text-text-secondary tracking-wider mb-3">
            What your role can do
          </div>
          <div className="flex flex-wrap items-center gap-2.5">
            {userPerms.map((perm) => (
              <span
                key={perm}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-bold border bg-status-pass-soft text-status-pass border-status-pass/30 shadow-xs"
              >
                <span className="w-2 h-2 rounded-full bg-status-pass" />
                <span className="font-mono tracking-wide uppercase">{perm}</span>
                <span className="font-bold">✓</span>
              </span>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
