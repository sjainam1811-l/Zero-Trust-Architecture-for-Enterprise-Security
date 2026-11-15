import React from 'react';

export function Badge({ children, variant = 'muted', className = '' }) {
  const variants = {
    pass: 'text-status-pass bg-status-pass-soft border border-status-pass/25',
    fail: 'text-status-fail bg-status-fail-soft border border-status-fail/25',
    warning: 'text-status-warning bg-status-warning-soft border border-status-warning/25',
    blue: 'text-blue bg-blue-soft border border-blue/25',
    teal: 'text-blue bg-blue-soft border border-blue/25', // backward compat
    muted: 'text-text-secondary bg-raised border border-border',
  };

  const style = variants[variant] || variants.muted;

  return (
    <span
      className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-xs font-medium whitespace-nowrap ${style} ${className}`}
    >
      {children}
    </span>
  );
}
