import React from 'react';

export function StatCard({ label, value, subtext, icon: Icon }) {
  return (
    <div className="bg-surface border border-border rounded-card p-4 flex flex-col justify-between">
      <div className="flex items-center justify-between text-text-secondary text-sm">
        <span>{label}</span>
        {Icon && <Icon className="w-4 h-4 text-text-muted shrink-0" />}
      </div>
      <div className="mt-3">
        <div className="text-3xl font-semibold text-text-primary tracking-tight">
          {value}
        </div>
        {subtext && (
          <div className="mt-2 text-xs text-text-muted">
            {subtext}
          </div>
        )}
      </div>
    </div>
  );
}
