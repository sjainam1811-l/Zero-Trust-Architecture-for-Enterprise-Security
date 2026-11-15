import React from 'react';

export function Skeleton({ className = '' }) {
  return (
    <div
      className={`animate-pulse bg-raised/70 rounded ${className}`}
      aria-hidden="true"
    />
  );
}

export function TableSkeleton({ rows = 5, cols = 4 }) {
  return (
    <div className="space-y-3 p-4">
      <Skeleton className="h-6 w-full max-w-sm mb-4" />
      {Array.from({ length: rows }).map((_, i) => (
        <div key={i} className="flex gap-4">
          {Array.from({ length: cols }).map((_, j) => (
            <Skeleton key={j} className="h-8 flex-1" />
          ))}
        </div>
      ))}
    </div>
  );
}
