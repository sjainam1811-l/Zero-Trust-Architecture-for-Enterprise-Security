import React from 'react';
import { Inbox } from 'lucide-react';

export function EmptyState({ icon: Icon = Inbox, title = 'No records found', description = 'There is no data to display right now.', action }) {
  return (
    <div className="flex flex-col items-center justify-center p-8 text-center bg-surface border border-border rounded-card my-4">
      <div className="p-3 bg-raised rounded-full mb-3 border border-border">
        <Icon className="w-6 h-6 text-text-muted" />
      </div>
      <h3 className="text-sm font-medium text-text-primary mb-1">{title}</h3>
      <p className="text-xs text-text-secondary max-w-sm mb-4">{description}</p>
      {action}
    </div>
  );
}
