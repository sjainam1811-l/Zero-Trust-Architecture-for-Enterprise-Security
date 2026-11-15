import React, { useEffect } from 'react';
import { X } from 'lucide-react';

export function Drawer({ isOpen, onClose, title, subtitle, children }) {
  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === 'Escape' && isOpen) onClose();
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 overflow-hidden">
      {/* Backdrop */}
      <div
        className="absolute inset-0 bg-black/60 transition-opacity"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Slide-out panel */}
      <div className="absolute inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-xl bg-surface border-l border-border shadow-2xl flex flex-col">
          {/* Header */}
          <div className="h-14 px-6 border-b border-border flex items-center justify-between bg-raised">
            <div>
              <h3 className="text-sm font-semibold text-text-primary">{title}</h3>
              {subtitle && <p className="text-xs text-text-muted">{subtitle}</p>}
            </div>
            <button
              onClick={onClose}
              aria-label="Close drawer"
              className="p-1.5 rounded-control text-text-secondary hover:text-text-primary hover:bg-surface border border-transparent hover:border-border"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Content */}
          <div className="flex-1 overflow-y-auto p-6 space-y-4">
            {children}
          </div>
        </div>
      </div>
    </div>
  );
}
