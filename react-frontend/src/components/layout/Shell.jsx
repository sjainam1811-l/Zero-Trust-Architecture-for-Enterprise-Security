import React, { useState } from 'react';
import {
  Menu,
  ChevronLeft,
  ChevronRight,
  LogOut,
} from 'lucide-react';
import { NAV_GROUPS } from '../../constants/nav';

export function Shell({
  activePage,
  setActivePage,
  user,
  onLogout,
  children,
}) {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState(false);

  // Breadcrumb mapping
  const activeItem = NAV_GROUPS.flatMap((g) => g.items).find((i) => i.id === activePage);
  const activeGroup = NAV_GROUPS.find((g) => g.items.some((i) => i.id === activePage));

  const sidebarContent = (
    <div className="flex flex-col h-full bg-surface border-r border-border select-none">
      {/* Brand Header (56px) */}
      <div className="h-14 px-4 flex items-center justify-between border-b border-border bg-surface shrink-0">
        <div className="flex items-center gap-2.5 overflow-hidden">
          {!isCollapsed && (
            <span className="text-base font-bold text-text-primary tracking-tight truncate">
              Zero-Trust Console
            </span>
          )}
        </div>

        {/* Desktop Collapse Toggle */}
        <button
          onClick={() => setIsCollapsed(!isCollapsed)}
          className="hidden lg:flex p-1.5 rounded-control text-text-muted hover:text-text-primary hover:bg-raised border border-transparent hover:border-border"
          aria-label={isCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {isCollapsed ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </div>

      {/* Navigation Group Items: 9 items total, 36px item height, fits 1366x768 without scrolling */}
      <nav className="flex-1 p-2 space-y-2.5 overflow-y-auto">
        {NAV_GROUPS.map((group) => (
          <div key={group.group}>
            {!isCollapsed && (
              <div className="px-3 pb-1 text-xs font-bold uppercase text-text-secondary tracking-wider">
                {group.group}
              </div>
            )}
            <div className="space-y-0.5">
              {group.items.map((item) => {
                const Icon = item.icon;
                const isActive = activePage === item.id;
                return (
                  <button
                    key={item.id}
                    onClick={() => {
                      setActivePage(item.id);
                      setMobileDrawerOpen(false);
                    }}
                    title={isCollapsed ? item.label : undefined}
                    className={`w-full h-9 flex items-center gap-3 px-3 text-sm rounded-control text-left transition-colors relative whitespace-nowrap font-medium ${
                      isActive
                        ? 'bg-blue-soft text-blue font-bold border-l-[3px] border-blue pl-[9px]'
                        : 'text-text-secondary hover:text-text-primary hover:bg-raised border-l-[3px] border-transparent font-medium'
                    }`}
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    {!isCollapsed && <span className="truncate">{item.label}</span>}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </nav>
    </div>
  );

  return (
    <div className="min-h-screen flex bg-base text-text-primary font-sans">
      {/* Sticky Desktop Sidebar */}
      <aside
        className={`hidden lg:block shrink-0 sticky top-0 h-[100dvh] transition-all duration-150 no-print ${
          isCollapsed ? 'w-16' : 'w-[240px]'
        }`}
      >
        {sidebarContent}
      </aside>

      {/* Mobile Drawer (< 1024px) */}
      {mobileDrawerOpen && (
        <div className="fixed inset-0 z-50 lg:hidden flex no-print">
          <div
            className="fixed inset-0 bg-black/40 backdrop-blur-xs"
            onClick={() => setMobileDrawerOpen(false)}
            aria-hidden="true"
          />
          <div className="relative w-[240px] h-full z-10">
            {sidebarContent}
          </div>
        </div>
      )}

      {/* Main Container - Only Content Area Scrolls */}
      <div className="flex-1 flex flex-col min-w-0 min-h-screen">
        {/* Top Bar (56px) */}
        <header className="h-14 px-4 sm:px-6 bg-surface border-b border-border sticky top-0 z-30 flex items-center justify-between gap-4 no-print">
          <div className="flex items-center gap-3">
            <button
              onClick={() => setMobileDrawerOpen(true)}
              className="lg:hidden p-1.5 rounded-control text-text-secondary hover:text-text-primary hover:bg-raised border border-border"
              aria-label="Open navigation menu"
            >
              <Menu className="w-4 h-4" />
            </button>

            {/* Breadcrumb: sentence case */}
            <div className="flex items-center gap-1.5 text-xs text-text-secondary font-bold">
              <span>{activeGroup?.group ? activeGroup.group.charAt(0) + activeGroup.group.slice(1).toLowerCase() : 'Overview'}</span>
              <span className="text-text-muted">/</span>
              <span className="text-text-primary font-bold">{activeItem?.label || 'Dashboard'}</span>
            </div>
          </div>

          {/* Right: Single 36px icon-only Log out button */}
          <div className="flex items-center">
            {onLogout && (
              <button
                onClick={onLogout}
                aria-label="Log out"
                title="Log out"
                className="w-9 h-9 rounded-control flex items-center justify-center text-text-secondary hover:text-status-fail hover:bg-status-fail-soft border border-border transition-colors"
              >
                <LogOut className="w-4 h-4" />
              </button>
            )}
          </div>
        </header>

        {/* Content Area: Max width 1200px, padding 24px */}
        <main className="flex-1 p-6 max-w-[1200px] w-full mx-auto flex flex-col space-y-6">
          <div className="flex-1 space-y-6">
            {children}
          </div>

          {/* Small Footer at bottom of each page with distinct divider line and highlight */}
          <footer className="mt-12 pt-6 pb-6 text-xs text-center border-t-2 border-border/80 space-y-2 select-none no-print">
            <div className="font-bold text-text-primary text-sm tracking-tight">
              Minor Project 2: Zero Trust Architecture for Enterprise Security
            </div>
            <div className="flex justify-center">
              <span className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-full bg-blue-soft border border-blue/25 text-blue font-bold text-xs shadow-xs tracking-wide">
                Developed by Jainam Shah and Mahi Patel &bull; Group C
              </span>
            </div>
          </footer>
        </main>
      </div>
    </div>
  );
}
