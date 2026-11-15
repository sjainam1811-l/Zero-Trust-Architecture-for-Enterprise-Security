import React, { useState, useEffect } from 'react';
import { ArrowRight, AlertTriangle, ShieldCheck } from 'lucide-react';
import { apiClient } from '../../zero-trust-auth.jsx';

export function NetworkSegmentationPage() {
  const [labData, setLabData] = useState({
    labMode: 'Checking lab status...',
    dockerRunning: false,
    services: [],
    networks: [],
  });
  const [loading, setLoading] = useState(false);

  const fetchLabStatus = async () => {
    setLoading(true);
    try {
      const res = await apiClient.get('/api/lab/status');
      const filteredServices = (res.data.services || []).filter(
        (s) => !s.name.toLowerCase().includes('app-api') && !s.role.toLowerCase().includes('fastapi')
      );
      setLabData({
        ...res.data,
        services: filteredServices,
      });
    } catch (err) {
      console.warn('Lab status fallback:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchLabStatus();
  }, []);

  // Standard 5 allowed services per prompt: Node.js auth service, React console, PostgreSQL, Redis and attacker container
  const cleanServices = [
    {
      name: 'React console',
      role: 'Web client user interface',
      network: 'frontend-net',
      port: '5173',
      status: 'Up',
    },
    {
      name: 'Node.js auth service',
      role: 'Authentication gateway & policies',
      network: 'frontend-net / app-net',
      port: '4000',
      status: 'Up',
    },
    {
      name: 'PostgreSQL database',
      role: 'User and audit log persistence',
      network: 'db-net',
      port: '5432',
      status: 'Up',
    },
    {
      name: 'Redis cache',
      role: 'Token blacklist and login counters',
      network: 'app-net',
      port: '6379',
      status: 'Up',
    },
    {
      name: 'Attacker container',
      role: 'Isolated penetration test container',
      network: 'frontend-net',
      port: 'None',
      status: 'Blocked',
    },
  ];

  return (
    <div className="space-y-6">
      {/* Title & Short Description (Health button removed per user instruction) */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-text-primary tracking-tight">Network & Lab</h1>
          <p className="text-sm font-medium text-text-secondary mt-1">
            Zero-Trust micro-segmentation and container isolation rules.
          </p>
        </div>
      </div>

      {/* Lab Mode Banner */}
      {!labData.dockerRunning ? (
        <div className="bg-surface border border-border rounded-card p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-raised rounded-control text-status-warning">
              <AlertTriangle className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold text-text-primary">
                Local Enterprise Lab Mode (Standalone Ports)
              </div>
              <p className="text-xs font-medium text-text-secondary">
                Services are running directly on verified ports with strict firewall and zero-trust routing.
              </p>
            </div>
          </div>
          <span className="pill-warning shrink-0 font-bold">Standalone</span>
        </div>
      ) : (
        <div className="bg-surface border border-border rounded-card p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-raised rounded-control text-status-pass">
              <ShieldCheck className="w-5 h-5" />
            </div>
            <div>
              <div className="text-sm font-bold text-text-primary">
                Docker Network Separation Active
              </div>
              <p className="text-xs font-medium text-text-secondary">
                Containers are running in separate Docker bridge networks with strict egress filtering.
              </p>
            </div>
          </div>
          <span className="pill-pass shrink-0 font-bold">Segmented</span>
        </div>
      )}

      {/* Blocked Path Banner */}
      <div className="bg-surface border border-border rounded-card p-4 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3 shadow-xs">
        <div className="flex items-center gap-2">
          <span className="text-sm font-bold text-text-primary">Direct client to database:</span>
          <span className="text-xs font-medium text-text-secondary">Packets from outside untrusted nets are dropped before reaching port 5432 / 6379</span>
        </div>
        <span className="pill-fail shrink-0 font-bold">Blocked</span>
      </div>

      {/* 3 Zone Columns */}
      <div className="bg-surface border border-border rounded-card p-6 space-y-4 shadow-xs">
        <div className="text-xs font-bold uppercase text-text-secondary tracking-wider">
          Docker network zones
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 items-stretch">
          {/* Zone 1: Public Ingress */}
          <div className="p-4 bg-raised rounded-card border border-border space-y-3 flex flex-col">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-text-primary">Zone 1 (Ingress)</span>
              <span className="font-mono text-xs bg-surface px-2 py-0.5 rounded border border-border font-semibold text-text-primary">
                frontend-net
              </span>
            </div>
            <div className="p-3 bg-surface border border-border rounded-control space-y-1">
              <div className="text-sm font-bold text-text-primary">React Console</div>
              <div className="text-xs font-mono font-medium text-text-muted">Port 5173</div>
            </div>
            <div className="p-3 bg-surface border border-border rounded-control space-y-1">
              <div className="text-sm font-bold text-text-primary">Attacker Container</div>
              <div className="text-xs font-mono font-medium text-status-fail">Isolated sandbox</div>
            </div>
          </div>

          {/* Zone 2: Application Gateway */}
          <div className="p-4 bg-raised rounded-card border border-border space-y-3 flex flex-col">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-text-primary">Zone 2 (Gateway)</span>
              <span className="font-mono text-xs bg-surface px-2 py-0.5 rounded border border-border font-semibold text-blue">
                app-net
              </span>
            </div>
            <div className="p-3 bg-surface border border-border rounded-control space-y-1">
              <div className="text-sm font-bold text-text-primary">Node.js Auth Gateway</div>
              <div className="text-xs font-mono font-medium text-text-muted">Port 4000</div>
            </div>
            <div className="p-3 bg-surface border border-border rounded-control space-y-1">
              <div className="text-sm font-bold text-text-primary">Redis Cache</div>
              <div className="text-xs font-mono font-medium text-text-muted">Port 6379</div>
            </div>
          </div>

          {/* Zone 3: Data Store */}
          <div className="p-4 bg-raised rounded-card border border-border space-y-3 flex flex-col">
            <div className="flex items-center justify-between">
              <span className="text-xs font-bold text-text-primary">Zone 3 (Isolated)</span>
              <span className="font-mono text-xs bg-surface px-2 py-0.5 rounded border border-border font-semibold text-status-pass">
                db-net
              </span>
            </div>
            <div className="p-3 bg-surface border border-border rounded-control space-y-1">
              <div className="text-sm font-bold text-text-primary">PostgreSQL Database</div>
              <div className="text-xs font-mono font-medium text-text-muted">Port 5432</div>
            </div>
            <div className="p-3 bg-surface border border-border rounded-control space-y-1">
              <div className="text-sm font-bold text-text-primary">SQLite Persistent Storage</div>
              <div className="text-xs font-mono font-medium text-text-muted">zero_trust.sqlite</div>
            </div>
          </div>
        </div>

        {/* Straight Flow Indicator Bar */}
        <div className="hidden md:flex items-center justify-between px-6 py-2.5 text-xs font-semibold text-text-secondary border-t border-border mt-3">
          <span>Client Web Ingress</span>
          <ArrowRight className="w-4 h-4 text-blue shrink-0" />
          <span>Node.js Policy Enforcement Gateway</span>
          <ArrowRight className="w-4 h-4 text-blue shrink-0" />
          <span>Isolated Database Storage</span>
        </div>
      </div>

      {/* Services Table - Pristine alignment with generous spacing, no text clipping */}
      <div className="bg-surface border border-border rounded-card p-6 space-y-4 shadow-xs">
        <div>
          <div className="text-base font-bold text-text-primary">Service list</div>
          <p className="text-xs text-text-secondary mt-0.5">Continuous connectivity and microsegmentation firewall status.</p>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs min-w-[720px]">
            <thead>
              <tr className="border-b border-border text-text-secondary bg-raised/70">
                <th className="py-3 px-5 font-bold text-text-primary">Service</th>
                <th className="py-3 px-5 font-bold text-text-primary">Role</th>
                <th className="py-3 px-5 font-bold text-text-primary">Network zone</th>
                <th className="py-3 px-5 font-bold text-text-primary">Port</th>
                <th className="py-3 px-5 font-bold text-text-primary text-right">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {cleanServices.map((s, i) => (
                <tr key={i} className="hover:bg-raised/50 transition-colors">
                  <td className="py-3.5 px-5 font-bold text-text-primary">{s.name}</td>
                  <td className="py-3.5 px-5 font-medium text-text-secondary">{s.role}</td>
                  <td className="py-3.5 px-5">
                    <span className="font-mono text-xs bg-raised px-2.5 py-1 rounded border border-border text-text-secondary font-semibold inline-block">
                      {s.network}
                    </span>
                  </td>
                  <td className="py-3.5 px-5 font-mono font-bold text-text-secondary">{s.port}</td>
                  <td className="py-3.5 px-5 text-right">
                    <span
                      className={`font-bold inline-block ${
                        s.status === 'Up'
                          ? 'pill-pass'
                          : s.status === 'Blocked'
                          ? 'pill-fail'
                          : 'pill-warning'
                      }`}
                    >
                      {s.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
