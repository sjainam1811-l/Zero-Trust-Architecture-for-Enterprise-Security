import {
  LayoutDashboard,
  Fingerprint,
  Smartphone,
  Users,
  ScrollText,
  Network,
  Lock,
  ShieldAlert,
  BarChart3,
} from 'lucide-react';

export const NAV_GROUPS = [
  {
    group: 'OVERVIEW',
    items: [
      { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    ],
  },
  {
    group: 'IDENTITY',
    items: [
      { id: 'session', label: 'Login & Session', icon: Fingerprint },
      { id: 'mfa-setup', label: 'MFA Setup', icon: Smartphone },
    ],
  },
  {
    group: 'ACCESS CONTROL',
    items: [
      { id: 'users-roles', label: 'Users & Roles', icon: Users },
      { id: 'policies', label: 'Policies', icon: ScrollText },
    ],
  },
  {
    group: 'INFRASTRUCTURE',
    items: [
      { id: 'network-lab', label: 'Network & Lab', icon: Network },
      { id: 'encryption', label: 'Encryption', icon: Lock },
    ],
  },
  {
    group: 'SECURITY TESTING',
    items: [
      { id: 'threat-lab', label: 'Threat Lab', icon: ShieldAlert },
    ],
  },
  {
    group: 'REPORT',
    items: [
      { id: 'results', label: 'Results', icon: BarChart3 },
    ],
  },
];
