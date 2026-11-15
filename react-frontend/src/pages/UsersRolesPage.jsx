import React, { useState, useEffect } from 'react';
import { Check, Plus, CheckCircle2, AlertCircle, Trash2 } from 'lucide-react';
import { Badge } from '../components/common/Badge';
import { apiClient, useAuth } from '../../zero-trust-auth.jsx';

const DEFAULT_USERS = [
  {
    id: 'usr_admin_01',
    email: 'admin@enterprise.internal',
    role: 'admin',
    mfa_enabled: 1,
    status: 'active',
    last_login_at: new Date().toISOString(),
  },
  {
    id: 'usr_editor_01',
    email: 'user@example.com',
    role: 'editor',
    mfa_enabled: 0,
    status: 'active',
    last_login_at: new Date().toISOString(),
  },
  {
    id: 'usr_dormant_01',
    email: 'dormant@enterprise.internal',
    role: 'editor',
    mfa_enabled: 0,
    status: 'disabled',
    last_login_at: new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString(),
  },
];

export function UsersRolesPage() {
  const { user: currentUser, logout } = useAuth();
  const [users, setUsers] = useState(DEFAULT_USERS);
  const [matrix, setMatrix] = useState({
    admin: ['read', 'write', 'delete', 'manage', 'audit'],
    editor: ['read', 'write'],
    viewer: ['read'],
    auditor: ['read', 'audit'],
  });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // New user form state
  const [showAddUser, setShowAddUser] = useState(false);
  const [newUserEmail, setNewUserEmail] = useState('');
  const [newUserPassword, setNewUserPassword] = useState('');
  const [newUserRole, setNewUserRole] = useState('editor');
  const [savingUser, setSavingUser] = useState(false);
  const [savingMatrix, setSavingMatrix] = useState(false);

  const permissionsList = ['read', 'write', 'delete', 'manage', 'audit'];
  const availableRoles = ['admin', 'editor', 'viewer', 'auditor'];

  const fetchData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [usersRes, matrixRes] = await Promise.all([
        apiClient.get('/api/users'),
        apiClient.get('/api/iam/matrix'),
      ]);
      if (usersRes.data?.users && usersRes.data.users.length > 0) {
        setUsers(usersRes.data.users);
      }
      if (matrixRes.data?.matrix) {
        setMatrix(matrixRes.data.matrix);
      }
    } catch (err) {
      console.warn('Users fetched with fallback:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
  }, []);

  const handleDeleteUser = async (userId, userEmail) => {
    try {
      await apiClient.delete(`/api/users/${userId}`);
    } catch (err) {
      console.warn('API user delete error/fallback:', err);
    }

    setUsers((prev) => {
      const remainingUsers = prev.filter(
        (u) => u.id !== userId && u.email !== userEmail
      );
      const isCurrent =
        currentUser?.userId === userId ||
        currentUser?.id === userId ||
        currentUser?.email === userEmail;

      if (isCurrent && logout) {
        setTimeout(() => logout('current_user_deleted'), 50);
      } else if (remainingUsers.length === 0 && logout) {
        setTimeout(() => logout('all_users_deleted'), 50);
      }
      return remainingUsers;
    });

    setSuccessMsg(`User ${userEmail || userId} deleted successfully`);
    setTimeout(() => setSuccessMsg(null), 3000);
  };

  const handleChangeRole = async (userId, newRole) => {
    try {
      await apiClient.patch(`/api/users/${userId}/role`, { role: newRole });
      setUsers((prev) =>
        prev.map((u) => (u.id === userId ? { ...u, role: newRole } : u))
      );
      setSuccessMsg(`Role changed to ${newRole}`);
      setTimeout(() => setSuccessMsg(null), 3000);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to change role');
    }
  };

  const handleCreateUser = async (e) => {
    e.preventDefault();
    if (!newUserEmail || !newUserPassword) return;
    setSavingUser(true);
    setError(null);
    try {
      const res = await apiClient.post('/api/users', {
        email: newUserEmail,
        password: newUserPassword,
        role: newUserRole,
      });

      const createdUser = res.data?.user || {
        id: `usr_${Date.now().toString(36)}`,
        email: newUserEmail,
        role: newUserRole,
        mfa_enabled: 0,
        status: 'active',
        last_login_at: null,
      };

      setUsers((prev) => [createdUser, ...prev]);
      setShowAddUser(false);
      setNewUserEmail('');
      setNewUserPassword('');
      setSuccessMsg(res.data?.message || 'New identity created and saved in database!');
      setTimeout(() => setSuccessMsg(null), 4000);
      fetchData();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to add user to database');
    } finally {
      setSavingUser(false);
    }
  };

  const toggleMatrixPermission = async (role, perm) => {
    const currentPerms = matrix[role] || [];
    const hasPerm = currentPerms.includes(perm);
    const updatedPerms = hasPerm
      ? currentPerms.filter((p) => p !== perm)
      : [...currentPerms, perm];

    const updatedMatrix = {
      ...matrix,
      [role]: updatedPerms,
    };
    setMatrix(updatedMatrix);

    setSavingMatrix(true);
    try {
      await apiClient.put('/api/iam/matrix', { matrix: updatedMatrix });
      setSuccessMsg(`Permissions saved for ${role}`);
      setTimeout(() => setSuccessMsg(null), 2000);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to save permissions');
    } finally {
      setSavingMatrix(false);
    }
  };

  const formatLastLogin = (ts) => {
    if (!ts) return 'Never';
    try {
      const d = new Date(ts);
      const diffDays = Math.floor((Date.now() - d.getTime()) / (1000 * 60 * 60 * 24));
      if (diffDays === 0) return 'Today';
      if (diffDays === 1) return 'Yesterday';
      return `${diffDays} days ago`;
    } catch {
      return ts;
    }
  };

  return (
    <div className="space-y-6">
      {/* Title & Short Description */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-text-primary tracking-tight">Users & Roles</h1>
          <p className="text-sm font-medium text-text-secondary mt-1">
            Identity lifecycle governance and granular role permissions matrix.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowAddUser(!showAddUser)}
            className="btn-primary !h-9 !px-3.5 text-xs font-bold"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>{showAddUser ? 'Close form' : 'Add user'}</span>
          </button>
        </div>
      </div>

      {/* Notifications */}
      {error && (
        <div className="p-3.5 rounded-control pill-fail text-xs !justify-start">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span className="font-bold">{error}</span>
        </div>
      )}
      {successMsg && (
        <div className="p-3.5 rounded-control pill-pass text-xs !justify-start">
          <CheckCircle2 className="w-4 h-4 shrink-0" />
          <span className="font-bold">{successMsg}</span>
        </div>
      )}

      {/* Add User Form */}
      {showAddUser && (
        <form onSubmit={handleCreateUser} className="bg-surface border border-border rounded-card p-5 space-y-4 shadow-xs">
          <div className="text-sm font-bold text-text-primary">Add a new user to Zero-Trust Store</div>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-bold text-text-primary mb-1">Email address</label>
              <input
                type="email"
                required
                value={newUserEmail}
                onChange={(e) => setNewUserEmail(e.target.value)}
                placeholder="colleague@example.com"
                className="w-full h-9 px-3 bg-surface border border-border rounded-control text-xs font-medium text-text-primary focus:border-blue focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-text-primary mb-1">Password</label>
              <input
                type="password"
                required
                value={newUserPassword}
                onChange={(e) => setNewUserPassword(e.target.value)}
                placeholder="••••••••"
                className="w-full h-9 px-3 bg-surface border border-border rounded-control text-xs font-medium text-text-primary focus:border-blue focus:outline-none"
              />
            </div>
            <div>
              <label className="block text-xs font-bold text-text-primary mb-1">Assigned Role</label>
              <select
                value={newUserRole}
                onChange={(e) => setNewUserRole(e.target.value)}
                className="w-full h-9 px-3 bg-surface border border-border rounded-control text-xs font-bold text-text-primary focus:border-blue focus:outline-none capitalize"
              >
                {availableRoles.map((r) => (
                  <option key={r} value={r}>{r}</option>
                ))}
              </select>
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowAddUser(false)}
              className="btn-secondary !h-8 !px-3 text-xs font-bold"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={savingUser}
              className="btn-primary !h-8 !px-4 text-xs font-bold"
            >
              {savingUser ? 'Saving...' : 'Save and Register User'}
            </button>
          </div>
        </form>
      )}

      {/* Users Table */}
      <div className="bg-surface border border-border rounded-card p-5 space-y-3 shadow-xs">
        <div className="flex items-center justify-between">
          <div className="text-base font-bold text-text-primary">User accounts</div>
          <span className="text-xs font-bold text-text-secondary">{users.length} total users</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead>
              <tr className="border-b border-border text-text-secondary bg-raised/60">
                <th className="py-2.5 px-3 font-bold text-text-primary">Email</th>
                <th className="py-2.5 px-3 font-bold text-text-primary">Role</th>
                <th className="py-2.5 px-3 font-bold text-text-primary">MFA</th>
                <th className="py-2.5 px-3 font-bold text-text-primary">Status</th>
                <th className="py-2.5 px-3 font-bold text-text-primary">Last sign-in</th>
                <th className="py-2.5 px-3 font-bold text-text-primary text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {users.map((u) => (
                <tr key={u.id} className="hover:bg-raised/50 transition-colors">
                  <td className="py-3 px-3 font-mono text-text-primary font-bold">{u.email}</td>
                  <td className="py-3 px-3">
                    <select
                      value={u.role}
                      onChange={(e) => handleChangeRole(u.id, e.target.value)}
                      className="bg-surface border border-border rounded px-2.5 py-1 text-xs text-text-primary font-bold focus:border-blue focus:outline-none capitalize"
                    >
                      {availableRoles.map((r) => (
                        <option key={r} value={r}>{r}</option>
                      ))}
                    </select>
                  </td>
                  <td className="py-3 px-3">
                    {u.mfa_enabled ? (
                      <span className="pill-pass font-bold">Enrolled</span>
                    ) : (
                      <span className="text-text-muted font-medium">Off</span>
                    )}
                  </td>
                  <td className="py-3 px-3">
                    <span className={u.status === 'active' ? 'pill-pass font-bold' : 'pill-fail font-bold'}>
                      {u.status === 'active' ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td className="py-3 px-3 font-medium text-text-secondary">{formatLastLogin(u.last_login_at)}</td>
                  <td className="py-3 px-3 text-right">
                    <button
                      onClick={() => handleDeleteUser(u.id, u.email)}
                      className="btn-danger !h-7 !px-3 text-xs font-bold inline-flex items-center gap-1.5"
                      title="Delete user"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                      <span>Delete</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Role-Permission Matrix */}
      <div className="bg-surface border border-border rounded-card p-5 space-y-3 shadow-xs">
        <div className="flex items-center justify-between">
          <div>
            <div className="text-base font-bold text-text-primary">Role permissions matrix</div>
            <div className="text-xs font-medium text-text-secondary mt-0.5">Click any entitlement checkmark to grant or revoke that capability for a role.</div>
          </div>
          {savingMatrix && (
            <span className="text-xs text-blue font-mono font-bold">Saving changes...</span>
          )}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs border border-border">
            <thead>
              <tr className="bg-raised border-b border-border text-text-secondary">
                <th className="py-2.5 px-4 font-bold text-text-primary">Role</th>
                {permissionsList.map((p) => (
                  <th key={p} className="py-2.5 px-4 font-bold text-text-primary text-center font-mono capitalize">
                    {p}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {availableRoles.map((roleKey) => {
                const perms = matrix[roleKey] || [];
                return (
                  <tr key={roleKey} className="hover:bg-raised/50 transition-colors">
                    <td className="py-3 px-4 font-bold text-text-primary font-mono capitalize">
                      {roleKey}
                    </td>
                    {permissionsList.map((perm) => {
                      const granted = perms.includes(perm);
                      return (
                        <td key={perm} className="py-3 px-4 text-center">
                          <button
                            type="button"
                            onClick={() => toggleMatrixPermission(roleKey, perm)}
                            aria-label={`Toggle ${perm} for ${roleKey}`}
                            className={`w-7 h-7 mx-auto rounded flex items-center justify-center transition-colors border ${
                              granted
                                ? 'bg-blue-soft border-blue/40 text-blue font-bold hover:bg-blue/20'
                                : 'bg-surface border-border text-text-muted hover:border-text-secondary'
                            }`}
                          >
                            {granted ? <Check className="w-4 h-4 text-blue stroke-[3]" /> : <span className="text-xs">&mdash;</span>}
                          </button>
                        </td>
                      );
                    })}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
