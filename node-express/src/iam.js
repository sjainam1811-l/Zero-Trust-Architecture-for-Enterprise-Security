/**
 * IAM Module: Role-Based Access Control and Identity Governance
 */
const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

const ROLE_PERMISSIONS = {
  admin: ['read', 'write', 'delete', 'manage', 'audit'],
  editor: ['read', 'write'],
  viewer: ['read'],
  auditor: ['read', 'audit'],
};

const VALID_ROLES = Object.keys(ROLE_PERMISSIONS);

function getRolePermissions() {
  return ROLE_PERMISSIONS;
}

function hasPermission(role, requiredPermission) {
  const perms = ROLE_PERMISSIONS[role] || [];
  return perms.includes(requiredPermission);
}

// Handler: GET /api/iam/matrix
function getMatrixHandler(req, res) {
  return res.status(200).json({
    matrix: ROLE_PERMISSIONS,
    roles: VALID_ROLES,
  });
}

// Handler: PUT /api/iam/matrix
function updateMatrixHandler(req, res) {
  const { matrix } = req.body;
  if (!matrix || typeof matrix !== 'object') {
    return res.status(400).json({ error: 'matrix object is required' });
  }
  for (const [role, perms] of Object.entries(matrix)) {
    if (ROLE_PERMISSIONS[role]) {
      ROLE_PERMISSIONS[role] = Array.isArray(perms) ? perms : Object.keys(perms).filter((k) => perms[k]);
    }
  }
  return res.status(200).json({
    message: 'Role permissions matrix updated successfully',
    matrix: ROLE_PERMISSIONS,
  });
}

// Handler: GET /api/users
async function listUsersHandler(req, res) {
  try {
    const users = await db.listUsers();
    return res.status(200).json({ users });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to retrieve identities', detail: err.message });
  }
}

// Handler: POST /api/users
async function createUserHandler(req, res) {
  try {
    const { email, password, role, mfaEnabled } = req.body;
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }
    const assignedRole = role || 'viewer';
    if (!VALID_ROLES.includes(assignedRole)) {
      return res.status(400).json({ error: `Invalid role. Allowed roles: ${VALID_ROLES.join(', ')}` });
    }

    const existing = await db.findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ error: 'Identity already exists with this email' });
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const id = `usr_${uuidv4().slice(0, 8)}`;

    const user = await db.createUser({
      id,
      email,
      passwordHash,
      role: assignedRole,
      mfaEnabled: Boolean(mfaEnabled),
    });

    return res.status(201).json({
      message: 'Identity created successfully',
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        mfa_enabled: Boolean(user.mfa_enabled),
        status: user.status,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to create user', detail: err.message });
  }
}

// Handler: PATCH /api/users/:id/role
async function updateUserRoleHandler(req, res) {
  try {
    const { id } = req.params;
    const { role } = req.body;
    if (!role || !VALID_ROLES.includes(role)) {
      return res.status(400).json({ error: `Invalid role. Allowed roles: ${VALID_ROLES.join(', ')}` });
    }

    const user = await db.findUserById(id);
    if (!user) {
      return res.status(404).json({ error: 'User identity not found' });
    }

    const updated = await db.updateUserRole(id, role);
    return res.status(200).json({
      message: `Role updated to ${role}`,
      user: {
        id: updated.id,
        email: updated.email,
        role: updated.role,
        status: updated.status,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update user role', detail: err.message });
  }
}

// Handler: PATCH /api/users/:id/status
async function updateUserStatusHandler(req, res) {
  try {
    const { id } = req.params;
    const { status } = req.body;
    if (!status || !['active', 'disabled'].includes(status)) {
      return res.status(400).json({ error: 'Status must be "active" or "disabled"' });
    }

    const user = await db.findUserById(id);
    if (!user) {
      return res.status(404).json({ error: 'User identity not found' });
    }

    const updated = await db.updateUserStatus(id, status);
    return res.status(200).json({
      message: `Account status updated to ${status}`,
      user: {
        id: updated.id,
        email: updated.email,
        status: updated.status,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to update user status', detail: err.message });
  }
}

// Handler: DELETE /api/users/:id
async function deleteUserHandler(req, res) {
  try {
    const { id } = req.params;
    await db.deleteUser(id);
    return res.status(200).json({
      message: 'User identity deleted successfully',
      id,
    });
  } catch (err) {
    return res.status(500).json({ error: 'Failed to delete user', detail: err.message });
  }
}

module.exports = {
  ROLE_PERMISSIONS,
  VALID_ROLES,
  getRolePermissions,
  hasPermission,
  getMatrixHandler,
  updateMatrixHandler,
  listUsersHandler,
  createUserHandler,
  deleteUserHandler,
  updateUserRoleHandler,
  updateUserStatusHandler,
};
