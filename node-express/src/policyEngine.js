/**
 * Policy Engine: Continuous Contextual Zero-Trust Evaluation
 */
const { v4: uuidv4 } = require('uuid');
const db = require('./db');
const iam = require('./iam');
const speakeasy = require('speakeasy');

/**
 * Evaluates zero-trust policies for an incoming request.
 */
async function evaluatePolicy(req, res, next, requiredPermission = null) {
  const userId = req.user?.userId || req.user?.id;
  const ip = req.ip || req.connection?.remoteAddress || '127.0.0.1';
  const method = req.method;
  const path = req.path;

  // Retrieve fresh user state and active policies from persistent database
  const user = userId ? await db.findUserById(userId) : null;
  const policies = await db.getPolicies();
  const isPolEnabled = (id) => {
    const p = policies.find((x) => x.id === id || x.id === id.replace('-', '_'));
    return p ? Boolean(p.enabled) : true;
  };

  if (!user) {
    await db.insertAuditLog({
      id: `aud_${uuidv4().slice(0, 8)}`,
      userId: userId || 'anonymous',
      event: 'UNAUTHENTICATED_ACCESS',
      ip,
      method,
      path,
      decision: 'DENY',
      reason: 'No authenticated user identity found',
    });
    return res.status(401).json({ error: 'Authentication required' });
  }

  // ─── RULE 1: INACTIVE ACCOUNT (Dormant > 30 days) ──────────
  if (user.last_login_at && isPolEnabled('pol-02')) {
    const lastLoginTime = new Date(user.last_login_at).getTime();
    const daysInactive = (Date.now() - lastLoginTime) / (1000 * 60 * 60 * 24);

    if (daysInactive > 30 || user.status === 'disabled') {
      if (user.status !== 'disabled') {
        await db.updateUserStatus(user.id, 'disabled');
      }
      await db.insertAuditLog({
        id: `aud_${uuidv4().slice(0, 8)}`,
        userId: user.id,
        event: 'DORMANT_ACCOUNT_BLOCKED',
        ip,
        method,
        path,
        decision: 'DENY',
        reason: `Account inactive for ${Math.floor(daysInactive)} days. Automatically locked.`,
        details: { daysInactive, role: user.role },
      });
      return res.status(403).json({
        error: 'Account locked: Dormant identity inactive for > 30 days. Contact security.',
      });
    }
  }

  // ─── RULE 2: ADMIN MFA ENFORCEMENT ────────────────────────
  const isAdminTarget =
    path.startsWith('/admin') ||
    requiredPermission === 'manage';

  if (isAdminTarget && isPolEnabled('pol-01')) {
    const mfaHeader = req.headers['x-mfa-token'];
    let mfaValid = false;

    if (user.totp_secret && mfaHeader) {
      mfaValid = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: mfaHeader,
        window: 1,
      });
    }

    // Check if recovery code was passed
    if (!mfaValid && mfaHeader && user.recovery_codes?.includes(mfaHeader)) {
      mfaValid = true;
    }

    if (!mfaValid) {
      await db.insertAuditLog({
        id: `aud_${uuidv4().slice(0, 8)}`,
        userId: user.id,
        event: 'MFA_CHALLENGE_FAILED',
        ip,
        method,
        path,
        decision: 'CHALLENGE',
        reason: 'Step-up MFA verification failed or token missing',
        details: { target: path, role: user.role },
      });
      return res.status(401).json({
        error: 'Multi-factor authentication required for privileged route',
        mfa_required: true,
        header_required: 'X-MFA-Token',
      });
    }
  }

  // ─── RULE 3: DEVICE FINGERPRINT TRUST CHALLENGE ───────────
  const clientFingerprint = req.headers['x-device-fingerprint'] || req.fingerprint;
  const knownDevices = user.trusted_devices || [];
  const isTrusted = clientFingerprint && knownDevices.includes(clientFingerprint);

  if (clientFingerprint && !isTrusted && isPolEnabled('pol-03')) {
    req.newDevice = true;
    await db.insertAuditLog({
      id: `aud_${uuidv4().slice(0, 8)}`,
      userId: user.id,
      event: 'DEVICE_UNRECOGNIZED',
      ip,
      method,
      path,
      decision: 'WARN',
      reason: 'Session presented from an unrecognized device fingerprint',
      details: { fingerprint: clientFingerprint },
    });
  }

  // ─── RULE 4: LEAST PRIVILEGE RBAC ─────────────────────────
  if (requiredPermission) {
    const granted = iam.hasPermission(user.role, requiredPermission);
    if (!granted) {
      await db.insertAuditLog({
        id: `aud_${uuidv4().slice(0, 8)}`,
        userId: user.id,
        event: 'AUTHORIZATION_DENIED',
        ip,
        method,
        path,
        decision: 'DENY',
        reason: `Role '${user.role}' lacks required entitlement '${requiredPermission}'`,
        details: { required: requiredPermission, userRole: user.role },
      });
      return res.status(403).json({
        error: `Forbidden: Role '${user.role}' lacks required permission '${requiredPermission}'`,
      });
    }
  }

  // Record allowed policy decision
  await db.insertAuditLog({
    id: `aud_${uuidv4().slice(0, 8)}`,
    userId: user.id,
    event: 'POLICY_EVALUATION_PASS',
    ip,
    method,
    path,
    decision: 'ALLOW',
    reason: 'Identity, device, and entitlements satisfied',
    details: { role: user.role, requiredPermission },
  });

  req.dbUser = user;
  next();
}

/**
 * Middleware factory for RBAC endpoint protection
 */
function enforcePolicy(requiredPermission = null) {
  return (req, res, next) => {
    evaluatePolicy(req, res, next, requiredPermission).catch(next);
  };
}

module.exports = {
  evaluatePolicy,
  enforcePolicy,
};
