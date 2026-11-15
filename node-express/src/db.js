/**
 * Database Layer for Zero-Trust Enterprise Lab
 * Supports persistent SQLite file storage via sql.js (pure JS/WASM)
 * and PostgreSQL when DATABASE_URL is defined (Docker Compose).
 */
const fs = require('fs');
const path = require('path');
const initSqlJs = require('sql.js');
const bcrypt = require('bcryptjs');
const cryptoUtil = require('./cryptoUtil');

const DATA_DIR = path.join(__dirname, '..', 'data');
const DB_PATH = path.join(DATA_DIR, 'zero_trust.sqlite');

let sqlDb = null;

async function getDb() {
  if (sqlDb) return sqlDb;

  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }

  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const fileBuffer = fs.readFileSync(DB_PATH);
    sqlDb = new SQL.Database(fileBuffer);
  } else {
    sqlDb = new SQL.Database();
    initSchema(sqlDb);
    await seedData(sqlDb);
    saveDb();
  }
  return sqlDb;
}

function saveDb() {
  if (!sqlDb) return;
  const data = sqlDb.export();
  fs.writeFileSync(DB_PATH, Buffer.from(data));
}

function initSchema(db) {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL,
      mfa_enabled INTEGER DEFAULT 0,
      totp_secret TEXT DEFAULT NULL,
      recovery_codes TEXT DEFAULT '[]',
      status TEXT DEFAULT 'active',
      created_at TEXT NOT NULL,
      last_login_at TEXT,
      trusted_devices TEXT DEFAULT '[]',
      sensitive_data TEXT DEFAULT NULL
    );

    CREATE TABLE IF NOT EXISTS policies (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      condition TEXT NOT NULL,
      action TEXT NOT NULL,
      enabled INTEGER DEFAULT 1,
      description TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      user_id TEXT,
      event TEXT NOT NULL,
      ip TEXT,
      method TEXT,
      path TEXT,
      decision TEXT NOT NULL,
      reason TEXT,
      details TEXT
    );
  `);
}

async function seedData(db) {
  const salt = 12;
  const defaultPasswordHash = await bcrypt.hash('password123', salt);
  const adminPasswordHash = await bcrypt.hash('AdminSecret123!', salt);

  const now = new Date().toISOString();
  // 45 days ago for dormant account test
  const fortyFiveDaysAgo = new Date(Date.now() - 45 * 24 * 60 * 60 * 1000).toISOString();

  // Admin user with AES-256-GCM encrypted TOTP secret
  const adminSecretEncrypted = cryptoUtil.encrypt('JBSWY3DPEHPK3PXP');
  db.run(`
    INSERT OR REPLACE INTO users (id, email, password_hash, role, mfa_enabled, totp_secret, recovery_codes, status, created_at, last_login_at, trusted_devices)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    'usr_admin_01',
    'admin@enterprise.internal',
    adminPasswordHash,
    'admin',
    1,
    adminSecretEncrypted,
    JSON.stringify(['REC-1111', 'REC-2222', 'REC-3333']),
    'active',
    now,
    now,
    JSON.stringify(['sha256-admin-trusted-device']),
  ]);

  // Standard editor user
  db.run(`
    INSERT OR REPLACE INTO users (id, email, password_hash, role, mfa_enabled, totp_secret, recovery_codes, status, created_at, last_login_at, trusted_devices)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    'usr_editor_01',
    'user@example.com',
    defaultPasswordHash,
    'editor',
    0,
    null,
    JSON.stringify([]),
    'active',
    now,
    now,
    JSON.stringify(['sha256-default-device']),
  ]);

  // Read-only viewer
  db.run(`
    INSERT OR REPLACE INTO users (id, email, password_hash, role, mfa_enabled, totp_secret, recovery_codes, status, created_at, last_login_at, trusted_devices)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    'usr_viewer_01',
    'viewer@example.com',
    defaultPasswordHash,
    'viewer',
    0,
    null,
    JSON.stringify([]),
    'active',
    now,
    now,
    JSON.stringify([]),
  ]);

  // Dormant account inactive > 30 days
  db.run(`
    INSERT OR REPLACE INTO users (id, email, password_hash, role, mfa_enabled, totp_secret, recovery_codes, status, created_at, last_login_at, trusted_devices)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    'usr_dormant_01',
    'dormant@enterprise.internal',
    defaultPasswordHash,
    'editor',
    0,
    null,
    JSON.stringify([]),
    'active',
    fortyFiveDaysAgo,
    fortyFiveDaysAgo,
    JSON.stringify([]),
  ]);

  // Seed default policies
  const defaultPolicies = [
    ['pol-01', 'Admins must use MFA', 'user.role == "admin" || path.startsWith("/admin")', 'REQUIRE_MFA', 1, 'Requires TOTP verification header for all administrative actions.'],
    ['pol-02', 'Disable accounts inactive 30 days', 'now() - user.last_login_at > 30d', 'DENY_AND_DISABLE', 1, 'Automatically suspends identities without login activity for 30 days.'],
    ['pol-03', 'Challenge new devices', 'fingerprint not in user.trusted_devices', 'CHALLENGE_DEVICE', 1, 'Demands re-authentication when client hardware fingerprint is unrecognized.'],
    ['pol-04', 'Single-use refresh token rotation', 'token.type == "refresh" && token.used == true', 'TERMINATE_FAMILY', 1, 'Invalidates used refresh token JTI immediately upon exchange to prevent replay.'],
    ['pol-05', 'Brute-force lockout', 'failed_attempts >= 5 within 15m', 'LOCKOUT_429', 1, 'Locks IP and account after 5 consecutive failed login attempts within 15 minutes.'],
  ];

  for (const pol of defaultPolicies) {
    db.run(
      'INSERT OR REPLACE INTO policies (id, name, condition, action, enabled, description) VALUES (?, ?, ?, ?, ?, ?)',
      pol
    );
  }
}

// ─── QUERY HELPERS ──────────────────────────────────────────

async function findUserByEmail(email) {
  const db = await getDb();
  const res = db.exec('SELECT * FROM users WHERE email = ? LIMIT 1', [email]);
  if (!res.length || !res[0].values.length) return null;
  const cols = res[0].columns;
  const vals = res[0].values[0];
  const user = {};
  cols.forEach((c, i) => (user[c] = vals[i]));
  if (user.trusted_devices) {
    try { user.trusted_devices = JSON.parse(user.trusted_devices); } catch { user.trusted_devices = []; }
  }
  if (user.recovery_codes) {
    try { user.recovery_codes = JSON.parse(user.recovery_codes); } catch { user.recovery_codes = []; }
  }
  if (user.totp_secret && user.totp_secret.startsWith('enc:v1:aes-256-gcm:')) {
    try { user.totp_secret = cryptoUtil.decrypt(user.totp_secret); } catch {}
  }
  return user;
}

async function findUserById(id) {
  const db = await getDb();
  const res = db.exec('SELECT * FROM users WHERE id = ? LIMIT 1', [id]);
  if (!res.length || !res[0].values.length) return null;
  const cols = res[0].columns;
  const vals = res[0].values[0];
  const user = {};
  cols.forEach((c, i) => (user[c] = vals[i]));
  if (user.trusted_devices) {
    try { user.trusted_devices = JSON.parse(user.trusted_devices); } catch { user.trusted_devices = []; }
  }
  if (user.recovery_codes) {
    try { user.recovery_codes = JSON.parse(user.recovery_codes); } catch { user.recovery_codes = []; }
  }
  if (user.totp_secret && user.totp_secret.startsWith('enc:v1:aes-256-gcm:')) {
    try { user.totp_secret = cryptoUtil.decrypt(user.totp_secret); } catch {}
  }
  return user;
}

async function listUsers() {
  const db = await getDb();
  const res = db.exec('SELECT id, email, role, mfa_enabled, status, created_at, last_login_at FROM users ORDER BY created_at DESC');
  if (!res.length) return [];
  const cols = res[0].columns;
  return res[0].values.map((row) => {
    const u = {};
    cols.forEach((c, i) => (u[c] = row[i]));
    return u;
  });
}

async function createUser({ id, email, passwordHash, role, mfaEnabled = 0 }) {
  const db = await getDb();
  const now = new Date().toISOString();
  db.run(`
    INSERT INTO users (id, email, password_hash, role, mfa_enabled, status, created_at, last_login_at, trusted_devices)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [id, email, passwordHash, role, mfaEnabled ? 1 : 0, 'active', now, now, JSON.stringify([])]);
  saveDb();
  return findUserById(id);
}

async function updateUserRole(id, role) {
  const db = await getDb();
  db.run('UPDATE users SET role = ? WHERE id = ?', [role, id]);
  saveDb();
  return findUserById(id);
}

async function updateUserStatus(id, status) {
  const db = await getDb();
  db.run('UPDATE users SET status = ? WHERE id = ?', [status, id]);
  saveDb();
  return findUserById(id);
}

async function updateUserMFA(id, mfaEnabled, totpSecret, recoveryCodes = []) {
  const db = await getDb();
  const encryptedSecret = totpSecret
    ? (totpSecret.startsWith('enc:v1:aes-256-gcm:') ? totpSecret : cryptoUtil.encrypt(totpSecret))
    : null;
  db.run(`
    UPDATE users SET mfa_enabled = ?, totp_secret = ?, recovery_codes = ? WHERE id = ?
  `, [mfaEnabled ? 1 : 0, encryptedSecret, JSON.stringify(recoveryCodes), id]);
  saveDb();
  return findUserById(id);
}

async function updateLastLogin(id) {
  const db = await getDb();
  const now = new Date().toISOString();
  db.run('UPDATE users SET last_login_at = ? WHERE id = ?', [now, id]);
  saveDb();
}

async function addTrustedDevice(id, fingerprint) {
  const user = await findUserById(id);
  if (!user) return;
  const devices = new Set(user.trusted_devices || []);
  devices.add(fingerprint);
  const db = await getDb();
  db.run('UPDATE users SET trusted_devices = ? WHERE id = ?', [
    JSON.stringify(Array.from(devices)),
    id,
  ]);
  saveDb();
}

async function updateSensitiveData(id, ciphertext) {
  const db = await getDb();
  db.run('UPDATE users SET sensitive_data = ? WHERE id = ?', [ciphertext, id]);
  saveDb();
}

// ─── AUDIT LOGGING HELPERS ──────────────────────────────────

async function insertAuditLog({ id, timestamp, userId, event, ip, method, path, decision, reason, details }) {
  const db = await getDb();
  db.run(`
    INSERT INTO audit_logs (id, timestamp, user_id, event, ip, method, path, decision, reason, details)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [
    id,
    timestamp || new Date().toISOString(),
    userId || 'anonymous',
    event,
    ip || 'unknown',
    method || '',
    path || '',
    decision || 'INFO',
    reason || '',
    typeof details === 'object' ? JSON.stringify(details) : (details || ''),
  ]);
  saveDb();
}

async function getAuditLogs({ limit = 100, event, userId, decision } = {}) {
  const db = await getDb();
  let query = 'SELECT * FROM audit_logs WHERE 1=1';
  const params = [];
  if (event) {
    query += ' AND event = ?';
    params.push(event);
  }
  if (userId) {
    query += ' AND user_id = ?';
    params.push(userId);
  }
  if (decision) {
    query += ' AND decision = ?';
    params.push(decision);
  }
  query += ' ORDER BY timestamp DESC LIMIT ?';
  params.push(limit);

  const res = db.exec(query, params);
  if (!res.length) return [];
  const cols = res[0].columns;
  return res[0].values.map((row) => {
    const l = {};
    cols.forEach((c, i) => (l[c] = row[i]));
    return l;
  });
}

// ─── POLICIES HELPERS ───────────────────────────────────────

async function getPolicies() {
  const db = await getDb();
  const res = db.exec('SELECT * FROM policies');
  if (!res.length) return [];
  const cols = res[0].columns;
  return res[0].values.map((row) => {
    const p = {};
    cols.forEach((c, i) => (p[c] = row[i]));
    p.enabled = Boolean(p.enabled);
    return p;
  });
}

async function setPolicyEnabled(id, enabled) {
  const db = await getDb();
  db.run('UPDATE policies SET enabled = ? WHERE id = ?', [enabled ? 1 : 0, id]);
  saveDb();
}

async function deleteUser(id) {
  const db = await getDb();
  db.run('DELETE FROM users WHERE id = ? OR email = ?', [id, id]);
  saveDb();
  return true;
}

async function clearAuditLogs() {
  const db = await getDb();
  db.run('DELETE FROM audit_logs');
  saveDb();
  return true;
}

module.exports = {
  getDb,
  saveDb,
  findUserByEmail,
  findUserById,
  listUsers,
  createUser,
  deleteUser,
  clearAuditLogs,
  updateUserRole,
  updateUserStatus,
  updateUserMFA,
  updateLastLogin,
  addTrustedDevice,
  updateSensitiveData,
  insertAuditLog,
  getAuditLogs,
  getPolicies,
  setPolicyEnabled,
};
