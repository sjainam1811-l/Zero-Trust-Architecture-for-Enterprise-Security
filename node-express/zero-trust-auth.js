/**
 * @file        zero-trust-auth.js
 * @description Zero-Trust Authentication Middleware for Node.js / Express
 * @author      Kelvin Chipili <KelvinChipili>
 * @license     MIT
 *
 * ─────────────────────────────────────────────────────────────
 *  ZERO-TRUST PHILOSOPHY
 *  "Never trust, always verify."
 *
 *  Traditional security assumes everything inside a network is safe.
 *  Zero-trust assumes breach by default — every request must prove
 *  its identity, regardless of where it comes from.
 * ─────────────────────────────────────────────────────────────
 *
 *  WHAT THIS FILE PROVIDES
 *  ───────────────────────
 *  • JWT access tokens  (short-lived, 15 min)
 *  • JWT refresh tokens (longer-lived, 7 days, one-time-use rotation)
 *  • Per-request identity verification middleware
 *  • Device fingerprinting (detects session hijacking attempts)
 *  • Brute-force protection with IP + user lockout
 *  • Rate limiting (global and auth-specific)
 *  • Role-Based Access Control (RBAC)
 *  • TOTP / MFA verification hook
 *  • Token revocation via JTI blacklist
 *  • Structured audit logging for every auth event
 *
 *  HOW TO USE
 *  ──────────
 *  1. npm install express jsonwebtoken bcryptjs express-rate-limit
 *                speakeasy uuid winston
 *  2. Copy this file into your project
 *  3. Set environment variables (see ZT_CONFIG below)
 *  4. Replace mockFindUser() with your real database query
 *  5. Wire the exported handlers into your Express routes
 *
 *  EDIT GUIDE
 *  ──────────
 *  Search for "// EDIT:" comments — these are the only lines
 *  you need to change to plug this into your application.
 */

'use strict';

// ─── DEPENDENCIES ────────────────────────────────────────────
// jwt      — signs and verifies JSON Web Tokens
// bcrypt   — securely hashes and compares passwords
// rateLimit— limits how many requests an IP can make per window
// speakeasy— generates and verifies TOTP codes (Google Authenticator)
// uuidv4   — generates unique IDs for each token (JTI claim)
// winston  — structured logging to console / file / remote
const jwt        = require('jsonwebtoken');
const bcrypt     = require('bcryptjs');
const rateLimit  = require('express-rate-limit');
const speakeasy  = require('speakeasy');
const { v4: uuidv4 } = require('uuid');
const winston    = require('winston');

// ─── CONFIGURATION ───────────────────────────────────────────
// All sensitive values should come from environment variables.
// Never hard-code secrets in source code that gets committed.
const ZT_CONFIG = {

  jwt: {
    // EDIT: Set these in your .env file — must be 32+ random characters
    accessSecret:  process.env.JWT_ACCESS_SECRET  || 'CHANGE_ME_ACCESS_SECRET_MIN_32_CHARS',
    refreshSecret: process.env.JWT_REFRESH_SECRET || 'CHANGE_ME_REFRESH_SECRET_MIN_32_CHARS',

    // Access tokens expire quickly to limit damage if one is stolen
    accessExpiry:  '15m',

    // Refresh tokens live longer but are rotated on every use
    refreshExpiry: '7d',

    // HS256 is fine for single-server apps. Use RS256 (asymmetric)
    // if multiple services need to verify tokens independently.
    algorithm: 'HS256', // EDIT: 'RS256' for asymmetric keys in production

    // EDIT: Replace with your app's name and user group identifier
    issuer:   'your-app-name',
    audience: 'your-app-users',
  },

  security: {
    maxLoginAttempts:  5,              // lockout after this many failures
    lockoutDurationMs: 15 * 60 * 1000, // 15-minute lockout window
    saltRounds:        12,             // bcrypt cost factor (higher = slower = safer)
    requireMFA:        false,          // EDIT: set true to enforce TOTP for all users

    // EDIT: Add your frontend origin(s)
    allowedOrigins: ['http://localhost:3000'],
  },

  rateLimit: {
    windowMs:  15 * 60 * 1000, // 15-minute rolling window
    maxGlobal: 100,             // max requests per IP per window (all routes)
    maxAuth:   10,              // max requests per IP per window (auth routes only)
  },
};

// ─── AUDIT LOGGER ────────────────────────────────────────────
// Every authentication event is logged with a timestamp, user ID,
// and relevant metadata. In production, ship these logs to a
// centralised service (Datadog, CloudWatch, Splunk, etc.).
//
// EDIT: Add a file or remote transport for production use:
//   new winston.transports.File({ filename: 'auth-audit.log' })
const auditLogger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()        // structured JSON — easy to query
  ),
  defaultMeta: { service: 'zero-trust-auth' },
  transports: [
    new winston.transports.Console(),
    // EDIT: Add additional transports here for production
  ],
});

/**
 * Writes a structured audit log entry.
 * @param {string} event    - Event identifier (e.g. 'LOGIN_SUCCESS')
 * @param {string} userId   - The user involved (or null for anonymous)
 * @param {object} metadata - Extra context (IP, path, device, etc.)
 */
function auditLog(event, userId, metadata = {}) {
  auditLogger.info({
    event,
    userId:    userId || 'anonymous',
    timestamp: new Date().toISOString(),
    ...metadata,
  });
}

// ─── IN-MEMORY STORES ────────────────────────────────────────
// These work for single-server development and testing.
// In production with multiple servers, replace with Redis so all
// instances share the same state.
//
// EDIT: Replace each store with a Redis client call in production.
const tokenBlacklist    = new Set();  // JTIs of revoked tokens
const refreshTokenStore = new Map();  // userId → Set of active refresh JTIs
const loginAttempts     = new Map();  // "ip:userId" → { count, lastAttempt }
const deviceRegistry    = new Map();  // userId → Set of trusted fingerprints

// ─── TOKEN GENERATION ────────────────────────────────────────

/**
 * Creates a short-lived access token.
 * The JTI (JWT ID) makes each token unique so it can be revoked individually.
 * @param {object} payload - Claims to embed (userId, role, fingerprint, etc.)
 * @returns {string} Signed JWT access token
 */
function generateAccessToken(payload) {
  const jti = uuidv4(); // unique token ID — used for revocation
  return jwt.sign(
    { ...payload, jti, type: 'access' },
    ZT_CONFIG.jwt.accessSecret,
    {
      expiresIn: ZT_CONFIG.jwt.accessExpiry,
      algorithm: ZT_CONFIG.jwt.algorithm,
      issuer:    ZT_CONFIG.jwt.issuer,
      audience:  ZT_CONFIG.jwt.audience,
    }
  );
}

/**
 * Creates a longer-lived refresh token and tracks its JTI.
 * Tracking the JTI lets us detect and reject replay attacks.
 * @param {object} payload - Same payload as the access token
 * @returns {string} Signed JWT refresh token
 */
function generateRefreshToken(payload) {
  const jti   = uuidv4();
  const token = jwt.sign(
    { ...payload, jti, type: 'refresh' },
    ZT_CONFIG.jwt.refreshSecret,
    {
      expiresIn: ZT_CONFIG.jwt.refreshExpiry,
      algorithm: ZT_CONFIG.jwt.algorithm,
      issuer:    ZT_CONFIG.jwt.issuer,
      audience:  ZT_CONFIG.jwt.audience,
    }
  );

  // Register this JTI so we can validate it on refresh requests
  if (!refreshTokenStore.has(payload.userId)) {
    refreshTokenStore.set(payload.userId, new Set());
  }
  refreshTokenStore.get(payload.userId).add(jti);

  return token;
}

// ─── TOKEN VERIFICATION ──────────────────────────────────────

/**
 * Verifies an access token's signature, expiry, issuer, and audience.
 * Also checks the JTI blacklist to catch revoked tokens.
 * @param {string} token - Raw JWT string from the Authorization header
 * @returns {object} Decoded payload
 * @throws If the token is invalid, expired, or revoked
 */
function verifyAccessToken(token) {
  const decoded = jwt.verify(token, ZT_CONFIG.jwt.accessSecret, {
    algorithms: [ZT_CONFIG.jwt.algorithm],
    issuer:     ZT_CONFIG.jwt.issuer,
    audience:   ZT_CONFIG.jwt.audience,
  });

  // Reject tokens that have been explicitly revoked (e.g. on logout)
  if (tokenBlacklist.has(decoded.jti)) {
    throw new Error('Token has been revoked');
  }

  // Ensure this is actually an access token, not a refresh token
  if (decoded.type !== 'access') {
    throw new Error('Invalid token type — expected access token');
  }

  return decoded;
}

/**
 * Verifies a refresh token and confirms its JTI is still active.
 * If the JTI isn't in our store, the token may have been stolen and reused.
 * @param {string} token - Raw JWT refresh token string
 * @returns {object} Decoded payload
 * @throws If invalid, expired, already used, or not recognised
 */
function verifyRefreshToken(token) {
  const decoded = jwt.verify(token, ZT_CONFIG.jwt.refreshSecret, {
    algorithms: [ZT_CONFIG.jwt.algorithm],
    issuer:     ZT_CONFIG.jwt.issuer,
    audience:   ZT_CONFIG.jwt.audience,
  });

  if (decoded.type !== 'refresh') {
    throw new Error('Invalid token type — expected refresh token');
  }

  // If the JTI isn't in our active set, this token was already used
  // or was never issued by us — possible replay attack
  const userTokens = refreshTokenStore.get(decoded.userId);
  if (!userTokens || !userTokens.has(decoded.jti)) {
    throw new Error('Refresh token not recognised — possible replay attack');
  }

  return decoded;
}

// ─── TOKEN REVOCATION ────────────────────────────────────────

/**
 * Revokes a single token by adding its JTI to the blacklist.
 * Also removes it from the refresh token store if applicable.
 * @param {string} jti    - The JWT ID to revoke
 * @param {string} userId - The owning user's ID (optional)
 */
function revokeToken(jti, userId) {
  tokenBlacklist.add(jti);
  if (userId && refreshTokenStore.has(userId)) {
    refreshTokenStore.get(userId).delete(jti);
  }
}

/**
 * Revokes ALL active sessions for a user.
 * Use this when a password is changed, account is compromised, etc.
 * @param {string} userId - The user whose sessions should all end
 */
function revokeAllUserTokens(userId) {
  refreshTokenStore.delete(userId);
  // EDIT: In production with Redis, mark all JTIs for this user as revoked
  auditLog('TOKENS_REVOKED_ALL', userId);
}

// ─── DEVICE FINGERPRINTING ───────────────────────────────────
// A fingerprint is derived from request headers that rarely change
// between requests from the same browser. If a token is stolen and
// used from a different device, the fingerprint won't match.
//
// EDIT: Add more signals (TLS fingerprint, IP subnet, etc.) for
// higher-security applications.

/**
 * Derives a device fingerprint from incoming request headers.
 * @param {object} req - Express request object
 * @returns {string} Base64-encoded fingerprint string
 */
function extractFingerprint(req) {
  const ua       = req.headers['user-agent']      || '';
  const lang     = req.headers['accept-language'] || '';
  const encoding = req.headers['accept-encoding'] || '';
  return Buffer.from(`${ua}:${lang}:${encoding}`).toString('base64');
}

/**
 * Checks whether a fingerprint is in the user's trusted device list.
 * @param {string} userId      - The user's ID
 * @param {string} fingerprint - The computed fingerprint
 * @returns {boolean}
 */
function isTrustedDevice(userId, fingerprint) {
  const devices = deviceRegistry.get(userId);
  return devices ? devices.has(fingerprint) : false;
}

/**
 * Adds a device fingerprint to a user's trusted device list.
 * Call this when the user explicitly chooses to "trust this device".
 * @param {string} userId      - The user's ID
 * @param {string} fingerprint - The fingerprint to trust
 */
function trustDevice(userId, fingerprint) {
  if (!deviceRegistry.has(userId)) {
    deviceRegistry.set(userId, new Set());
  }
  deviceRegistry.get(userId).add(fingerprint);
}

// ─── BRUTE-FORCE PROTECTION ──────────────────────────────────

/**
 * Throws an error if the user/IP combo has exceeded the login attempt limit.
 * The key combines IP and identifier so:
 *  - One IP can't hammer multiple accounts
 *  - One account can't be hammered from distributed IPs (use a DB for that)
 * @param {string} ip         - Client IP address
 * @param {string} identifier - Username or email being attempted
 * @throws 429 error if account is locked
 */
function checkLoginAttempts(ip, identifier) {
  const key  = `${ip}:${identifier}`;
  const data = loginAttempts.get(key) || { count: 0, lastAttempt: 0 };
  const now  = Date.now();

  if (data.count >= ZT_CONFIG.security.maxLoginAttempts) {
    const elapsed   = now - data.lastAttempt;
    const remaining = ZT_CONFIG.security.lockoutDurationMs - elapsed;

    if (remaining > 0) {
      // Still within lockout window — reject immediately
      const seconds = Math.ceil(remaining / 1000);
      throw Object.assign(
        new Error(`Account locked. Try again in ${seconds}s`),
        { status: 429 }
      );
    }

    // Lockout period has passed — reset the counter
    loginAttempts.delete(key);
  }
}

/**
 * Records a failed login attempt for rate-limiting purposes.
 * @param {string} ip         - Client IP address
 * @param {string} identifier - Username or email that failed
 */
function recordFailedAttempt(ip, identifier) {
  const key  = `${ip}:${identifier}`;
  const data = loginAttempts.get(key) || { count: 0, lastAttempt: 0 };
  data.count++;
  data.lastAttempt = Date.now();
  loginAttempts.set(key, data);
  auditLog('LOGIN_FAILED', identifier, { ip, attempts: data.count });
}

/**
 * Clears the failed attempt counter after a successful login.
 * @param {string} ip         - Client IP address
 * @param {string} identifier - Username or email that succeeded
 */
function clearLoginAttempts(ip, identifier) {
  loginAttempts.delete(`${ip}:${identifier}`);
}

// ─── RATE LIMITERS ───────────────────────────────────────────

/**
 * Global rate limiter — apply to all routes via app.use().
 * Prevents any single IP from flooding your server.
 */
const globalRateLimiter = rateLimit({
  windowMs:        ZT_CONFIG.rateLimit.windowMs,
  max:             ZT_CONFIG.rateLimit.maxGlobal,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: 'Too many requests. Please slow down.' },
});

/**
 * Stricter rate limiter for auth endpoints.
 * Apply directly to /auth/login and /auth/refresh routes.
 */
const authRateLimiter = rateLimit({
  windowMs:        ZT_CONFIG.rateLimit.windowMs,
  max:             ZT_CONFIG.rateLimit.maxAuth,
  standardHeaders: true,
  legacyHeaders:   false,
  message:         { error: 'Too many authentication attempts.' },
  keyGenerator:    (req) => `${req.ip}:auth`,
});

// ─── CORE MIDDLEWARE ─────────────────────────────────────────

/**
 * authenticate — Core Zero-Trust middleware.
 *
 * Attach this to any route that requires a logged-in user.
 * It verifies the token on EVERY request — no session cache,
 * no implicit trust from a previous successful request.
 *
 * On success: attaches req.user (decoded token payload)
 * On failure: returns 401 with an error message
 *
 * @example
 *   app.get('/api/profile', authenticate, (req, res) => {
 *     res.json({ user: req.user });
 *   });
 */
function authenticate(req, res, next) {
  try {
    // 1. Extract the token from the Authorization header
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Missing or malformed Authorization header' });
    }

    // 2. Verify signature, expiry, issuer, audience, and blacklist
    const token   = authHeader.split(' ')[1];
    const decoded = verifyAccessToken(token);

    // 3. Zero-Trust device check — reject if fingerprint has changed
    //    This catches token theft: a stolen token used from a different device
    const fingerprint = extractFingerprint(req);
    if (decoded.fingerprint && decoded.fingerprint !== fingerprint) {
      auditLog('FINGERPRINT_MISMATCH', decoded.userId, {
        ip: req.ip,
        path: req.path,
      });
      return res.status(401).json({ error: 'Device fingerprint mismatch — re-authenticate' });
    }

    // 4. Attach verified identity to the request for downstream use
    req.user        = decoded;
    req.fingerprint = fingerprint;

    auditLog('REQUEST_AUTHENTICATED', decoded.userId, {
      path:   req.path,
      method: req.method,
      ip:     req.ip,
    });

    next();

  } catch (err) {
    auditLog('AUTH_FAILED', null, { error: err.message, ip: req.ip, path: req.path });
    return res.status(401).json({ error: 'Authentication failed', detail: err.message });
  }
}

// ─── ROLE-BASED ACCESS CONTROL ───────────────────────────────
// EDIT: Modify this map to reflect your application's roles.
// Each role maps to an array of permission strings.
// You can name permissions anything — 'read', 'publish', 'admin:users', etc.
const ROLE_PERMISSIONS = {
  admin:  ['read', 'write', 'delete', 'manage'], // EDIT: full access
  editor: ['read', 'write'],                      // EDIT: content creators
  viewer: ['read'],                               // EDIT: read-only users
};

/**
 * authorize — RBAC middleware factory.
 *
 * Creates a middleware that checks whether the authenticated user
 * has all of the specified permissions. Must come after authenticate().
 *
 * @param {...string} requiredPermissions - Permission strings to check
 * @returns {function} Express middleware
 *
 * @example
 *   // Only admins can delete:
 *   app.delete('/api/posts/:id', authenticate, authorize('delete'), handler);
 *
 *   // Both admins and editors can write:
 *   app.post('/api/posts', authenticate, authorize('write'), handler);
 */
function authorize(...requiredPermissions) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const userRole  = req.user.role;
    const userPerms = ROLE_PERMISSIONS[userRole] || [];

    // Check that the user has EVERY required permission
    const hasAll = requiredPermissions.every(p => userPerms.includes(p));

    if (!hasAll) {
      auditLog('AUTHORIZATION_DENIED', req.user.userId, {
        role:     userRole,
        required: requiredPermissions,
        path:     req.path,
        method:   req.method,
      });
      return res.status(403).json({
        error: 'Insufficient permissions',
        required: requiredPermissions,
        yourRole: userRole,
      });
    }

    next();
  };
}

// ─── MFA MIDDLEWARE ──────────────────────────────────────────

/**
 * requireMFA — Enforces TOTP verification on specific routes.
 *
 * Reads the OTP code from the X-MFA-Token header or req.body.mfaToken.
 * The user's TOTP secret must be stored in their account record and
 * embedded in req.user (added during login).
 *
 * Only active when ZT_CONFIG.security.requireMFA is true.
 *
 * EDIT: Fetch the TOTP secret from your database if not embedded in the token.
 *
 * @example
 *   app.get('/admin', authenticate, requireMFA, authorize('manage'), adminHandler);
 */
function requireMFA(req, res, next) {
  // Skip if MFA is not globally required
  if (!ZT_CONFIG.security.requireMFA) return next();

  const totpToken = req.headers['x-mfa-token'] || req.body?.mfaToken;
  if (!totpToken) {
    return res.status(401).json({ error: 'MFA token required (X-MFA-Token header)' });
  }

  // EDIT: Retrieve the user's TOTP secret from your database
  // e.g. const { totpSecret } = await db.users.findById(req.user.userId);
  const totpSecret = req.user?.totpSecret || '';

  const valid = speakeasy.totp.verify({
    secret:   totpSecret,
    encoding: 'base32',
    token:    totpToken,
    window:   1, // allow 1 time-step tolerance for clock skew
  });

  if (!valid) {
    auditLog('MFA_FAILED', req.user?.userId, { ip: req.ip });
    return res.status(401).json({ error: 'Invalid MFA token' });
  }

  auditLog('MFA_PASSED', req.user?.userId);
  next();
}

// ─── ROUTE HANDLERS ──────────────────────────────────────────
// Wire these into your Express router. See usage example at the bottom.

/**
 * loginHandler — Authenticates a user and issues token pair.
 *
 * POST /auth/login
 * Body: { identifier: string, password: string, mfaToken?: string }
 *
 * EDIT: Replace mockFindUser() with your actual database query.
 */
async function loginHandler(req, res) {
  const { identifier, password } = req.body;
  const mfaToken = req.body?.mfaToken || req.body?.mfa_token;
  const ip = req.ip;

  // Validate that required fields are present
  if (!identifier || !password) {
    return res.status(400).json({ error: 'identifier and password are required' });
  }

  try {
    // 1. Check if this IP/user combo is currently locked out
    checkLoginAttempts(ip, identifier);

    // 2. Look up the user — EDIT: replace with your DB query
    const user = await mockFindUser(identifier);

    // 3. Verify password — use constant-time comparison (bcrypt does this)
    const passwordValid = user && await bcrypt.compare(password, user.passwordHash);
    if (!user || !passwordValid) {
      // Always record the failure and return the same error message
      // (don't reveal whether the user exists or just the password is wrong)
      recordFailedAttempt(ip, identifier);
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // 4. MFA check — if the user has MFA enabled, verify the TOTP code
    if (user.mfaEnabled) {
      if (!mfaToken) {
        // Client needs to re-submit with a TOTP code
        return res.status(200).json({ mfaRequired: true });
      }
      const mfaValid = speakeasy.totp.verify({
        secret:   user.totpSecret,
        encoding: 'base32',
        token:    mfaToken,
        window:   1,
      });
      if (!mfaValid) {
        recordFailedAttempt(ip, identifier);
        return res.status(401).json({ error: 'Invalid MFA token' });
      }
    }

    // 5. Compute device fingerprint and check if it's a known device
    const fingerprint  = extractFingerprint(req);
    const knownDevice  = isTrustedDevice(user.id, fingerprint);

    // 6. Build the token payload
    // EDIT: Add any extra claims your application needs
    const payload = {
      userId:      user.id,
      role:        user.role,
      fingerprint, // embedded so we can detect device changes
    };

    // 7. Issue token pair
    const accessToken  = generateAccessToken(payload);
    const refreshToken = generateRefreshToken(payload);

    // 8. Clear any previous failed attempt counter
    clearLoginAttempts(ip, identifier);
    auditLog('LOGIN_SUCCESS', user.id, { ip, knownDevice });

    return res.status(200).json({
      accessToken,
      refreshToken,
      expiresIn:  ZT_CONFIG.jwt.accessExpiry,
      newDevice:  !knownDevice, // hint to the client to offer "trust this device"
    });

  } catch (err) {
    if (err.status === 429) return res.status(429).json({ error: err.message });
    auditLog('LOGIN_ERROR', identifier, { error: err.message, ip });
    return res.status(500).json({ error: 'Internal authentication error' });
  }
}

/**
 * refreshHandler — Rotates tokens using a valid refresh token.
 *
 * POST /auth/refresh
 * Body: { refreshToken: string }
 *
 * Rotation means the old refresh token is revoked immediately on use.
 * If an attacker gets a refresh token and tries to use it after the
 * legitimate user already has, the server will detect the reuse.
 */
async function refreshHandler(req, res) {
  const refreshToken = req.body?.refreshToken || req.body?.refresh_token;

  if (!refreshToken) {
    return res.status(400).json({ error: 'refreshToken is required' });
  }

  try {
    // 1. Verify the refresh token's signature and check it's still active
    const decoded = verifyRefreshToken(refreshToken);

    // 2. Immediately revoke the old refresh token (rotation)
    //    Now it can never be reused — replay attacks are blocked
    revokeToken(decoded.jti, decoded.userId);

    // 3. Issue a fresh token pair with the current device fingerprint
    const fingerprint = extractFingerprint(req);
    const payload = {
      userId:      decoded.userId,
      role:        decoded.role,
      fingerprint,
    };

    auditLog('TOKEN_REFRESHED', decoded.userId, { ip: req.ip });

    return res.status(200).json({
      accessToken:  generateAccessToken(payload),
      refreshToken: generateRefreshToken(payload),
      expiresIn:    ZT_CONFIG.jwt.accessExpiry,
    });

  } catch (err) {
    auditLog('TOKEN_REFRESH_FAILED', null, { error: err.message, ip: req.ip });
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
}

/**
 * logoutHandler — Revokes the current session's tokens.
 *
 * POST /auth/logout
 * Requires: Bearer access token in Authorization header
 * Body (optional): { refreshToken: string }
 */
function logoutHandler(req, res) {
  try {
    // Revoke the access token
    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.split(' ')[1];
    if (token) {
      const decoded = jwt.decode(token); // decode without verify (we're revoking it)
      if (decoded?.jti) revokeToken(decoded.jti, decoded.userId);
    }

    // Also revoke the refresh token if provided
    const refreshToken = req.body?.refreshToken || req.body?.refresh_token;
    if (refreshToken) {
      const decoded = jwt.decode(refreshToken);
      if (decoded?.jti) revokeToken(decoded.jti, decoded.userId);
    }

    auditLog('LOGOUT', req.user?.userId, { ip: req.ip });
    return res.status(200).json({ message: 'Logged out successfully' });

  } catch {
    // Even if something goes wrong, respond with success
    // The client should discard tokens regardless
    return res.status(200).json({ message: 'Logged out' });
  }
}

/**
 * trustDeviceHandler — Marks the current device as trusted for this user.
 *
 * POST /auth/trust-device
 * Requires: authenticate middleware
 */
function trustDeviceHandler(req, res) {
  const { userId, fingerprint } = req.user;
  trustDevice(userId, fingerprint);
  auditLog('DEVICE_TRUSTED', userId, { fingerprint, ip: req.ip });
  return res.status(200).json({ message: 'Device trusted for future logins' });
}

/**
 * logoutAllHandler — Terminates all active sessions for the current user.
 *
 * POST /auth/logout-all
 * Requires: authenticate middleware
 * Use this for: password change, account recovery, suspected compromise
 */
function logoutAllHandler(req, res) {
  revokeAllUserTokens(req.user.userId);
  return res.status(200).json({ message: 'All sessions terminated' });
}

// ─── MOCK USER DATABASE ──────────────────────────────────────
// EDIT: Delete this function and replace every call to mockFindUser()
//       with your actual database query. Example with Mongoose:
//
//   const user = await User.findOne({ email: identifier }).select('+passwordHash');
//
//   Or with Prisma:
//   const user = await prisma.user.findUnique({ where: { email: identifier } });
async function mockFindUser(identifier) {
  if (identifier !== 'user@example.com') return null;
  return {
    id:           'user-001',
    email:        'user@example.com',
    passwordHash: await bcrypt.hash('password123', ZT_CONFIG.security.saltRounds),
    role:         'editor',       // EDIT: comes from your DB
    mfaEnabled:   false,          // EDIT: comes from your DB
    totpSecret:   '',             // EDIT: comes from your DB (store encrypted)
  };
}

// ─── EXPORTS ─────────────────────────────────────────────────
module.exports = {
  // Middleware — attach to routes
  authenticate,
  authorize,
  requireMFA,
  globalRateLimiter,
  authRateLimiter,

  // Route handlers — register with your Express router
  loginHandler,
  refreshHandler,
  logoutHandler,
  trustDeviceHandler,
  logoutAllHandler,

  // Utilities — useful for testing and extending
  generateAccessToken,
  generateRefreshToken,
  revokeToken,
  revokeAllUserTokens,
  extractFingerprint,
  isTrustedDevice,
  trustDevice,
  auditLog,

  // Expose config for external customisation
  ZT_CONFIG,
  ROLE_PERMISSIONS,
};

// ─── USAGE EXAMPLE ───────────────────────────────────────────
/*
  // app.js — wire everything together

  const express = require('express');
  const {
    authenticate, authorize, requireMFA,
    globalRateLimiter, authRateLimiter,
    loginHandler, refreshHandler,
    logoutHandler, trustDeviceHandler, logoutAllHandler,
  } = require('./zero-trust-auth');

  const app = express();
  app.use(express.json());
  app.use(globalRateLimiter);          // apply to all routes

  // ── Public auth routes ─────────────────────
  app.post('/auth/login',        authRateLimiter, loginHandler);
  app.post('/auth/refresh',      authRateLimiter, refreshHandler);

  // ── Protected auth routes ──────────────────
  app.post('/auth/logout',       authenticate, logoutHandler);
  app.post('/auth/logout-all',   authenticate, logoutAllHandler);
  app.post('/auth/trust-device', authenticate, trustDeviceHandler);

  // ── Protected API routes ───────────────────
  app.get('/api/data',     authenticate, authorize('read'),            yourHandler);
  app.post('/api/data',    authenticate, authorize('write'),           yourHandler);
  app.delete('/api/data',  authenticate, authorize('delete'),          yourHandler);
  app.get('/admin',        authenticate, requireMFA, authorize('manage'), adminHandler);

  app.listen(4000);
*/
