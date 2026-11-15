/**
 * Automated Security Test Suite (Jest)
 * Tests Policy Engine, Token Logic, Real TOTP, and AES-256-GCM
 */
const request = require('supertest');
const speakeasy = require('speakeasy');
const app = require('../server');
const db = require('../src/db');
const cryptoUtil = require('../src/cryptoUtil');
const iam = require('../src/iam');

describe('Zero-Trust Architecture Enterprise Security Suite', () => {
  let editorToken = null;
  let adminToken = null;

  beforeAll(async () => {
    // Warm up database
    await db.getDb();
  });

  // ─── 1. IAM & Authentication Tests ─────────────────────────
  describe('IAM & Authentication', () => {
    it('authenticates valid editor and returns JWT pair', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ identifier: 'user@example.com', password: 'password123' });

      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeDefined();
      expect(res.body.refreshToken).toBeDefined();
      editorToken = res.body.accessToken;
    });

    it('rejects invalid password with 401', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ identifier: 'user@example.com', password: 'incorrect_password' });

      expect(res.status).toBe(401);
      expect(res.body.error).toMatch(/Invalid credentials/i);
    });

    it('demands step-up MFA challenge for enrolled admin identity', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ identifier: 'admin@enterprise.internal', password: 'AdminSecret123!' });

      expect(res.status).toBe(200);
      expect(res.body.mfaRequired).toBe(true);
      expect(res.body.userId).toBe('usr_admin_01');
    });

    it('allows admin login when valid TOTP is presented', async () => {
      // Generate real TOTP code using admin's seeded secret 'JBSWY3DPEHPK3PXP'
      const totp = speakeasy.totp({
        secret: 'JBSWY3DPEHPK3PXP',
        encoding: 'base32',
      });

      const res = await request(app)
        .post('/auth/login')
        .send({
          identifier: 'admin@enterprise.internal',
          password: 'AdminSecret123!',
          mfaToken: totp,
        });

      expect(res.status).toBe(200);
      expect(res.body.accessToken).toBeDefined();
      adminToken = res.body.accessToken;
    });
  });

  // ─── 2. Policy Engine Tests ─────────────────────────────────
  describe('Policy Engine & Least Privilege RBAC', () => {
    it('allows editor to access READ protected resource', async () => {
      const res = await request(app)
        .get('/api/data')
        .set('Authorization', `Bearer ${editorToken}`);

      expect(res.status).toBe(200);
      expect(res.body.authorizedRole).toBe('editor');
    });

    it('allows editor to access WRITE protected resource', async () => {
      const res = await request(app)
        .post('/api/data')
        .set('Authorization', `Bearer ${editorToken}`)
        .send({ record: 'Telemetry log' });

      expect(res.status).toBe(200);
      expect(res.body.status).toBe('success');
    });

    it('DENIES editor from executing DELETE (Least Privilege enforcement)', async () => {
      const res = await request(app)
        .delete('/api/data')
        .set('Authorization', `Bearer ${editorToken}`);

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/lacks required permission 'delete'/i);
    });

    it('enforces step-up MFA on administrative route', async () => {
      // Call admin without X-MFA-Token header
      const res = await request(app)
        .get('/admin')
        .set('Authorization', `Bearer ${adminToken}`);

      expect(res.status).toBe(401);
      expect(res.body.mfa_required).toBe(true);
    });

    it('allows administrative route when X-MFA-Token is valid', async () => {
      const totp = speakeasy.totp({
        secret: 'JBSWY3DPEHPK3PXP',
        encoding: 'base32',
      });

      const res = await request(app)
        .get('/admin')
        .set('Authorization', `Bearer ${adminToken}`)
        .set('X-MFA-Token', totp);

      expect(res.status).toBe(200);
      expect(res.body.message).toMatch(/Administrative control room granted/i);
    });

    it('DENIES access to dormant account inactive > 30 days', async () => {
      const res = await request(app)
        .post('/auth/login')
        .send({ identifier: 'dormant@enterprise.internal', password: 'password123' });

      expect(res.status).toBe(403);
      expect(res.body.error).toMatch(/(30 days of inactivity|Account is disabled)/i);
    });
  });

  // ─── 3. Token Rotation & Replay Protection ─────────────────
  describe('Single-Use Refresh Token Rotation', () => {
    it('revokes previous refresh token upon exchange and blocks replay', async () => {
      const loginRes = await request(app)
        .post('/auth/login')
        .send({ identifier: 'user@example.com', password: 'password123' });

      const oldRefresh = loginRes.body.refreshToken;

      // First refresh succeeds
      const refreshRes = await request(app)
        .post('/auth/refresh')
        .send({ refreshToken: oldRefresh });

      expect(refreshRes.status).toBe(200);
      expect(refreshRes.body.accessToken).toBeDefined();

      // Second reuse of old refresh token MUST fail
      const replayRes = await request(app)
        .post('/auth/refresh')
        .send({ refreshToken: oldRefresh });

      expect(replayRes.status).toBe(401);
      expect(replayRes.body.error).toMatch(/reuse detected/i);
    });
  });

  // ─── 4. Cryptographic AES-256-GCM Tests ─────────────────────
  describe('AES-256-GCM Data Protection', () => {
    it('encrypts and decrypts sensitive data with tamper resistance', () => {
      const sensitiveText = 'SUPER_SECRET_RECOVERY_KEY_9921';
      const envelope = cryptoUtil.encrypt(sensitiveText);

      expect(envelope).toMatch(/^enc:v1:aes-256-gcm:[0-9a-f]{24}:[0-9a-f]{32}:/);

      const decrypted = cryptoUtil.decrypt(envelope);
      expect(decrypted).toBe(sensitiveText);

      // Tampered envelope test (modify 1 character)
      const tampered = envelope.slice(0, -2) + 'aa';
      expect(() => cryptoUtil.decrypt(tampered)).toThrow();
    });
  });

  // ─── 5. IAM Management APIs ─────────────────────────────────
  describe('IAM Governance APIs', () => {
    it('returns role permissions matrix', async () => {
      const res = await request(app).get('/api/iam/matrix');
      expect(res.status).toBe(200);
      expect(res.body.matrix.admin).toContain('manage');
      expect(res.body.matrix.editor).not.toContain('manage');
    });

    it('creates a new identity in persistent store', async () => {
      const newEmail = `engineer_${Date.now()}@lab.corp`;
      const totp = speakeasy.totp({ secret: 'JBSWY3DPEHPK3PXP', encoding: 'base32' });

      const res = await request(app)
        .post('/api/users')
        .set('Authorization', `Bearer ${adminToken}`)
        .set('X-MFA-Token', totp)
        .send({
          email: newEmail,
          password: 'NewUserPass123!',
          role: 'auditor',
        });

      expect(res.status).toBe(201);
      expect(res.body.user.email).toBe(newEmail);
      expect(res.body.user.role).toBe('auditor');
    });
  });
});
