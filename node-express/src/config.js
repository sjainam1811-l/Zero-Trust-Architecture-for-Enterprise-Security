/**
 * Configuration & Security Secret Validator
 * Enforces fail-fast validation for secrets.
 */
const path = require('path');
require('dotenv').config({ path: path.join(__dirname, '..', '..', '.env') });
require('dotenv').config(); // Local fallback

const accessSecret = process.env.JWT_ACCESS_SECRET;
const refreshSecret = process.env.JWT_REFRESH_SECRET;

// Fail fast check if secrets are missing or placeholder
if (!accessSecret || accessSecret.includes('CHANGE_ME') || accessSecret.length < 32) {
  // If in automated dev without .env, initialize secure cryptographically random secrets
  if (process.env.NODE_ENV !== 'production' && !accessSecret) {
    console.warn('[SECURITY WARNING] JWT_ACCESS_SECRET not provided. Generating 256-bit random secret for local session.');
    process.env.JWT_ACCESS_SECRET = require('crypto').randomBytes(32).toString('hex');
  } else {
    throw new Error('FATAL SECURITY ERROR: JWT_ACCESS_SECRET must be set and contain at least 32 characters!');
  }
}

if (!refreshSecret || refreshSecret.includes('CHANGE_ME') || refreshSecret.length < 32) {
  if (process.env.NODE_ENV !== 'production' && !refreshSecret) {
    console.warn('[SECURITY WARNING] JWT_REFRESH_SECRET not provided. Generating 256-bit random secret for local session.');
    process.env.JWT_REFRESH_SECRET = require('crypto').randomBytes(32).toString('hex');
  } else {
    throw new Error('FATAL SECURITY ERROR: JWT_REFRESH_SECRET must be set and contain at least 32 characters!');
  }
}

const CONFIG = {
  jwt: {
    accessSecret: process.env.JWT_ACCESS_SECRET,
    refreshSecret: process.env.JWT_REFRESH_SECRET,
    accessExpiry: process.env.JWT_ACCESS_EXPIRY || '15m',
    refreshExpiry: process.env.JWT_REFRESH_EXPIRY || '7d',
    issuer: 'zero-trust-lab',
    audience: 'zero-trust-users',
  },
  redis: {
    url: process.env.REDIS_URL || 'redis://localhost:6379',
  },
  security: {
    maxLoginAttempts: 5,
    lockoutDurationSeconds: 900, // 15 mins
    saltRounds: 12,
  },
  encryption: {
    aesKey: process.env.DB_ENCRYPTION_KEY || '0123456789abcdef0123456789abcdef', // 32 bytes for AES-256
  },
};

module.exports = CONFIG;
