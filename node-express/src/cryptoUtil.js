/**
 * AES-256-GCM Authenticated Encryption Layer
 * Provides authenticated encryption for data-at-rest.
 */
const crypto = require('crypto');
const config = require('./config');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits standard for GCM
const AUTH_TAG_LENGTH = 16; // 128 bits standard

function getKey() {
  const rawKey = config.encryption.aesKey;
  // Ensure 32-byte Buffer
  return crypto.createHash('sha256').update(rawKey).digest();
}

/**
 * Encrypt plaintext using AES-256-GCM
 * @param {string} text
 * @returns {string} Serialized ciphertext envelope
 */
function encrypt(text) {
  if (!text) return null;
  const key = getKey();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });

  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag();

  return `enc:v1:aes-256-gcm:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
}

/**
 * Decrypt and verify AES-256-GCM ciphertext envelope
 * @param {string} envelope
 * @returns {string} Plaintext
 */
function decrypt(envelope) {
  if (!envelope) return null;
  const parts = envelope.split(':');
  if (parts.length !== 6 || parts[0] !== 'enc' || parts[2] !== 'aes-256-gcm') {
    throw new Error('Invalid ciphertext envelope format');
  }

  const iv = Buffer.from(parts[3], 'hex');
  const authTag = Buffer.from(parts[4], 'hex');
  const ciphertext = parts[5];

  const key = getKey();
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(ciphertext, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

module.exports = {
  encrypt,
  decrypt,
};
