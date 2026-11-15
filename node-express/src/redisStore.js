/**
 * Persistent Security State Layer (Redis with graceful In-Memory Fallback)
 * Manages:
 * - JTI Token Blacklist
 * - Single-use Refresh Token registry
 * - IP + User brute-force lockout counters
 */
const Redis = require('ioredis');
const config = require('./config');

let redisClient = null;
let isRedisConnected = false;

// Fallback in-memory structures if Redis is offline
const memoryBlacklist = new Map(); // jti -> expiresAt
const memoryRefreshStore = new Map(); // userId -> Set of JTIs
const memoryAttempts = new Map(); // key -> { count, expiresAt }

try {
  redisClient = new Redis(config.redis.url, {
    maxRetriesPerRequest: 1,
    retryStrategy: (times) => {
      if (times > 3) return null; // Don't spam retries if Redis isn't running
      return Math.min(times * 100, 1000);
    },
    lazyConnect: true,
  });

  redisClient.connect().then(() => {
    isRedisConnected = true;
    console.log('[REDIS] Connected to security state store at', config.redis.url);
  }).catch(() => {
    isRedisConnected = false;
    console.log('[REDIS] Redis unreachable, using localized persistence fallback');
  });

  redisClient.on('error', () => {
    isRedisConnected = false;
  });
} catch {
  isRedisConnected = false;
}

// ─── 1. JTI TOKEN BLACKLIST ──────────────────────────────────

async function blacklistToken(jti, expirySeconds = 900) {
  if (isRedisConnected && redisClient) {
    try {
      await redisClient.set(`zt:blacklist:${jti}`, '1', 'EX', expirySeconds);
      return;
    } catch {
      // Fallback
    }
  }
  memoryBlacklist.set(jti, Date.now() + expirySeconds * 1000);
}

async function isTokenBlacklisted(jti) {
  if (isRedisConnected && redisClient) {
    try {
      const exists = await redisClient.exists(`zt:blacklist:${jti}`);
      return exists === 1;
    } catch {
      // Fallback
    }
  }
  const exp = memoryBlacklist.get(jti);
  if (!exp) return false;
  if (Date.now() > exp) {
    memoryBlacklist.delete(jti);
    return false;
  }
  return true;
}

// ─── 2. REFRESH TOKEN REGISTRY (Single-Use Rotation) ─────────

async function registerRefreshToken(userId, jti, expirySeconds = 7 * 24 * 3600) {
  if (isRedisConnected && redisClient) {
    try {
      await redisClient.sadd(`zt:refresh:${userId}`, jti);
      await redisClient.expire(`zt:refresh:${userId}`, expirySeconds);
      return;
    } catch {
      // Fallback
    }
  }
  if (!memoryRefreshStore.has(userId)) {
    memoryRefreshStore.set(userId, new Set());
  }
  memoryRefreshStore.get(userId).add(jti);
}

async function isValidRefreshToken(userId, jti) {
  if (isRedisConnected && redisClient) {
    try {
      const isMember = await redisClient.sismember(`zt:refresh:${userId}`, jti);
      return isMember === 1;
    } catch {
      // Fallback
    }
  }
  const userSet = memoryRefreshStore.get(userId);
  return userSet ? userSet.has(jti) : false;
}

async function revokeRefreshToken(userId, jti) {
  await blacklistToken(jti, 7 * 24 * 3600);
  if (isRedisConnected && redisClient) {
    try {
      await redisClient.srem(`zt:refresh:${userId}`, jti);
      return;
    } catch {
      // Fallback
    }
  }
  const userSet = memoryRefreshStore.get(userId);
  if (userSet) {
    userSet.delete(jti);
  }
}

async function revokeAllUserTokens(userId) {
  if (isRedisConnected && redisClient) {
    try {
      await redisClient.del(`zt:refresh:${userId}`);
      return;
    } catch {
      // Fallback
    }
  }
  memoryRefreshStore.delete(userId);
}

// ─── 3. LOGIN ATTEMPTS / LOCKOUT ─────────────────────────────

async function recordFailedAttempt(key, lockoutWindowSeconds = 900) {
  if (isRedisConnected && redisClient) {
    try {
      const count = await redisClient.incr(`zt:attempts:${key}`);
      if (count === 1) {
        await redisClient.expire(`zt:attempts:${key}`, lockoutWindowSeconds);
      }
      return count;
    } catch {
      // Fallback
    }
  }
  const now = Date.now();
  const entry = memoryAttempts.get(key);
  if (!entry || now > entry.expiresAt) {
    memoryAttempts.set(key, { count: 1, expiresAt: now + lockoutWindowSeconds * 1000 });
    return 1;
  }
  entry.count += 1;
  return entry.count;
}

async function getFailedAttempts(key) {
  if (isRedisConnected && redisClient) {
    try {
      const count = await redisClient.get(`zt:attempts:${key}`);
      return count ? parseInt(count, 10) : 0;
    } catch {
      // Fallback
    }
  }
  const now = Date.now();
  const entry = memoryAttempts.get(key);
  if (!entry || now > entry.expiresAt) {
    return 0;
  }
  return entry.count;
}

async function clearFailedAttempts(key) {
  if (isRedisConnected && redisClient) {
    try {
      await redisClient.del(`zt:attempts:${key}`);
      return;
    } catch {
      // Fallback
    }
  }
  memoryAttempts.delete(key);
}

module.exports = {
  blacklistToken,
  isTokenBlacklisted,
  registerRefreshToken,
  isValidRefreshToken,
  revokeRefreshToken,
  revokeAllUserTokens,
  recordFailedAttempt,
  getFailedAttempts,
  clearFailedAttempts,
  getIsConnected: () => isRedisConnected,
};
