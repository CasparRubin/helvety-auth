/**
 * Rate Limiting Module
 *
 * Provides distributed rate limiting using Upstash Redis for production
 * environments. Falls back to in-memory rate limiting when Upstash
 * credentials are not configured (development).
 *
 * Production: Uses @upstash/ratelimit with sliding window algorithm.
 *   - Works across serverless invocations and multiple instances
 *   - Shared state via Upstash Redis
 *
 * Development: Uses in-memory Map (single-server only).
 *   - Acceptable for local development
 *   - Does not persist across server restarts
 */

import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

// =============================================================================
// Types
// =============================================================================

/**
 * Rate limit check result
 */
export interface RateLimitResult {
  /** Whether the request is allowed */
  allowed: boolean;
  /** Number of remaining requests in the current window */
  remaining: number;
  /** Seconds until the rate limit resets (only if not allowed) */
  retryAfter?: number;
}

// =============================================================================
// Upstash Redis Client (singleton)
// =============================================================================

let redis: Redis | null = null;

/**
 * Get or create the Upstash Redis client.
 * Returns null if credentials are not configured.
 */
function getRedis(): Redis | null {
  if (redis) return redis;

  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;

  if (!url || !token) {
    return null;
  }

  redis = new Redis({ url, token });
  return redis;
}

// =============================================================================
// Rate Limiter Instances (cached per configuration)
// =============================================================================

const rateLimiters = new Map<string, Ratelimit>();

/**
 * Get or create an Upstash rate limiter for the given configuration.
 */
function getUpstashLimiter(
  prefix: string,
  maxRequests: number,
  windowMs: number
): Ratelimit | null {
  const redisClient = getRedis();
  if (!redisClient) return null;

  const key = `${prefix}:${maxRequests}:${windowMs}`;
  let limiter = rateLimiters.get(key);

  if (!limiter) {
    const windowSec = Math.ceil(windowMs / 1000);
    const duration: `${number} m` | `${number} s` =
      windowSec >= 60 ? `${Math.ceil(windowSec / 60)} m` : `${windowSec} s`;

    limiter = new Ratelimit({
      redis: redisClient,
      limiter: Ratelimit.slidingWindow(maxRequests, duration),
      prefix: `ratelimit:${prefix}`,
      analytics: false,
    });

    rateLimiters.set(key, limiter);
  }

  return limiter;
}

// =============================================================================
// In-Memory Fallback (development only)
// =============================================================================

/** In-memory rate limit tracking record (development fallback) */
interface RateLimitRecord {
  count: number;
  resetTime: number;
}

const inMemoryStore = new Map<string, RateLimitRecord>();

const CLEANUP_INTERVAL = 60 * 1000;
let cleanupTimer: NodeJS.Timeout | null = null;

/** Start periodic cleanup of expired in-memory records. */
function startCleanup(): void {
  if (cleanupTimer) return;

  cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, record] of inMemoryStore.entries()) {
      if (now > record.resetTime) {
        inMemoryStore.delete(key);
      }
    }
  }, CLEANUP_INTERVAL);

  cleanupTimer.unref();
}

/** In-memory rate limit check (fallback for development). */
function checkInMemoryRateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): RateLimitResult {
  startCleanup();

  const now = Date.now();
  const record = inMemoryStore.get(key);

  if (!record || now > record.resetTime) {
    inMemoryStore.set(key, { count: 1, resetTime: now + windowMs });
    return { allowed: true, remaining: maxRequests - 1 };
  }

  if (record.count >= maxRequests) {
    const retryAfter = Math.ceil((record.resetTime - now) / 1000);
    return { allowed: false, remaining: 0, retryAfter };
  }

  record.count++;
  return { allowed: true, remaining: maxRequests - record.count };
}

// =============================================================================
// Public API
// =============================================================================

/**
 * Check if a request is allowed under the rate limit.
 *
 * Uses Upstash Redis in production (distributed), falls back to in-memory
 * in development when UPSTASH_REDIS_REST_URL is not configured.
 *
 * @param key - Unique identifier for the rate limit (e.g., IP + endpoint)
 * @param maxRequests - Maximum number of requests allowed in the window
 * @param windowMs - Time window in milliseconds (default: 60 seconds)
 * @returns Rate limit result with allowed status and remaining requests
 */
export async function checkRateLimit(
  key: string,
  maxRequests: number = 5,
  windowMs: number = 60000
): Promise<RateLimitResult> {
  const limiter = getUpstashLimiter("api", maxRequests, windowMs);

  if (limiter) {
    try {
      const result = await limiter.limit(key);

      if (!result.success) {
        const retryAfter = Math.ceil((result.reset - Date.now()) / 1000);
        return {
          allowed: false,
          remaining: result.remaining,
          retryAfter: Math.max(retryAfter, 1),
        };
      }

      return { allowed: true, remaining: result.remaining };
    } catch {
      // If Upstash fails, fall through to in-memory
    }
  }

  return checkInMemoryRateLimit(key, maxRequests, windowMs);
}

/**
 * Reset the rate limit for a specific key.
 *
 * @param key - The rate limit key to reset
 */
export async function resetRateLimit(key: string): Promise<void> {
  const redisClient = getRedis();
  if (redisClient) {
    try {
      await redisClient.del(`ratelimit:api:${key}`);
    } catch {
      // Ignore errors on reset
    }
  }

  inMemoryStore.delete(key);
}

/**
 * Rate limit configurations for different endpoints
 */
export const RATE_LIMITS = {
  /** Login attempts: 5 per minute per IP */
  LOGIN: { maxRequests: 5, windowMs: 60 * 1000 },
  /** Passkey authentication: 10 per minute per IP */
  PASSKEY: { maxRequests: 10, windowMs: 60 * 1000 },
  /** Magic link requests: 3 per 5 minutes per email */
  MAGIC_LINK: { maxRequests: 3, windowMs: 5 * 60 * 1000 },
  /** Encryption unlock attempts: 5 per minute per user */
  ENCRYPTION_UNLOCK: { maxRequests: 5, windowMs: 60 * 1000 },
  /** API calls: 100 per minute per user */
  API: { maxRequests: 100, windowMs: 60 * 1000 },
  /** Download requests: 30 per minute per user */
  DOWNLOADS: { maxRequests: 30, windowMs: 60 * 1000 },
  /** Tenant management: 20 per minute per user */
  TENANTS: { maxRequests: 20, windowMs: 60 * 1000 },
} as const;
