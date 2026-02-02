/**
 * Rate Limiting Module
 *
 * Provides in-memory rate limiting for authentication endpoints.
 * Prevents brute force attacks by limiting the number of requests
 * from a single IP or identifier within a time window.
 *
 * Note: This is an in-memory implementation suitable for single-server deployments.
 * For multi-server deployments, consider using Redis or a similar distributed store.
 */

/**
 *
 */
interface RateLimitRecord {
  count: number;
  resetTime: number;
}

// In-memory store for rate limit records
// Key is the identifier (e.g., IP address, user ID)
const rateLimitStore = new Map<string, RateLimitRecord>();

// Clean up expired records periodically to prevent memory leaks
const CLEANUP_INTERVAL = 60 * 1000; // 1 minute
let cleanupTimer: NodeJS.Timeout | null = null;

/**
 *
 */
function startCleanup(): void {
  if (cleanupTimer) return;

  cleanupTimer = setInterval(() => {
    const now = Date.now();
    for (const [key, record] of rateLimitStore.entries()) {
      if (now > record.resetTime) {
        rateLimitStore.delete(key);
      }
    }
  }, CLEANUP_INTERVAL);

  // Don't block process exit
  cleanupTimer.unref();
}

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

/**
 * Check if a request is allowed under the rate limit.
 *
 * @param key - Unique identifier for the rate limit (e.g., IP + endpoint)
 * @param maxRequests - Maximum number of requests allowed in the window
 * @param windowMs - Time window in milliseconds (default: 60 seconds)
 * @returns Rate limit result with allowed status and remaining requests
 *
 * @example
 * // In a Server Action
 * const ip = headers().get("x-forwarded-for") ?? "unknown";
 * const result = checkRateLimit(`login:${ip}`, 5, 60000);
 * if (!result.allowed) {
 *   return { error: `Rate limited. Try again in ${result.retryAfter} seconds.` };
 * }
 */
export function checkRateLimit(
  key: string,
  maxRequests: number = 5,
  windowMs: number = 60000
): RateLimitResult {
  // Start cleanup timer on first use
  startCleanup();

  const now = Date.now();
  const record = rateLimitStore.get(key);

  // No existing record or expired record - allow and create new
  if (!record || now > record.resetTime) {
    rateLimitStore.set(key, {
      count: 1,
      resetTime: now + windowMs,
    });
    return {
      allowed: true,
      remaining: maxRequests - 1,
    };
  }

  // Check if limit exceeded
  if (record.count >= maxRequests) {
    const retryAfter = Math.ceil((record.resetTime - now) / 1000);
    return {
      allowed: false,
      remaining: 0,
      retryAfter,
    };
  }

  // Increment count and allow
  record.count++;
  return {
    allowed: true,
    remaining: maxRequests - record.count,
  };
}

/**
 * Reset the rate limit for a specific key.
 *
 * Use this after successful authentication to clear failed attempt counts.
 *
 * @param key - The rate limit key to reset
 */
export function resetRateLimit(key: string): void {
  rateLimitStore.delete(key);
}

/**
 * Get the current rate limit status without incrementing the counter.
 *
 * @param key - The rate limit key to check
 * @param maxRequests - Maximum requests for calculating remaining
 * @returns Current rate limit status
 */
export function getRateLimitStatus(
  key: string,
  maxRequests: number = 5
): RateLimitResult {
  const now = Date.now();
  const record = rateLimitStore.get(key);

  if (!record || now > record.resetTime) {
    return {
      allowed: true,
      remaining: maxRequests,
    };
  }

  if (record.count >= maxRequests) {
    return {
      allowed: false,
      remaining: 0,
      retryAfter: Math.ceil((record.resetTime - now) / 1000),
    };
  }

  return {
    allowed: true,
    remaining: maxRequests - record.count,
  };
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
} as const;
