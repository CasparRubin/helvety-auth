import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";

import {
  checkRateLimit,
  resetRateLimit,
  getRateLimitStatus,
  RATE_LIMITS,
} from "@/lib/rate-limit";

describe("Rate Limit Module", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    // Reset all rate limits between tests
    resetRateLimit("test-key");
    resetRateLimit("test-key-2");
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("checkRateLimit", () => {
    it("should allow first request", () => {
      const result = checkRateLimit("test-key", 5, 60000);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
      expect(result.retryAfter).toBeUndefined();
    });

    it("should decrement remaining count on each request", () => {
      const result1 = checkRateLimit("test-key", 5, 60000);
      expect(result1.remaining).toBe(4);

      const result2 = checkRateLimit("test-key", 5, 60000);
      expect(result2.remaining).toBe(3);

      const result3 = checkRateLimit("test-key", 5, 60000);
      expect(result3.remaining).toBe(2);
    });

    it("should block requests when limit is exceeded", () => {
      // Use up all requests
      for (let i = 0; i < 5; i++) {
        checkRateLimit("test-key", 5, 60000);
      }

      // Next request should be blocked
      const result = checkRateLimit("test-key", 5, 60000);

      expect(result.allowed).toBe(false);
      expect(result.remaining).toBe(0);
      expect(result.retryAfter).toBeGreaterThan(0);
    });

    it("should provide correct retryAfter value", () => {
      // Use up all requests
      for (let i = 0; i < 5; i++) {
        checkRateLimit("test-key", 5, 60000);
      }

      const result = checkRateLimit("test-key", 5, 60000);

      // Should be close to 60 seconds
      expect(result.retryAfter).toBeLessThanOrEqual(60);
      expect(result.retryAfter).toBeGreaterThan(55);
    });

    it("should reset after window expires", () => {
      // Use up all requests
      for (let i = 0; i < 5; i++) {
        checkRateLimit("test-key", 5, 60000);
      }

      // Advance time past the window
      vi.advanceTimersByTime(61000);

      // Should be allowed again
      const result = checkRateLimit("test-key", 5, 60000);

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });

    it("should track different keys independently", () => {
      // Use up key 1
      for (let i = 0; i < 3; i++) {
        checkRateLimit("test-key", 3, 60000);
      }

      // Key 1 should be blocked
      expect(checkRateLimit("test-key", 3, 60000).allowed).toBe(false);

      // Key 2 should still be allowed
      expect(checkRateLimit("test-key-2", 3, 60000).allowed).toBe(true);
    });

    it("should use default values when not specified", () => {
      const result = checkRateLimit("test-key");

      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4); // default maxRequests is 5
    });
  });

  describe("resetRateLimit", () => {
    it("should reset rate limit for a key", () => {
      // Use up all requests
      for (let i = 0; i < 5; i++) {
        checkRateLimit("test-key", 5, 60000);
      }

      // Should be blocked
      expect(checkRateLimit("test-key", 5, 60000).allowed).toBe(false);

      // Reset the key
      resetRateLimit("test-key");

      // Should be allowed again
      const result = checkRateLimit("test-key", 5, 60000);
      expect(result.allowed).toBe(true);
      expect(result.remaining).toBe(4);
    });

    it("should not affect other keys when resetting", () => {
      // Use up both keys
      for (let i = 0; i < 5; i++) {
        checkRateLimit("test-key", 5, 60000);
        checkRateLimit("test-key-2", 5, 60000);
      }

      // Reset only key 1
      resetRateLimit("test-key");

      // Key 1 should be allowed
      expect(checkRateLimit("test-key", 5, 60000).allowed).toBe(true);

      // Key 2 should still be blocked
      expect(checkRateLimit("test-key-2", 5, 60000).allowed).toBe(false);
    });
  });

  describe("getRateLimitStatus", () => {
    it("should return status without incrementing counter", () => {
      // Make 2 requests
      checkRateLimit("test-key", 5, 60000);
      checkRateLimit("test-key", 5, 60000);

      // Check status (should not increment)
      const status1 = getRateLimitStatus("test-key", 5);
      expect(status1.remaining).toBe(3);

      // Check again (should be same)
      const status2 = getRateLimitStatus("test-key", 5);
      expect(status2.remaining).toBe(3);
    });

    it("should return full remaining for unknown key", () => {
      const status = getRateLimitStatus("unknown-key", 10);

      expect(status.allowed).toBe(true);
      expect(status.remaining).toBe(10);
    });

    it("should return blocked status when limit exceeded", () => {
      // Use up all requests
      for (let i = 0; i < 5; i++) {
        checkRateLimit("test-key", 5, 60000);
      }

      const status = getRateLimitStatus("test-key", 5);

      expect(status.allowed).toBe(false);
      expect(status.remaining).toBe(0);
      expect(status.retryAfter).toBeGreaterThan(0);
    });
  });

  describe("RATE_LIMITS constants", () => {
    it("should have LOGIN limit defined", () => {
      expect(RATE_LIMITS.LOGIN).toBeDefined();
      expect(RATE_LIMITS.LOGIN.maxRequests).toBe(5);
      expect(RATE_LIMITS.LOGIN.windowMs).toBe(60 * 1000);
    });

    it("should have PASSKEY limit defined", () => {
      expect(RATE_LIMITS.PASSKEY).toBeDefined();
      expect(RATE_LIMITS.PASSKEY.maxRequests).toBe(10);
      expect(RATE_LIMITS.PASSKEY.windowMs).toBe(60 * 1000);
    });

    it("should have MAGIC_LINK limit defined", () => {
      expect(RATE_LIMITS.MAGIC_LINK).toBeDefined();
      expect(RATE_LIMITS.MAGIC_LINK.maxRequests).toBe(3);
      expect(RATE_LIMITS.MAGIC_LINK.windowMs).toBe(5 * 60 * 1000);
    });

    it("should have ENCRYPTION_UNLOCK limit defined", () => {
      expect(RATE_LIMITS.ENCRYPTION_UNLOCK).toBeDefined();
      expect(RATE_LIMITS.ENCRYPTION_UNLOCK.maxRequests).toBe(5);
      expect(RATE_LIMITS.ENCRYPTION_UNLOCK.windowMs).toBe(60 * 1000);
    });

    it("should have API limit defined", () => {
      expect(RATE_LIMITS.API).toBeDefined();
      expect(RATE_LIMITS.API.maxRequests).toBe(100);
      expect(RATE_LIMITS.API.windowMs).toBe(60 * 1000);
    });
  });
});
