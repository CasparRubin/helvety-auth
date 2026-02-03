import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

describe("env-validation", () => {
  const originalEnv = process.env;

  beforeEach(() => {
    vi.resetModules();
    process.env = { ...originalEnv };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  describe("getValidatedEnv", () => {
    it("should validate correct environment variables", async () => {
      process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

      const { getValidatedEnv } = await import("@/lib/env-validation");
      const env = getValidatedEnv();

      expect(env.NEXT_PUBLIC_SUPABASE_URL).toBe("https://test.supabase.co");
      expect(env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY).toBe(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
      );
    });

    it("should throw error for missing URL", async () => {
      process.env.NEXT_PUBLIC_SUPABASE_URL = "";
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

      const { getValidatedEnv } = await import("@/lib/env-validation");

      expect(() => getValidatedEnv()).toThrow();
    });

    it("should throw error for invalid URL format", async () => {
      process.env.NEXT_PUBLIC_SUPABASE_URL = "not-a-url";
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

      const { getValidatedEnv } = await import("@/lib/env-validation");

      expect(() => getValidatedEnv()).toThrow();
    });

    it("should throw error for missing publishable key", async () => {
      process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY = "";

      const { getValidatedEnv } = await import("@/lib/env-validation");

      expect(() => getValidatedEnv()).toThrow();
    });

    it("should accept new format Supabase keys", async () => {
      process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY =
        "sb_test_abcdefghijklmnopqrstuvwxyz";

      const { getValidatedEnv } = await import("@/lib/env-validation");
      const env = getValidatedEnv();

      expect(env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY).toBe(
        "sb_test_abcdefghijklmnopqrstuvwxyz"
      );
    });

    it("should accept http URLs (for local development)", async () => {
      process.env.NEXT_PUBLIC_SUPABASE_URL = "http://localhost:54321";
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

      const { getValidatedEnv } = await import("@/lib/env-validation");
      const env = getValidatedEnv();

      expect(env.NEXT_PUBLIC_SUPABASE_URL).toBe("http://localhost:54321");
    });
  });

  describe("getSupabaseUrl", () => {
    it("should return the validated URL", async () => {
      process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

      const { getSupabaseUrl } = await import("@/lib/env-validation");

      expect(getSupabaseUrl()).toBe("https://test.supabase.co");
    });
  });

  describe("getSupabaseKey", () => {
    it("should return the validated key", async () => {
      process.env.NEXT_PUBLIC_SUPABASE_URL = "https://test.supabase.co";
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature";

      const { getSupabaseKey } = await import("@/lib/env-validation");

      expect(getSupabaseKey()).toBe(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.signature"
      );
    });
  });
});
