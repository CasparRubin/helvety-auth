/**
 * @vitest-environment node
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock next/headers cookies
const mockCookieStore = {
  get: vi.fn(),
  set: vi.fn(),
};

vi.mock("next/headers", () => ({
  cookies: vi.fn(() => Promise.resolve(mockCookieStore)),
}));

import {
  generateCSRFToken,
  getCSRFToken,
  validateCSRFToken,
  requireCSRFToken,
} from "@/lib/csrf";

describe("CSRF Module", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockCookieStore.get.mockReturnValue(undefined);
    mockCookieStore.set.mockReturnValue(undefined);
  });

  describe("generateCSRFToken", () => {
    it("should generate a token and set it as a cookie", async () => {
      const token = await generateCSRFToken();

      expect(token).toBeDefined();
      expect(typeof token).toBe("string");
      expect(token.length).toBeGreaterThan(0);
      expect(mockCookieStore.set).toHaveBeenCalledWith(
        "csrf_token",
        expect.any(String),
        expect.objectContaining({
          httpOnly: true,
          sameSite: "strict",
          path: "/",
          maxAge: 60 * 60,
        })
      );
    });

    it("should set secure flag in production", async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "production";

      await generateCSRFToken();

      expect(mockCookieStore.set).toHaveBeenCalledWith(
        "csrf_token",
        expect.any(String),
        expect.objectContaining({
          secure: true,
        })
      );

      process.env.NODE_ENV = originalEnv;
    });

    it("should not set secure flag in development", async () => {
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "development";

      await generateCSRFToken();

      expect(mockCookieStore.set).toHaveBeenCalledWith(
        "csrf_token",
        expect.any(String),
        expect.objectContaining({
          secure: false,
        })
      );

      process.env.NODE_ENV = originalEnv;
    });
  });

  describe("getCSRFToken", () => {
    it("should return token from cookie if exists", async () => {
      mockCookieStore.get.mockReturnValue({ value: "test-token-123" });

      const token = await getCSRFToken();

      expect(token).toBe("test-token-123");
      expect(mockCookieStore.get).toHaveBeenCalledWith("csrf_token");
    });

    it("should return null if cookie does not exist", async () => {
      mockCookieStore.get.mockReturnValue(undefined);

      const token = await getCSRFToken();

      expect(token).toBeNull();
    });
  });

  describe("validateCSRFToken", () => {
    it("should return true for matching token", async () => {
      const storedToken = "valid-token-12345";
      mockCookieStore.get.mockReturnValue({ value: storedToken });

      const isValid = await validateCSRFToken(storedToken);

      expect(isValid).toBe(true);
    });

    it("should return false for mismatching token", async () => {
      mockCookieStore.get.mockReturnValue({ value: "stored-token" });

      const isValid = await validateCSRFToken("different-token");

      expect(isValid).toBe(false);
    });

    it("should return false for null token", async () => {
      mockCookieStore.get.mockReturnValue({ value: "stored-token" });

      const isValid = await validateCSRFToken(null);

      expect(isValid).toBe(false);
    });

    it("should return false for undefined token", async () => {
      mockCookieStore.get.mockReturnValue({ value: "stored-token" });

      const isValid = await validateCSRFToken(undefined);

      expect(isValid).toBe(false);
    });

    it("should return false when no cookie is set", async () => {
      mockCookieStore.get.mockReturnValue(undefined);

      const isValid = await validateCSRFToken("some-token");

      expect(isValid).toBe(false);
    });

    it("should return false for tokens of different lengths", async () => {
      mockCookieStore.get.mockReturnValue({ value: "short" });

      const isValid = await validateCSRFToken("much-longer-token");

      expect(isValid).toBe(false);
    });
  });

  describe("requireCSRFToken", () => {
    it("should not throw for valid token", async () => {
      const token = "valid-token";
      mockCookieStore.get.mockReturnValue({ value: token });

      await expect(requireCSRFToken(token)).resolves.not.toThrow();
    });

    it("should throw for invalid token", async () => {
      mockCookieStore.get.mockReturnValue({ value: "stored-token" });

      await expect(requireCSRFToken("wrong-token")).rejects.toThrow(
        "Invalid CSRF token"
      );
    });

    it("should throw for null token", async () => {
      mockCookieStore.get.mockReturnValue({ value: "stored-token" });

      await expect(requireCSRFToken(null)).rejects.toThrow("Invalid CSRF token");
    });

    it("should throw when cookie is missing", async () => {
      mockCookieStore.get.mockReturnValue(undefined);

      await expect(requireCSRFToken("some-token")).rejects.toThrow(
        "Invalid CSRF token"
      );
    });
  });
});
