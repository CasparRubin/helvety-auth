import { describe, it, expect, vi, beforeEach } from "vitest";

import { buildLoginUrl } from "@/lib/auth-utils";

// Mock the server actions since they require server-side execution
vi.mock("@/app/actions/passkey-auth-actions", () => ({
  checkUserPasskeyStatus: vi.fn(),
  hasEncryptionSetup: vi.fn(),
}));

describe("auth-utils", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Mock window.location.origin for buildLoginUrl
    Object.defineProperty(window, "location", {
      value: {
        origin: "https://auth.helvety.com",
      },
      writable: true,
    });
  });

  describe("buildLoginUrl", () => {
    it("should build URL with step parameter", () => {
      const url = buildLoginUrl("encryption-setup");
      expect(url).toBe("https://auth.helvety.com/login?step=encryption-setup");
    });

    it("should build URL with step and redirect_uri", () => {
      const url = buildLoginUrl("passkey-signin", "https://pdf.helvety.com");
      expect(url).toBe(
        "https://auth.helvety.com/login?step=passkey-signin&redirect_uri=https%3A%2F%2Fpdf.helvety.com"
      );
    });

    it("should handle null redirect_uri", () => {
      const url = buildLoginUrl("encryption-setup", null);
      expect(url).toBe("https://auth.helvety.com/login?step=encryption-setup");
    });

    it("should handle undefined redirect_uri", () => {
      const url = buildLoginUrl("encryption-setup", undefined);
      expect(url).toBe("https://auth.helvety.com/login?step=encryption-setup");
    });

    it("should use custom base URL", () => {
      const url = buildLoginUrl(
        "encryption-setup",
        "https://store.helvety.com",
        "/auth/login"
      );
      expect(url).toBe(
        "https://auth.helvety.com/auth/login?step=encryption-setup&redirect_uri=https%3A%2F%2Fstore.helvety.com"
      );
    });

    it("should handle redirect_uri with path", () => {
      const url = buildLoginUrl(
        "passkey-signin",
        "https://pdf.helvety.com/documents/123"
      );
      expect(url).toContain("redirect_uri=");
      expect(url).toContain(
        encodeURIComponent("https://pdf.helvety.com/documents/123")
      );
    });
  });
});
