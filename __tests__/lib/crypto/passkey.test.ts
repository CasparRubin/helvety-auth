import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock @simplewebauthn/browser before importing the module
vi.mock("@simplewebauthn/browser", () => ({
  browserSupportsWebAuthn: vi.fn(() => true),
}));

describe("passkey module", () => {
  const originalWindow = global.window;

  beforeEach(() => {
    vi.resetModules();
  });

  afterEach(() => {
    // Restore window
    if (originalWindow) {
      global.window = originalWindow;
    }
  });

  describe("getRPConfig", () => {
    it("should return localhost config for development", async () => {
      // Mock window.location for localhost
      Object.defineProperty(global, "window", {
        value: {
          location: {
            hostname: "localhost",
            origin: "http://localhost:3002",
          },
        },
        writable: true,
        configurable: true,
      });

      const { getRPConfig } = await import("@/lib/crypto/passkey");
      const config = getRPConfig();

      expect(config.rpId).toBe("localhost");
      expect(config.rpName).toBe("Helvety");
      expect(config.origin).toBe("http://localhost:3002");
    });

    it("should return localhost config for 127.0.0.1", async () => {
      Object.defineProperty(global, "window", {
        value: {
          location: {
            hostname: "127.0.0.1",
            origin: "http://127.0.0.1:3002",
          },
        },
        writable: true,
        configurable: true,
      });

      const { getRPConfig } = await import("@/lib/crypto/passkey");
      const config = getRPConfig();

      expect(config.rpId).toBe("localhost");
      expect(config.origin).toBe("http://127.0.0.1:3002");
    });

    it("should return production config for helvety.com domains", async () => {
      Object.defineProperty(global, "window", {
        value: {
          location: {
            hostname: "auth.helvety.com",
            origin: "https://auth.helvety.com",
          },
        },
        writable: true,
        configurable: true,
      });

      const { getRPConfig } = await import("@/lib/crypto/passkey");
      const config = getRPConfig();

      expect(config.rpId).toBe("helvety.com");
      expect(config.rpName).toBe("Helvety");
      expect(config.origin).toBe("https://auth.helvety.com");
    });

    it("should return server-side fallback when window is undefined", async () => {
      // @ts-expect-error - Intentionally setting window to undefined
      delete global.window;

      const { getRPConfig } = await import("@/lib/crypto/passkey");
      const config = getRPConfig();

      expect(config.rpId).toBe("localhost");
      expect(config.origin).toBe("http://localhost:3002");
    });
  });

  describe("isPasskeySupported", () => {
    it("should return true when WebAuthn is supported", async () => {
      const { browserSupportsWebAuthn } = await import(
        "@simplewebauthn/browser"
      );
      vi.mocked(browserSupportsWebAuthn).mockReturnValue(true);

      const { isPasskeySupported } = await import("@/lib/crypto/passkey");
      expect(isPasskeySupported()).toBe(true);
    });

    it("should return false when WebAuthn is not supported", async () => {
      const { browserSupportsWebAuthn } = await import(
        "@simplewebauthn/browser"
      );
      vi.mocked(browserSupportsWebAuthn).mockReturnValue(false);

      const { isPasskeySupported } = await import("@/lib/crypto/passkey");
      expect(isPasskeySupported()).toBe(false);
    });
  });
});
