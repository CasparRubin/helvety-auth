import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

// Mock @simplewebauthn/browser before importing the module
vi.mock("@simplewebauthn/browser", () => ({
  browserSupportsWebAuthn: vi.fn(() => true),
  platformAuthenticatorIsAvailable: vi.fn(() => Promise.resolve(true)),
  startRegistration: vi.fn(),
  startAuthentication: vi.fn(),
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

  describe("isPlatformAuthenticatorAvailable", () => {
    it("should return true when platform authenticator is available", async () => {
      const { platformAuthenticatorIsAvailable } = await import(
        "@simplewebauthn/browser"
      );
      vi.mocked(platformAuthenticatorIsAvailable).mockResolvedValue(true);

      const { isPlatformAuthenticatorAvailable } = await import(
        "@/lib/crypto/passkey"
      );
      expect(await isPlatformAuthenticatorAvailable()).toBe(true);
    });

    it("should return false when platform authenticator is not available", async () => {
      const { platformAuthenticatorIsAvailable } = await import(
        "@simplewebauthn/browser"
      );
      vi.mocked(platformAuthenticatorIsAvailable).mockResolvedValue(false);

      const { isPlatformAuthenticatorAvailable } = await import(
        "@/lib/crypto/passkey"
      );
      expect(await isPlatformAuthenticatorAvailable()).toBe(false);
    });
  });

  describe("PasskeyError", () => {
    it("should create error with type and message", async () => {
      const { PasskeyError, PasskeyErrorType } = await import(
        "@/lib/crypto/passkey"
      );

      const error = new PasskeyError(
        PasskeyErrorType.CANCELLED,
        "User cancelled the operation"
      );

      expect(error.type).toBe(PasskeyErrorType.CANCELLED);
      expect(error.message).toBe("User cancelled the operation");
      expect(error.name).toBe("PasskeyError");
      expect(error.cause).toBeUndefined();
    });

    it("should create error with cause", async () => {
      const { PasskeyError, PasskeyErrorType } = await import(
        "@/lib/crypto/passkey"
      );

      const originalError = new Error("Original error");
      const error = new PasskeyError(
        PasskeyErrorType.UNKNOWN,
        "Something went wrong",
        originalError
      );

      expect(error.type).toBe(PasskeyErrorType.UNKNOWN);
      expect(error.cause).toBe(originalError);
    });

    it("should have correct error types enum", async () => {
      const { PasskeyErrorType } = await import("@/lib/crypto/passkey");

      expect(PasskeyErrorType.NOT_SUPPORTED).toBe("NOT_SUPPORTED");
      expect(PasskeyErrorType.CANCELLED).toBe("CANCELLED");
      expect(PasskeyErrorType.ALREADY_EXISTS).toBe("ALREADY_EXISTS");
      expect(PasskeyErrorType.SECURITY_ERROR).toBe("SECURITY_ERROR");
      expect(PasskeyErrorType.UNKNOWN).toBe("UNKNOWN");
    });
  });

  describe("generateRegistrationOptions", () => {
    beforeEach(() => {
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
    });

    it("should generate valid registration options", async () => {
      const { generateRegistrationOptions } = await import(
        "@/lib/crypto/passkey"
      );

      const options = generateRegistrationOptions(
        "user-123",
        "test@example.com",
        "Test User"
      );

      expect(options.rp.id).toBe("localhost");
      expect(options.rp.name).toBe("Helvety");
      expect(options.user.name).toBe("test@example.com");
      expect(options.user.displayName).toBe("Test User");
      expect(options.challenge).toBeDefined();
      expect(options.pubKeyCredParams).toHaveLength(2);
      expect(options.authenticatorSelection?.userVerification).toBe("required");
      expect(options.authenticatorSelection?.residentKey).toBe("required");
    });

    it("should use email as displayName when userName is empty", async () => {
      const { generateRegistrationOptions } = await import(
        "@/lib/crypto/passkey"
      );

      const options = generateRegistrationOptions(
        "user-123",
        "test@example.com",
        ""
      );

      expect(options.user.displayName).toBe("test@example.com");
    });

    it("should include PRF extension when salt is provided", async () => {
      const { generateRegistrationOptions } = await import(
        "@/lib/crypto/passkey"
      );

      // Base64 encoded salt
      const prfSalt = btoa("test-salt-value");
      const options = generateRegistrationOptions(
        "user-123",
        "test@example.com",
        "Test User",
        prfSalt
      );

      const extensions = (
        options as { extensions?: { prf?: { eval?: { first?: Uint8Array } } } }
      ).extensions;
      expect(extensions?.prf).toBeDefined();
      expect(extensions?.prf?.eval?.first).toBeDefined();
    });

    it("should not include PRF extension when salt is not provided", async () => {
      const { generateRegistrationOptions } = await import(
        "@/lib/crypto/passkey"
      );

      const options = generateRegistrationOptions(
        "user-123",
        "test@example.com",
        "Test User"
      );

      const extensions = (options as { extensions?: unknown }).extensions;
      expect(extensions).toBeUndefined();
    });
  });

  describe("generateAuthenticationOptions", () => {
    beforeEach(() => {
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
    });

    it("should generate valid authentication options", async () => {
      const { generateAuthenticationOptions } = await import(
        "@/lib/crypto/passkey"
      );

      const options = generateAuthenticationOptions();

      expect(options.rpId).toBe("localhost");
      expect(options.challenge).toBeDefined();
      expect(options.userVerification).toBe("required");
      expect(options.timeout).toBe(60000);
    });

    it("should include allowed credentials when provided", async () => {
      const { generateAuthenticationOptions } = await import(
        "@/lib/crypto/passkey"
      );

      const credentialIds = ["cred-1", "cred-2"];
      const options = generateAuthenticationOptions(credentialIds);

      expect(options.allowCredentials).toHaveLength(2);
      expect(options.allowCredentials?.[0]?.id).toBe("cred-1");
      expect(options.allowCredentials?.[1]?.id).toBe("cred-2");
    });

    it("should include PRF extension when salt is provided", async () => {
      const { generateAuthenticationOptions } = await import(
        "@/lib/crypto/passkey"
      );

      const prfSalt = btoa("test-salt");
      const options = generateAuthenticationOptions(undefined, prfSalt);

      const extensions = (
        options as { extensions?: { prf?: { eval?: { first?: Uint8Array } } } }
      ).extensions;
      expect(extensions?.prf).toBeDefined();
    });
  });

  describe("registerPasskey", () => {
    beforeEach(() => {
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
    });

    it("should register passkey successfully", async () => {
      const { startRegistration } = await import("@simplewebauthn/browser");
      vi.mocked(startRegistration).mockResolvedValue({
        id: "credential-id-123",
        rawId: "credential-id-123",
        type: "public-key",
        response: {
          clientDataJSON: "eyJ0ZXN0IjoidmFsdWUifQ",
          attestationObject: "attestation-data",
        },
        clientExtensionResults: {
          prf: { enabled: true },
        } as AuthenticationExtensionsClientOutputs,
        authenticatorAttachment: "cross-platform",
      });

      const {
        registerPasskey,
        generateRegistrationOptions,
      } = await import("@/lib/crypto/passkey");

      const options = generateRegistrationOptions(
        "user-123",
        "test@example.com",
        "Test User"
      );
      const result = await registerPasskey(options);

      expect(result.credentialId).toBe("credential-id-123");
      expect(result.prfEnabled).toBe(true);
      expect(result.prfOutput).toBeUndefined(); // PRF output only in authentication
    });

    it("should throw CANCELLED error when user cancels", async () => {
      const { startRegistration } = await import("@simplewebauthn/browser");
      const cancelError = new Error("User cancelled");
      cancelError.name = "NotAllowedError";
      vi.mocked(startRegistration).mockRejectedValue(cancelError);

      const {
        registerPasskey,
        generateRegistrationOptions,
        PasskeyErrorType,
      } = await import("@/lib/crypto/passkey");

      const options = generateRegistrationOptions(
        "user-123",
        "test@example.com",
        "Test User"
      );

      await expect(registerPasskey(options)).rejects.toMatchObject({
        type: PasskeyErrorType.CANCELLED,
      });
    });

    it("should throw ALREADY_EXISTS error for duplicate registration", async () => {
      const { startRegistration } = await import("@simplewebauthn/browser");
      const existsError = new Error("Credential already exists");
      existsError.name = "InvalidStateError";
      vi.mocked(startRegistration).mockRejectedValue(existsError);

      const {
        registerPasskey,
        generateRegistrationOptions,
        PasskeyErrorType,
      } = await import("@/lib/crypto/passkey");

      const options = generateRegistrationOptions(
        "user-123",
        "test@example.com",
        "Test User"
      );

      await expect(registerPasskey(options)).rejects.toMatchObject({
        type: PasskeyErrorType.ALREADY_EXISTS,
      });
    });

    it("should throw UNKNOWN error for other errors", async () => {
      const { startRegistration } = await import("@simplewebauthn/browser");
      vi.mocked(startRegistration).mockRejectedValue(new Error("Some error"));

      const {
        registerPasskey,
        generateRegistrationOptions,
        PasskeyErrorType,
      } = await import("@/lib/crypto/passkey");

      const options = generateRegistrationOptions(
        "user-123",
        "test@example.com",
        "Test User"
      );

      await expect(registerPasskey(options)).rejects.toMatchObject({
        type: PasskeyErrorType.UNKNOWN,
      });
    });
  });

  describe("authenticateWithPasskey", () => {
    beforeEach(() => {
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
    });

    it("should authenticate successfully with PRF output", async () => {
      const { startAuthentication } = await import("@simplewebauthn/browser");
      const mockPrfOutput = new ArrayBuffer(32);
      vi.mocked(startAuthentication).mockResolvedValue({
        id: "credential-id-123",
        rawId: "credential-id-123",
        type: "public-key",
        response: {
          clientDataJSON: "eyJ0ZXN0IjoidmFsdWUifQ",
          authenticatorData: "auth-data",
          signature: "signature-data",
        },
        clientExtensionResults: {
          prf: { results: { first: mockPrfOutput } },
        } as AuthenticationExtensionsClientOutputs,
        authenticatorAttachment: "cross-platform",
      });

      const {
        authenticateWithPasskey,
        generateAuthenticationOptions,
      } = await import("@/lib/crypto/passkey");

      const options = generateAuthenticationOptions();
      const result = await authenticateWithPasskey(options);

      expect(result.credentialId).toBe("credential-id-123");
      expect(result.prfEnabled).toBe(true);
      expect(result.prfOutput).toBe(mockPrfOutput);
    });

    it("should authenticate successfully without PRF", async () => {
      const { startAuthentication } = await import("@simplewebauthn/browser");
      vi.mocked(startAuthentication).mockResolvedValue({
        id: "credential-id-123",
        rawId: "credential-id-123",
        type: "public-key",
        response: {
          clientDataJSON: "eyJ0ZXN0IjoidmFsdWUifQ",
          authenticatorData: "auth-data",
          signature: "signature-data",
        },
        clientExtensionResults: {},
        authenticatorAttachment: "cross-platform",
      });

      const {
        authenticateWithPasskey,
        generateAuthenticationOptions,
      } = await import("@/lib/crypto/passkey");

      const options = generateAuthenticationOptions();
      const result = await authenticateWithPasskey(options);

      expect(result.credentialId).toBe("credential-id-123");
      expect(result.prfEnabled).toBe(false);
      expect(result.prfOutput).toBeUndefined();
    });

    it("should throw CANCELLED error when user cancels", async () => {
      const { startAuthentication } = await import("@simplewebauthn/browser");
      const cancelError = new Error("User cancelled");
      cancelError.name = "NotAllowedError";
      vi.mocked(startAuthentication).mockRejectedValue(cancelError);

      const {
        authenticateWithPasskey,
        generateAuthenticationOptions,
        PasskeyErrorType,
      } = await import("@/lib/crypto/passkey");

      const options = generateAuthenticationOptions();

      await expect(authenticateWithPasskey(options)).rejects.toMatchObject({
        type: PasskeyErrorType.CANCELLED,
      });
    });

    it("should throw SECURITY_ERROR for security errors", async () => {
      const { startAuthentication } = await import("@simplewebauthn/browser");
      const securityError = new Error("Security error");
      securityError.name = "SecurityError";
      vi.mocked(startAuthentication).mockRejectedValue(securityError);

      const {
        authenticateWithPasskey,
        generateAuthenticationOptions,
        PasskeyErrorType,
      } = await import("@/lib/crypto/passkey");

      const options = generateAuthenticationOptions();

      await expect(authenticateWithPasskey(options)).rejects.toMatchObject({
        type: PasskeyErrorType.SECURITY_ERROR,
      });
    });
  });

  describe("registerPasskeyWithEncryption", () => {
    beforeEach(() => {
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
    });

    it("should register passkey with encryption setup", async () => {
      const { startRegistration } = await import("@simplewebauthn/browser");
      vi.mocked(startRegistration).mockResolvedValue({
        id: "credential-id-123",
        rawId: "credential-id-123",
        type: "public-key",
        response: {
          clientDataJSON: "eyJ0ZXN0IjoidmFsdWUifQ",
          attestationObject: "attestation-data",
        },
        clientExtensionResults: {
          prf: { enabled: true },
        } as AuthenticationExtensionsClientOutputs,
        authenticatorAttachment: "cross-platform",
      });

      const { registerPasskeyWithEncryption } = await import(
        "@/lib/crypto/passkey"
      );

      const prfSalt = btoa("encryption-salt");
      const result = await registerPasskeyWithEncryption(
        "user-123",
        "test@example.com",
        prfSalt
      );

      expect(result.credentialId).toBe("credential-id-123");
      expect(result.prfEnabled).toBe(true);
    });
  });

  describe("authenticatePasskeyWithEncryption", () => {
    beforeEach(() => {
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
    });

    it("should authenticate with encryption unlock", async () => {
      const { startAuthentication } = await import("@simplewebauthn/browser");
      const mockPrfOutput = new ArrayBuffer(32);
      vi.mocked(startAuthentication).mockResolvedValue({
        id: "credential-id-123",
        rawId: "credential-id-123",
        type: "public-key",
        response: {
          clientDataJSON: "eyJ0ZXN0IjoidmFsdWUifQ",
          authenticatorData: "auth-data",
          signature: "signature-data",
        },
        clientExtensionResults: {
          prf: { results: { first: mockPrfOutput } },
        } as AuthenticationExtensionsClientOutputs,
        authenticatorAttachment: "cross-platform",
      });

      const { authenticatePasskeyWithEncryption } = await import(
        "@/lib/crypto/passkey"
      );

      const prfSalt = btoa("encryption-salt");
      const result = await authenticatePasskeyWithEncryption(
        ["cred-1"],
        prfSalt
      );

      expect(result.credentialId).toBe("credential-id-123");
      expect(result.prfOutput).toBe(mockPrfOutput);
    });
  });

  describe("isPRFSupported", () => {
    it("should return false when window is undefined", async () => {
      // @ts-expect-error - Intentionally setting window to undefined
      delete global.window;

      const { isPRFSupported } = await import("@/lib/crypto/passkey");
      expect(await isPRFSupported()).toBe(false);
    });

    it("should return false when PublicKeyCredential is not available", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: undefined,
        },
        writable: true,
        configurable: true,
      });

      const { isPRFSupported } = await import("@/lib/crypto/passkey");
      expect(await isPRFSupported()).toBe(false);
    });

    it("should return true for Chrome 128+", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: {},
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(global, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
        },
        writable: true,
        configurable: true,
      });

      const { isPRFSupported } = await import("@/lib/crypto/passkey");
      expect(await isPRFSupported()).toBe(true);
    });

    it("should return false for Chrome < 128", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: {},
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(global, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        },
        writable: true,
        configurable: true,
      });

      const { isPRFSupported } = await import("@/lib/crypto/passkey");
      expect(await isPRFSupported()).toBe(false);
    });

    it("should return true for Edge 128+", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: {},
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(global, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        },
        writable: true,
        configurable: true,
      });

      const { isPRFSupported } = await import("@/lib/crypto/passkey");
      expect(await isPRFSupported()).toBe(true);
    });

    it("should return true for Firefox 139+", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: {},
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(global, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:139.0) Gecko/20100101 Firefox/139.0",
        },
        writable: true,
        configurable: true,
      });

      const { isPRFSupported } = await import("@/lib/crypto/passkey");
      expect(await isPRFSupported()).toBe(true);
    });

    it("should return false for Firefox on Android", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: {},
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(global, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Android 13; Mobile; rv:139.0) Gecko/139.0 Firefox/139.0",
        },
        writable: true,
        configurable: true,
      });

      const { isPRFSupported } = await import("@/lib/crypto/passkey");
      expect(await isPRFSupported()).toBe(false);
    });
  });

  describe("getPRFSupportInfo", () => {
    it("should return not supported when not in browser", async () => {
      // @ts-expect-error - Intentionally setting window to undefined
      delete global.window;

      const { getPRFSupportInfo } = await import("@/lib/crypto/passkey");
      const info = await getPRFSupportInfo();

      expect(info.supported).toBe(false);
      expect(info.reason).toBe("Not in browser environment");
    });

    it("should return not supported when WebAuthn is not available", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: undefined,
        },
        writable: true,
        configurable: true,
      });

      const { getPRFSupportInfo } = await import("@/lib/crypto/passkey");
      const info = await getPRFSupportInfo();

      expect(info.supported).toBe(false);
      expect(info.reason).toBe("WebAuthn not supported");
    });

    it("should return detailed info for supported Chrome", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: {},
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(global, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/130.0.0.0 Safari/537.36",
        },
        writable: true,
        configurable: true,
      });

      const { getPRFSupportInfo } = await import("@/lib/crypto/passkey");
      const info = await getPRFSupportInfo();

      expect(info.supported).toBe(true);
      expect(info.browserInfo).toBe("Chrome 130");
    });

    it("should return upgrade message for old Chrome", async () => {
      Object.defineProperty(global, "window", {
        value: {
          PublicKeyCredential: {},
        },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(global, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        },
        writable: true,
        configurable: true,
      });

      const { getPRFSupportInfo } = await import("@/lib/crypto/passkey");
      const info = await getPRFSupportInfo();

      expect(info.supported).toBe(false);
      expect(info.reason).toContain("Chrome 120 detected");
      expect(info.reason).toContain("PRF requires Chrome 128 or later");
    });
  });
});
