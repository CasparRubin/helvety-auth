import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import { base64Decode } from "@/lib/crypto/encoding";
import {
  generatePRFParams,
  getPRFSaltBytes,
  deriveKeyFromPRF,
  initializePRFEncryption,
  unlockPRFEncryption,
  isPRFSupported,
  getPRFSupportInfo,
  PRF_VERSION,
} from "@/lib/crypto/prf-key-derivation";
import { CryptoError, CryptoErrorType } from "@/lib/crypto/types";

import type { PRFKeyParams } from "@/lib/crypto/prf-key-derivation";

describe("PRF Key Derivation", () => {
  describe("generatePRFParams", () => {
    it("should generate params with correct version", () => {
      const params = generatePRFParams();
      expect(params.version).toBe(PRF_VERSION);
    });

    it("should generate params with valid base64 salt", () => {
      const params = generatePRFParams();
      expect(typeof params.prfSalt).toBe("string");

      // Should be valid base64 (no error on decode)
      const decoded = base64Decode(params.prfSalt);
      expect(decoded.length).toBe(32); // PRF_SALT_LENGTH
    });

    it("should generate different salts each time", () => {
      const params1 = generatePRFParams();
      const params2 = generatePRFParams();
      expect(params1.prfSalt).not.toBe(params2.prfSalt);
    });
  });

  describe("getPRFSaltBytes", () => {
    it("should decode base64 salt to Uint8Array", () => {
      const params = generatePRFParams();
      const saltBytes = getPRFSaltBytes(params);

      expect(saltBytes).toBeInstanceOf(Uint8Array);
      expect(saltBytes.length).toBe(32);
    });

    it("should return correct bytes for known salt", () => {
      const params: PRFKeyParams = {
        prfSalt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", // 32 zeros
        version: 1,
      };

      const saltBytes = getPRFSaltBytes(params);
      expect(Array.from(saltBytes)).toEqual(new Array(32).fill(0));
    });
  });

  describe("deriveKeyFromPRF", () => {
    let mockImportKey: ReturnType<typeof vi.fn>;
    let mockDeriveKey: ReturnType<typeof vi.fn>;
    let mockKeyMaterial: CryptoKey;
    let mockDerivedKey: CryptoKey;

    beforeEach(() => {
      mockImportKey = vi.fn();
      mockDeriveKey = vi.fn();

      mockKeyMaterial = {
        type: "secret",
        extractable: false,
        algorithm: { name: "HKDF" },
        usages: ["deriveKey"],
      } as CryptoKey;

      mockDerivedKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt", "wrapKey", "unwrapKey"],
      } as CryptoKey;

      mockImportKey.mockResolvedValue(mockKeyMaterial);
      mockDeriveKey.mockResolvedValue(mockDerivedKey);

      Object.defineProperty(globalThis.crypto, "subtle", {
        value: {
          importKey: mockImportKey,
          deriveKey: mockDeriveKey,
          encrypt: vi.fn(),
          decrypt: vi.fn(),
          generateKey: vi.fn(),
        },
        configurable: true,
      });
    });

    it("should derive key from PRF output", async () => {
      const prfOutput = new ArrayBuffer(32);
      const params = generatePRFParams();

      const key = await deriveKeyFromPRF(prfOutput, params);

      expect(key).toBe(mockDerivedKey);
    });

    it("should call importKey with correct parameters", async () => {
      const prfOutput = new ArrayBuffer(32);
      const params = generatePRFParams();

      await deriveKeyFromPRF(prfOutput, params);

      expect(mockImportKey).toHaveBeenCalledWith(
        "raw",
        prfOutput,
        "HKDF",
        false,
        ["deriveKey"]
      );
    });

    it("should call deriveKey with HKDF and AES-GCM parameters", async () => {
      const prfOutput = new ArrayBuffer(32);
      const params = generatePRFParams();

      await deriveKeyFromPRF(prfOutput, params);

      expect(mockDeriveKey).toHaveBeenCalledTimes(1);
      const [algorithm, keyMaterial, derivedAlgorithm, extractable, usages] =
        mockDeriveKey.mock.calls[0]!;

      expect(algorithm.name).toBe("HKDF");
      expect(algorithm.hash).toBe("SHA-256");
      expect(algorithm.salt).toBeDefined();
      expect(algorithm.info).toBeDefined();
      expect(keyMaterial).toBe(mockKeyMaterial);
      expect(derivedAlgorithm).toEqual({ name: "AES-GCM", length: 256 });
      expect(extractable).toBe(false);
      expect(usages).toEqual(["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
    });

    it("should throw CryptoError on importKey failure", async () => {
      mockImportKey.mockRejectedValue(new Error("Import failed"));

      const prfOutput = new ArrayBuffer(32);
      const params = generatePRFParams();

      await expect(deriveKeyFromPRF(prfOutput, params)).rejects.toThrow(
        CryptoError
      );
      await expect(deriveKeyFromPRF(prfOutput, params)).rejects.toMatchObject({
        type: CryptoErrorType.KEY_DERIVATION_FAILED,
      });
    });

    it("should throw CryptoError on deriveKey failure", async () => {
      mockDeriveKey.mockRejectedValue(new Error("Derive failed"));

      const prfOutput = new ArrayBuffer(32);
      const params = generatePRFParams();

      await expect(deriveKeyFromPRF(prfOutput, params)).rejects.toThrow(
        CryptoError
      );
    });
  });

  describe("initializePRFEncryption", () => {
    let mockImportKey: ReturnType<typeof vi.fn>;
    let mockDeriveKey: ReturnType<typeof vi.fn>;

    beforeEach(() => {
      mockImportKey = vi.fn();
      mockDeriveKey = vi.fn();

      const mockKeyMaterial = {
        type: "secret",
        extractable: false,
        algorithm: { name: "HKDF" },
        usages: ["deriveKey"],
      } as CryptoKey;

      const mockDerivedKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      mockImportKey.mockResolvedValue(mockKeyMaterial);
      mockDeriveKey.mockResolvedValue(mockDerivedKey);

      Object.defineProperty(globalThis.crypto, "subtle", {
        value: {
          importKey: mockImportKey,
          deriveKey: mockDeriveKey,
          encrypt: vi.fn(),
          decrypt: vi.fn(),
          generateKey: vi.fn(),
        },
        configurable: true,
      });
    });

    it("should return params and master key", async () => {
      const prfOutput = new ArrayBuffer(32);

      const result = await initializePRFEncryption(prfOutput);

      expect(result).toHaveProperty("params");
      expect(result).toHaveProperty("masterKey");
      expect(result.params.version).toBe(PRF_VERSION);
      expect(typeof result.params.prfSalt).toBe("string");
    });
  });

  describe("unlockPRFEncryption", () => {
    let mockImportKey: ReturnType<typeof vi.fn>;
    let mockDeriveKey: ReturnType<typeof vi.fn>;
    let mockDerivedKey: CryptoKey;

    beforeEach(() => {
      mockImportKey = vi.fn();
      mockDeriveKey = vi.fn();

      const mockKeyMaterial = {
        type: "secret",
        extractable: false,
        algorithm: { name: "HKDF" },
        usages: ["deriveKey"],
      } as CryptoKey;

      mockDerivedKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      mockImportKey.mockResolvedValue(mockKeyMaterial);
      mockDeriveKey.mockResolvedValue(mockDerivedKey);

      Object.defineProperty(globalThis.crypto, "subtle", {
        value: {
          importKey: mockImportKey,
          deriveKey: mockDeriveKey,
          encrypt: vi.fn(),
          decrypt: vi.fn(),
          generateKey: vi.fn(),
        },
        configurable: true,
      });
    });

    it("should return derived key", async () => {
      const prfOutput = new ArrayBuffer(32);
      const params = generatePRFParams();

      const key = await unlockPRFEncryption(prfOutput, params);

      expect(key).toBe(mockDerivedKey);
    });
  });

  describe("isPRFSupported", () => {
    let originalWindow: typeof window;
    let originalNavigator: typeof navigator;

    beforeEach(() => {
      originalWindow = globalThis.window;
      originalNavigator = globalThis.navigator;
    });

    afterEach(() => {
      if (originalWindow) {
        Object.defineProperty(globalThis, "window", {
          value: originalWindow,
          configurable: true,
        });
      }
      if (originalNavigator) {
        Object.defineProperty(globalThis, "navigator", {
          value: originalNavigator,
          configurable: true,
        });
      }
    });

    it("should return false when window is undefined", async () => {
      Object.defineProperty(globalThis, "window", {
        value: undefined,
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(false);
    });

    it("should return false when PublicKeyCredential is not available", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: undefined },
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(false);
    });

    it("should return true for Chrome 128+", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36",
        },
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(true);
    });

    it("should return false for Chrome < 128", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 Chrome/127.0.0.0 Safari/537.36",
        },
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(false);
    });

    it("should return true for Edge 128+", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36 Edg/130.0.0.0",
        },
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(true);
    });

    it("should return true for Safari 18+", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/18.0 Safari/605.1.15",
        },
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(true);
    });

    it("should return false for Safari < 18", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent:
            "Mozilla/5.0 (Macintosh) AppleWebKit/605.1.15 Version/17.0 Safari/605.1.15",
        },
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(false);
    });

    it("should return true for Firefox 139+", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent: "Mozilla/5.0 (Windows NT 10.0; rv:139.0) Gecko/20100101 Firefox/139.0",
        },
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(true);
    });

    it("should return false for Firefox on Android", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent: "Mozilla/5.0 (Android 14) Gecko/139.0 Firefox/139.0",
        },
        configurable: true,
      });

      const result = await isPRFSupported();
      expect(result).toBe(false);
    });
  });

  describe("getPRFSupportInfo", () => {
    let originalWindow: typeof window;
    let originalNavigator: typeof navigator;

    beforeEach(() => {
      originalWindow = globalThis.window;
      originalNavigator = globalThis.navigator;
    });

    afterEach(() => {
      if (originalWindow) {
        Object.defineProperty(globalThis, "window", {
          value: originalWindow,
          configurable: true,
        });
      }
      if (originalNavigator) {
        Object.defineProperty(globalThis, "navigator", {
          value: originalNavigator,
          configurable: true,
        });
      }
    });

    it("should return not supported for server-side", async () => {
      Object.defineProperty(globalThis, "window", {
        value: undefined,
        configurable: true,
      });

      const info = await getPRFSupportInfo();
      expect(info.supported).toBe(false);
      expect(info.reason).toBe("Not in browser environment");
    });

    it("should return not supported when WebAuthn unavailable", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: undefined },
        configurable: true,
      });

      const info = await getPRFSupportInfo();
      expect(info.supported).toBe(false);
      expect(info.reason).toBe("WebAuthn not supported");
    });

    it("should return Chrome version info for supported browser", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent: "Mozilla/5.0 Chrome/130.0.0.0 Safari/537.36",
        },
        configurable: true,
      });

      const info = await getPRFSupportInfo();
      expect(info.supported).toBe(true);
      expect(info.browserInfo).toBe("Chrome 130");
    });

    it("should return Chrome version info for unsupported version", async () => {
      Object.defineProperty(globalThis, "window", {
        value: { PublicKeyCredential: {} },
        configurable: true,
      });
      Object.defineProperty(globalThis, "navigator", {
        value: {
          userAgent: "Mozilla/5.0 Chrome/120.0.0.0 Safari/537.36",
        },
        configurable: true,
      });

      const info = await getPRFSupportInfo();
      expect(info.supported).toBe(false);
      expect(info.browserInfo).toBe("Chrome 120");
      expect(info.reason).toContain("Chrome 120 detected");
    });
  });
});
