import {
  describe,
  it,
  expect,
  vi,
  beforeEach,
  beforeAll,
  afterAll,
} from "vitest";

import {
  encrypt,
  decrypt,
  encryptObject,
  decryptObject,
  serializeEncryptedData,
  parseEncryptedData,
  isEncryptedData,
  encryptFields,
  decryptFields,
} from "@/lib/crypto/encryption";
import { CryptoError, CryptoErrorType } from "@/lib/crypto/types";

import type { EncryptedData } from "@/lib/crypto/types";

// Store original crypto.subtle for restoration
const originalSubtle = globalThis.crypto?.subtle;

describe("encryption utilities", () => {
  describe("serializeEncryptedData", () => {
    it("should serialize encrypted data to JSON string", () => {
      const data: EncryptedData = {
        iv: "dGVzdGl2MTIzNDU2Nzg=",
        ciphertext: "dGVzdGNpcGhlcnRleHQ=",
        version: 1,
      };

      const result = serializeEncryptedData(data);
      expect(typeof result).toBe("string");

      const parsed = JSON.parse(result);
      expect(parsed.iv).toBe(data.iv);
      expect(parsed.ciphertext).toBe(data.ciphertext);
      expect(parsed.version).toBe(data.version);
    });
  });

  describe("parseEncryptedData", () => {
    it("should parse valid encrypted data from JSON string", () => {
      const serialized = JSON.stringify({
        iv: "dGVzdGl2MTIzNDU2Nzg=",
        ciphertext: "dGVzdGNpcGhlcnRleHQ=",
        version: 1,
      });

      const result = parseEncryptedData(serialized);
      expect(result.iv).toBe("dGVzdGl2MTIzNDU2Nzg=");
      expect(result.ciphertext).toBe("dGVzdGNpcGhlcnRleHQ=");
      expect(result.version).toBe(1);
    });

    it("should throw CryptoError for invalid JSON", () => {
      expect(() => parseEncryptedData("not json")).toThrow(CryptoError);
      expect(() => parseEncryptedData("not json")).toThrow(
        /Failed to parse encrypted data/
      );
    });

    it("should throw CryptoError for missing iv", () => {
      const serialized = JSON.stringify({
        ciphertext: "dGVzdGNpcGhlcnRleHQ=",
        version: 1,
      });

      expect(() => parseEncryptedData(serialized)).toThrow(CryptoError);
    });

    it("should throw CryptoError for missing ciphertext", () => {
      const serialized = JSON.stringify({
        iv: "dGVzdGl2MTIzNDU2Nzg=",
        version: 1,
      });

      expect(() => parseEncryptedData(serialized)).toThrow(CryptoError);
    });

    it("should throw CryptoError for missing version", () => {
      const serialized = JSON.stringify({
        iv: "dGVzdGl2MTIzNDU2Nzg=",
        ciphertext: "dGVzdGNpcGhlcnRleHQ=",
      });

      expect(() => parseEncryptedData(serialized)).toThrow(CryptoError);
    });

    it("should throw CryptoError for wrong types", () => {
      const serialized = JSON.stringify({
        iv: 123, // should be string
        ciphertext: "dGVzdGNpcGhlcnRleHQ=",
        version: 1,
      });

      expect(() => parseEncryptedData(serialized)).toThrow(CryptoError);
    });
  });

  describe("isEncryptedData", () => {
    it("should return true for valid encrypted data", () => {
      const data: EncryptedData = {
        iv: "dGVzdGl2MTIzNDU2Nzg=",
        ciphertext: "dGVzdGNpcGhlcnRleHQ=",
        version: 1,
      };

      expect(isEncryptedData(data)).toBe(true);
    });

    it("should return false for null", () => {
      expect(isEncryptedData(null)).toBe(false);
    });

    it("should return false for undefined", () => {
      expect(isEncryptedData(undefined)).toBe(false);
    });

    it("should return false for primitives", () => {
      expect(isEncryptedData("string")).toBe(false);
      expect(isEncryptedData(123)).toBe(false);
      expect(isEncryptedData(true)).toBe(false);
    });

    it("should return false for objects missing iv", () => {
      expect(
        isEncryptedData({
          ciphertext: "test",
          version: 1,
        })
      ).toBe(false);
    });

    it("should return false for objects missing ciphertext", () => {
      expect(
        isEncryptedData({
          iv: "test",
          version: 1,
        })
      ).toBe(false);
    });

    it("should return false for objects missing version", () => {
      expect(
        isEncryptedData({
          iv: "test",
          ciphertext: "test",
        })
      ).toBe(false);
    });

    it("should return false for objects with wrong types", () => {
      expect(
        isEncryptedData({
          iv: 123,
          ciphertext: "test",
          version: 1,
        })
      ).toBe(false);
      expect(
        isEncryptedData({
          iv: "test",
          ciphertext: 456,
          version: 1,
        })
      ).toBe(false);
      expect(
        isEncryptedData({
          iv: "test",
          ciphertext: "test",
          version: "1",
        })
      ).toBe(false);
    });
  });

  describe("encrypt and decrypt with mocked crypto", () => {
    let mockKey: CryptoKey;
    let mockEncrypt: ReturnType<typeof vi.fn>;
    let mockDecrypt: ReturnType<typeof vi.fn>;

    beforeAll(() => {
      // Create mock functions
      mockEncrypt = vi.fn();
      mockDecrypt = vi.fn();

      // Replace crypto.subtle with mocked version
      Object.defineProperty(globalThis.crypto, "subtle", {
        value: {
          encrypt: mockEncrypt,
          decrypt: mockDecrypt,
          generateKey: vi.fn(),
          importKey: vi.fn(),
          deriveKey: vi.fn(),
        },
        configurable: true,
      });
    });

    afterAll(() => {
      // Restore original
      if (originalSubtle) {
        Object.defineProperty(globalThis.crypto, "subtle", {
          value: originalSubtle,
          configurable: true,
        });
      }
    });

    beforeEach(() => {
      vi.clearAllMocks();

      // Create a mock CryptoKey
      mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      // Mock crypto.subtle.encrypt to return fake ciphertext
      mockEncrypt.mockResolvedValue(
        new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer
      );

      // Mock crypto.subtle.decrypt to return fake plaintext
      mockDecrypt.mockResolvedValue(
        new TextEncoder().encode("test data").buffer
      );
    });

    it("should encrypt data and return EncryptedData structure", async () => {
      const result = await encrypt("test data", mockKey);

      expect(result).toHaveProperty("iv");
      expect(result).toHaveProperty("ciphertext");
      expect(result).toHaveProperty("version");
      expect(result.version).toBe(1);
      expect(typeof result.iv).toBe("string");
      expect(typeof result.ciphertext).toBe("string");
    });

    it("should call crypto.subtle.encrypt with correct params", async () => {
      await encrypt("test data", mockKey);

      expect(mockEncrypt).toHaveBeenCalledTimes(1);
      const [algorithm, key, data] = mockEncrypt.mock.calls[0]!;
      expect(algorithm.name).toBe("AES-GCM");
      expect(algorithm.iv).toBeDefined();
      expect(algorithm.iv.length).toBe(12); // IV should be 12 bytes for AES-GCM
      expect(key).toBe(mockKey);
      expect(data).toBeDefined();
      // Verify the data is the encoded "test data"
      expect(new TextDecoder().decode(data)).toBe("test data");
    });

    it("should decrypt data", async () => {
      const encrypted: EncryptedData = {
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        ciphertext: btoa(String.fromCharCode(1, 2, 3, 4)),
        version: 1,
      };

      const result = await decrypt(encrypted, mockKey);

      expect(result).toBe("test data");
      expect(mockDecrypt).toHaveBeenCalled();
    });

    it("should throw CryptoError on encryption failure", async () => {
      mockEncrypt.mockRejectedValue(new Error("Encryption failed"));

      await expect(encrypt("test", mockKey)).rejects.toThrow(CryptoError);
      await expect(encrypt("test", mockKey)).rejects.toMatchObject({
        type: CryptoErrorType.ENCRYPTION_FAILED,
      });
    });

    it("should throw CryptoError on decryption failure", async () => {
      mockDecrypt.mockRejectedValue(new Error("Decryption failed"));

      const encrypted: EncryptedData = {
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        ciphertext: btoa(String.fromCharCode(1, 2, 3, 4)),
        version: 1,
      };

      await expect(decrypt(encrypted, mockKey)).rejects.toThrow(CryptoError);
      await expect(decrypt(encrypted, mockKey)).rejects.toMatchObject({
        type: CryptoErrorType.DECRYPTION_FAILED,
      });
    });
  });

  describe("encryptObject and decryptObject", () => {
    let mockKey: CryptoKey;
    let mockEncrypt: ReturnType<typeof vi.fn>;
    let mockDecrypt: ReturnType<typeof vi.fn>;

    beforeAll(() => {
      mockEncrypt = vi.fn();
      mockDecrypt = vi.fn();

      Object.defineProperty(globalThis.crypto, "subtle", {
        value: {
          encrypt: mockEncrypt,
          decrypt: mockDecrypt,
          generateKey: vi.fn(),
          importKey: vi.fn(),
          deriveKey: vi.fn(),
        },
        configurable: true,
      });
    });

    afterAll(() => {
      if (originalSubtle) {
        Object.defineProperty(globalThis.crypto, "subtle", {
          value: originalSubtle,
          configurable: true,
        });
      }
    });

    beforeEach(() => {
      vi.clearAllMocks();

      mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      mockEncrypt.mockResolvedValue(
        new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer
      );
    });

    it("should encrypt an object", async () => {
      const obj = { name: "test", value: 123 };
      const result = await encryptObject(obj, mockKey);

      expect(isEncryptedData(result)).toBe(true);
    });

    it("should decrypt an object", async () => {
      const obj = { name: "test", value: 123 };

      mockDecrypt.mockResolvedValue(
        new TextEncoder().encode(JSON.stringify(obj)).buffer
      );

      const encrypted: EncryptedData = {
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        ciphertext: btoa(String.fromCharCode(1, 2, 3, 4)),
        version: 1,
      };

      const result = await decryptObject<typeof obj>(encrypted, mockKey);

      expect(result).toEqual(obj);
    });

    it("should throw CryptoError for invalid JSON after decryption", async () => {
      mockDecrypt.mockResolvedValue(
        new TextEncoder().encode("not json").buffer
      );

      const encrypted: EncryptedData = {
        iv: btoa(String.fromCharCode(...new Uint8Array(12))),
        ciphertext: btoa(String.fromCharCode(1, 2, 3, 4)),
        version: 1,
      };

      await expect(decryptObject(encrypted, mockKey)).rejects.toThrow(
        CryptoError
      );
      await expect(decryptObject(encrypted, mockKey)).rejects.toMatchObject({
        type: CryptoErrorType.DECRYPTION_FAILED,
        message: "Decrypted data is not valid JSON",
      });
    });
  });

  describe("encryptFields and decryptFields", () => {
    let mockKey: CryptoKey;
    let mockEncrypt: ReturnType<typeof vi.fn>;
    let mockDecrypt: ReturnType<typeof vi.fn>;

    beforeAll(() => {
      mockEncrypt = vi.fn();
      mockDecrypt = vi.fn();

      Object.defineProperty(globalThis.crypto, "subtle", {
        value: {
          encrypt: mockEncrypt,
          decrypt: mockDecrypt,
          generateKey: vi.fn(),
          importKey: vi.fn(),
          deriveKey: vi.fn(),
        },
        configurable: true,
      });
    });

    afterAll(() => {
      if (originalSubtle) {
        Object.defineProperty(globalThis.crypto, "subtle", {
          value: originalSubtle,
          configurable: true,
        });
      }
    });

    beforeEach(() => {
      vi.clearAllMocks();

      mockKey = {
        type: "secret",
        extractable: false,
        algorithm: { name: "AES-GCM", length: 256 },
        usages: ["encrypt", "decrypt"],
      } as CryptoKey;

      mockEncrypt.mockResolvedValue(
        new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer
      );
    });

    it("should encrypt specified string fields", async () => {
      const data = {
        name: "John",
        email: "john@example.com",
        age: 30,
      };

      const result = await encryptFields(data, ["name", "email"], mockKey);

      expect(isEncryptedData(result.name)).toBe(true);
      expect(isEncryptedData(result.email)).toBe(true);
      expect(result.age).toBe(30); // Non-encrypted field unchanged
    });

    it("should encrypt object fields", async () => {
      const data = {
        user: { name: "John" },
        count: 5,
      };

      const result = await encryptFields(data, ["user"], mockKey);

      expect(isEncryptedData(result.user)).toBe(true);
      expect(result.count).toBe(5);
    });

    it("should skip null and undefined values", async () => {
      const data = {
        name: null,
        email: undefined,
        valid: "test",
      };

      const result = await encryptFields(
        data,
        ["name", "email", "valid"],
        mockKey
      );

      expect(result.name).toBeNull();
      expect(result.email).toBeUndefined();
      expect(isEncryptedData(result.valid)).toBe(true);
    });

    it("should decrypt specified fields", async () => {
      const decryptedValue = "decrypted";

      mockDecrypt.mockResolvedValue(
        new TextEncoder().encode(decryptedValue).buffer
      );

      const data = {
        name: {
          iv: btoa(String.fromCharCode(...new Uint8Array(12))),
          ciphertext: btoa(String.fromCharCode(1, 2, 3, 4)),
          version: 1,
        },
        age: 30,
      };

      const result = await decryptFields<{ name: string; age: number }>(
        data,
        ["name"],
        mockKey
      );

      expect(result.name).toBe(decryptedValue);
      expect(result.age).toBe(30);
    });

    it("should skip non-encrypted fields during decryption", async () => {
      const data = {
        name: "plain text", // Not encrypted data
        age: 30,
      };

      const result = await decryptFields<{ name: string; age: number }>(
        data,
        ["name"],
        mockKey
      );

      // Should remain unchanged since it's not encrypted
      expect(result.name).toBe("plain text");
      expect(result.age).toBe(30);
      expect(mockDecrypt).not.toHaveBeenCalled();
    });
  });

  describe("CryptoError", () => {
    it("should create error with correct properties", () => {
      const cause = new Error("Original error");
      const error = new CryptoError(
        CryptoErrorType.ENCRYPTION_FAILED,
        "Test message",
        cause
      );

      expect(error.name).toBe("CryptoError");
      expect(error.type).toBe(CryptoErrorType.ENCRYPTION_FAILED);
      expect(error.message).toBe("Test message");
      expect(error.cause).toBe(cause);
    });

    it("should create error without cause", () => {
      const error = new CryptoError(
        CryptoErrorType.DECRYPTION_FAILED,
        "Test message"
      );

      expect(error.cause).toBeUndefined();
    });
  });
});
