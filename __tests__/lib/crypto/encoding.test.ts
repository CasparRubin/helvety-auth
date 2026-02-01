import { describe, it, expect } from "vitest";

import {
  base64Encode,
  base64Decode,
  generateSalt,
  generateIV,
  concatBuffers,
  constantTimeEqual,
} from "@/lib/crypto/encoding";

describe("encoding utilities", () => {
  describe("base64Encode/base64Decode", () => {
    it("should encode and decode a simple string", () => {
      const original = new TextEncoder().encode("Hello, World!");
      const encoded = base64Encode(original);
      const decoded = base64Decode(encoded);

      expect(Array.from(decoded)).toEqual(Array.from(original));
    });

    it("should handle empty array", () => {
      const original = new Uint8Array(0);
      const encoded = base64Encode(original);
      const decoded = base64Decode(encoded);

      expect(decoded.length).toBe(0);
    });

    it("should handle binary data", () => {
      const original = new Uint8Array([0, 127, 255, 128, 64, 32]);
      const encoded = base64Encode(original);
      const decoded = base64Decode(encoded);

      expect(Array.from(decoded)).toEqual(Array.from(original));
    });

    it("should produce valid base64 output", () => {
      const data = new Uint8Array([1, 2, 3, 4, 5]);
      const encoded = base64Encode(data);

      // Base64 should only contain valid characters
      expect(encoded).toMatch(/^[A-Za-z0-9+/=]+$/);
    });
  });

  describe("generateSalt", () => {
    it("should generate salt of default length (16 bytes)", () => {
      const salt = generateSalt();
      expect(salt.length).toBe(16);
    });

    it("should generate salt of custom length", () => {
      const salt = generateSalt(32);
      expect(salt.length).toBe(32);
    });

    it("should generate different salts each time", () => {
      const salt1 = generateSalt();
      const salt2 = generateSalt();

      // Extremely unlikely to be equal
      expect(base64Encode(salt1)).not.toBe(base64Encode(salt2));
    });
  });

  describe("generateIV", () => {
    it("should generate IV of 12 bytes (AES-GCM standard)", () => {
      const iv = generateIV();
      expect(iv.length).toBe(12);
    });

    it("should generate different IVs each time", () => {
      const iv1 = generateIV();
      const iv2 = generateIV();

      expect(base64Encode(iv1)).not.toBe(base64Encode(iv2));
    });
  });

  describe("concatBuffers", () => {
    it("should concatenate multiple buffers", () => {
      const buf1 = new Uint8Array([1, 2, 3]);
      const buf2 = new Uint8Array([4, 5]);
      const buf3 = new Uint8Array([6, 7, 8, 9]);

      const result = concatBuffers(buf1, buf2, buf3);

      expect(Array.from(result)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9]);
    });

    it("should handle empty buffers", () => {
      const buf1 = new Uint8Array([1, 2]);
      const empty = new Uint8Array(0);
      const buf2 = new Uint8Array([3, 4]);

      const result = concatBuffers(buf1, empty, buf2);

      expect(Array.from(result)).toEqual([1, 2, 3, 4]);
    });

    it("should handle single buffer", () => {
      const buf = new Uint8Array([1, 2, 3]);
      const result = concatBuffers(buf);

      expect(Array.from(result)).toEqual(Array.from(buf));
    });

    it("should handle no buffers", () => {
      const result = concatBuffers();
      expect(result.length).toBe(0);
    });
  });

  describe("constantTimeEqual", () => {
    it("should return true for equal arrays", () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 5]);

      expect(constantTimeEqual(a, b)).toBe(true);
    });

    it("should return false for different arrays", () => {
      const a = new Uint8Array([1, 2, 3, 4, 5]);
      const b = new Uint8Array([1, 2, 3, 4, 6]);

      expect(constantTimeEqual(a, b)).toBe(false);
    });

    it("should return false for arrays of different lengths", () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 3, 4]);

      expect(constantTimeEqual(a, b)).toBe(false);
    });

    it("should handle empty arrays", () => {
      const a = new Uint8Array(0);
      const b = new Uint8Array(0);

      expect(constantTimeEqual(a, b)).toBe(true);
    });

    it("should detect difference in first byte", () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([0, 2, 3]);

      expect(constantTimeEqual(a, b)).toBe(false);
    });

    it("should detect difference in last byte", () => {
      const a = new Uint8Array([1, 2, 3]);
      const b = new Uint8Array([1, 2, 4]);

      expect(constantTimeEqual(a, b)).toBe(false);
    });
  });
});
