import { describe, it, expect } from "vitest";

import {
  isValidRedirectUri,
  getSafeRedirectUri,
} from "@/lib/redirect-validation";

describe("redirect-validation", () => {
  describe("isValidRedirectUri", () => {
    describe("valid production URIs", () => {
      it("should accept helvety.com root", () => {
        expect(isValidRedirectUri("https://helvety.com")).toBe(true);
      });

      it("should accept helvety.com with path", () => {
        expect(isValidRedirectUri("https://helvety.com/dashboard")).toBe(true);
      });

      it("should accept auth.helvety.com", () => {
        expect(isValidRedirectUri("https://auth.helvety.com")).toBe(true);
        expect(isValidRedirectUri("https://auth.helvety.com/callback")).toBe(
          true
        );
      });

      it("should accept store.helvety.com and its routes", () => {
        expect(isValidRedirectUri("https://store.helvety.com")).toBe(true);
        expect(isValidRedirectUri("https://store.helvety.com/products")).toBe(
          true
        );
        expect(isValidRedirectUri("https://store.helvety.com/account")).toBe(
          true
        );
        expect(
          isValidRedirectUri("https://store.helvety.com/subscriptions")
        ).toBe(true);
        expect(isValidRedirectUri("https://store.helvety.com/tenants")).toBe(
          true
        );
      });

      it("should accept pdf.helvety.com", () => {
        expect(isValidRedirectUri("https://pdf.helvety.com")).toBe(true);
        expect(isValidRedirectUri("https://pdf.helvety.com/editor")).toBe(true);
      });

      it("should accept any future subdomain dynamically", () => {
        // The pattern supports any subdomain for future apps
        expect(isValidRedirectUri("https://new-app.helvety.com")).toBe(true);
        expect(isValidRedirectUri("https://api.helvety.com")).toBe(true);
        expect(
          isValidRedirectUri("https://dashboard.helvety.com/settings")
        ).toBe(true);
        expect(isValidRedirectUri("https://my-cool-app.helvety.com")).toBe(
          true
        );
      });
    });

    describe("valid development URIs", () => {
      it("should accept localhost without port", () => {
        expect(isValidRedirectUri("http://localhost")).toBe(true);
        expect(isValidRedirectUri("http://localhost/callback")).toBe(true);
      });

      it("should accept localhost with any port", () => {
        expect(isValidRedirectUri("http://localhost:3000")).toBe(true);
        expect(isValidRedirectUri("http://localhost:3001")).toBe(true);
        expect(isValidRedirectUri("http://localhost:3002")).toBe(true);
        expect(isValidRedirectUri("http://localhost:8080/auth")).toBe(true);
      });

      it("should accept 127.0.0.1", () => {
        expect(isValidRedirectUri("http://127.0.0.1")).toBe(true);
        expect(isValidRedirectUri("http://127.0.0.1:3000")).toBe(true);
        expect(isValidRedirectUri("http://127.0.0.1:3000/callback")).toBe(true);
      });
    });

    describe("invalid URIs - security", () => {
      it("should reject null and undefined", () => {
        expect(isValidRedirectUri(null)).toBe(false);
        expect(isValidRedirectUri(undefined)).toBe(false);
      });

      it("should reject empty string", () => {
        expect(isValidRedirectUri("")).toBe(false);
      });

      it("should reject javascript: protocol", () => {
        expect(isValidRedirectUri("javascript:alert(1)")).toBe(false);
      });

      it("should reject data: protocol", () => {
        expect(isValidRedirectUri("data:text/html,<script>")).toBe(false);
      });

      it("should reject external domains", () => {
        expect(isValidRedirectUri("https://evil.com")).toBe(false);
        expect(isValidRedirectUri("https://google.com")).toBe(false);
        expect(
          isValidRedirectUri("https://evil.helvety.com.attacker.com")
        ).toBe(false);
      });

      it("should reject http for production domains", () => {
        expect(isValidRedirectUri("http://helvety.com")).toBe(false);
        expect(isValidRedirectUri("http://auth.helvety.com")).toBe(false);
      });

      it("should reject invalid URLs", () => {
        expect(isValidRedirectUri("not-a-url")).toBe(false);
        expect(isValidRedirectUri("://missing-protocol")).toBe(false);
      });

      it("should reject lookalike domains", () => {
        expect(isValidRedirectUri("https://helvety.com.evil.com")).toBe(false);
        expect(isValidRedirectUri("https://helvetycom.evil.com")).toBe(false);
        expect(isValidRedirectUri("https://fake-helvety.com")).toBe(false);
      });
    });
  });

  describe("getSafeRedirectUri", () => {
    it("should return valid URI unchanged", () => {
      expect(getSafeRedirectUri("https://helvety.com")).toBe(
        "https://helvety.com"
      );
      expect(getSafeRedirectUri("http://localhost:3000")).toBe(
        "http://localhost:3000"
      );
    });

    it("should return null for invalid URI without default", () => {
      expect(getSafeRedirectUri("https://evil.com")).toBe(null);
      expect(getSafeRedirectUri(null)).toBe(null);
      expect(getSafeRedirectUri(undefined)).toBe(null);
    });

    it("should return default URI for invalid input", () => {
      expect(
        getSafeRedirectUri("https://evil.com", "https://helvety.com")
      ).toBe("https://helvety.com");
    });

    it("should return null if default is also null", () => {
      expect(getSafeRedirectUri("https://evil.com", null)).toBe(null);
    });
  });
});
