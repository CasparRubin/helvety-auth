import { describe, it, expect } from "vitest";

import {
  AuthError,
  AuthErrorCode,
  AUTH_ERROR_MESSAGES,
  isAuthError,
  toAuthError,
  getErrorMessage,
  authSuccess,
  authFailure,
} from "@/lib/auth-errors";

describe("Auth Errors Module", () => {
  describe("AuthErrorCode", () => {
    it("should have all expected error codes", () => {
      expect(AuthErrorCode.INVALID_CREDENTIALS).toBe("invalid_credentials");
      expect(AuthErrorCode.SESSION_EXPIRED).toBe("session_expired");
      expect(AuthErrorCode.RATE_LIMITED).toBe("rate_limited");
      expect(AuthErrorCode.CSRF_INVALID).toBe("csrf_invalid");
      expect(AuthErrorCode.PASSKEY_FAILED).toBe("passkey_failed");
      expect(AuthErrorCode.PASSKEY_REGISTRATION_FAILED).toBe("passkey_registration_failed");
      expect(AuthErrorCode.PASSKEY_NOT_SUPPORTED).toBe("passkey_not_supported");
      expect(AuthErrorCode.PRF_NOT_SUPPORTED).toBe("prf_not_supported");
      expect(AuthErrorCode.ENCRYPTION_FAILED).toBe("encryption_failed");
      expect(AuthErrorCode.NETWORK_ERROR).toBe("network_error");
      expect(AuthErrorCode.USER_NOT_FOUND).toBe("user_not_found");
      expect(AuthErrorCode.UNAUTHORIZED).toBe("unauthorized");
      expect(AuthErrorCode.FORBIDDEN).toBe("forbidden");
      expect(AuthErrorCode.INVALID_REDIRECT).toBe("invalid_redirect");
      expect(AuthErrorCode.MAGIC_LINK_INVALID).toBe("magic_link_invalid");
      expect(AuthErrorCode.EMAIL_IN_USE).toBe("email_in_use");
      expect(AuthErrorCode.SERVER_ERROR).toBe("server_error");
    });
  });

  describe("AUTH_ERROR_MESSAGES", () => {
    it("should have a message for every error code", () => {
      const errorCodes = Object.values(AuthErrorCode);

      for (const code of errorCodes) {
        expect(AUTH_ERROR_MESSAGES[code]).toBeDefined();
        expect(typeof AUTH_ERROR_MESSAGES[code]).toBe("string");
        expect(AUTH_ERROR_MESSAGES[code].length).toBeGreaterThan(0);
      }
    });

    it("should have user-friendly messages (no internal details)", () => {
      // Messages should not contain technical jargon
      const messages = Object.values(AUTH_ERROR_MESSAGES);

      for (const message of messages) {
        expect(message).not.toMatch(/undefined/i);
        expect(message).not.toMatch(/null/i);
        expect(message).not.toMatch(/exception/i);
        expect(message).not.toMatch(/stack trace/i);
      }
    });
  });

  describe("AuthError class", () => {
    it("should create error with code and default message", () => {
      const error = new AuthError(AuthErrorCode.SESSION_EXPIRED);

      expect(error).toBeInstanceOf(Error);
      expect(error).toBeInstanceOf(AuthError);
      expect(error.code).toBe(AuthErrorCode.SESSION_EXPIRED);
      expect(error.message).toBe(AUTH_ERROR_MESSAGES[AuthErrorCode.SESSION_EXPIRED]);
      expect(error.userMessage).toBe(AUTH_ERROR_MESSAGES[AuthErrorCode.SESSION_EXPIRED]);
      expect(error.name).toBe("AuthError");
    });

    it("should allow custom message while keeping userMessage", () => {
      const error = new AuthError(
        AuthErrorCode.NETWORK_ERROR,
        "Connection timeout after 30s"
      );

      expect(error.message).toBe("Connection timeout after 30s");
      expect(error.userMessage).toBe(AUTH_ERROR_MESSAGES[AuthErrorCode.NETWORK_ERROR]);
    });

    it("should store cause error", () => {
      const cause = new Error("Original error");
      const error = new AuthError(AuthErrorCode.SERVER_ERROR, "Wrapped error", cause);

      expect(error.cause).toBe(cause);
    });

    it("should serialize to JSON correctly", () => {
      const error = new AuthError(
        AuthErrorCode.RATE_LIMITED,
        "Too many login attempts"
      );

      const json = error.toJSON();

      expect(json.code).toBe(AuthErrorCode.RATE_LIMITED);
      expect(json.message).toBe("Too many login attempts");
      expect(json.userMessage).toBe(AUTH_ERROR_MESSAGES[AuthErrorCode.RATE_LIMITED]);
    });
  });

  describe("isAuthError", () => {
    it("should return true for AuthError instances", () => {
      const error = new AuthError(AuthErrorCode.UNAUTHORIZED);
      expect(isAuthError(error)).toBe(true);
    });

    it("should return false for regular Error", () => {
      const error = new Error("Regular error");
      expect(isAuthError(error)).toBe(false);
    });

    it("should return false for non-error values", () => {
      expect(isAuthError(null)).toBe(false);
      expect(isAuthError(undefined)).toBe(false);
      expect(isAuthError("error string")).toBe(false);
      expect(isAuthError({ code: "some_code" })).toBe(false);
    });
  });

  describe("toAuthError", () => {
    it("should return AuthError unchanged", () => {
      const original = new AuthError(AuthErrorCode.FORBIDDEN);
      const result = toAuthError(original);

      expect(result).toBe(original);
    });

    it("should wrap regular Error", () => {
      const original = new Error("Something went wrong");
      const result = toAuthError(original);

      expect(result).toBeInstanceOf(AuthError);
      expect(result.code).toBe(AuthErrorCode.SERVER_ERROR);
      expect(result.message).toBe("Something went wrong");
      expect(result.cause).toBe(original);
    });

    it("should use custom default code", () => {
      const original = new Error("Network issue");
      const result = toAuthError(original, AuthErrorCode.NETWORK_ERROR);

      expect(result.code).toBe(AuthErrorCode.NETWORK_ERROR);
    });

    it("should handle string errors", () => {
      const result = toAuthError("Something bad happened");

      expect(result).toBeInstanceOf(AuthError);
      expect(result.message).toBe("Something bad happened");
    });

    it("should handle unknown values", () => {
      const result = toAuthError(42);

      expect(result).toBeInstanceOf(AuthError);
      expect(result.message).toBe("42");
    });
  });

  describe("getErrorMessage", () => {
    it("should return userMessage for AuthError", () => {
      const error = new AuthError(
        AuthErrorCode.CSRF_INVALID,
        "Technical: token mismatch"
      );

      const message = getErrorMessage(error);

      expect(message).toBe(AUTH_ERROR_MESSAGES[AuthErrorCode.CSRF_INVALID]);
      expect(message).not.toContain("Technical");
    });

    it("should return generic message for regular Error", () => {
      const error = new Error("Internal implementation detail");

      const message = getErrorMessage(error);

      expect(message).toBe(AUTH_ERROR_MESSAGES[AuthErrorCode.SERVER_ERROR]);
      expect(message).not.toContain("Internal");
    });

    it("should return generic message for non-error values", () => {
      expect(getErrorMessage(null)).toBe(AUTH_ERROR_MESSAGES[AuthErrorCode.SERVER_ERROR]);
      expect(getErrorMessage("string error")).toBe(AUTH_ERROR_MESSAGES[AuthErrorCode.SERVER_ERROR]);
    });
  });

  describe("authSuccess", () => {
    it("should create successful result", () => {
      const data = { userId: "123", email: "test@example.com" };
      const result = authSuccess(data);

      expect(result.success).toBe(true);
      if (result.success) {
        expect(result.data).toEqual(data);
      }
    });

    it("should handle different data types", () => {
      expect(authSuccess(null).success).toBe(true);
      expect(authSuccess(42).success).toBe(true);
      expect(authSuccess("string").success).toBe(true);
      expect(authSuccess([1, 2, 3]).success).toBe(true);
    });
  });

  describe("authFailure", () => {
    it("should create failed result with error", () => {
      const result = authFailure<{ userId: string }>(AuthErrorCode.USER_NOT_FOUND);

      expect(result.success).toBe(false);
      if (!result.success) {
        expect(result.error).toBeInstanceOf(AuthError);
        expect(result.error.code).toBe(AuthErrorCode.USER_NOT_FOUND);
      }
    });

    it("should allow custom message", () => {
      const result = authFailure<void>(
        AuthErrorCode.INVALID_CREDENTIALS,
        "Email not found in database"
      );

      if (!result.success) {
        expect(result.error.message).toBe("Email not found in database");
      }
    });
  });

  describe("helvety-auth specific error codes", () => {
    it("should have PASSKEY_REGISTRATION_FAILED error", () => {
      const error = new AuthError(AuthErrorCode.PASSKEY_REGISTRATION_FAILED);
      expect(error.userMessage).toContain("register passkey");
    });

    it("should have PRF_NOT_SUPPORTED error", () => {
      const error = new AuthError(AuthErrorCode.PRF_NOT_SUPPORTED);
      expect(error.userMessage).toContain("encryption");
    });

    it("should have MAGIC_LINK_INVALID error", () => {
      const error = new AuthError(AuthErrorCode.MAGIC_LINK_INVALID);
      expect(error.userMessage).toContain("link");
    });

    it("should have EMAIL_IN_USE error", () => {
      const error = new AuthError(AuthErrorCode.EMAIL_IN_USE);
      expect(error.userMessage).toContain("already exists");
    });
  });
});
