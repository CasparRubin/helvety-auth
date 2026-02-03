import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";

import {
  logAuthEvent,
  createUserLogger,
  type AuthEvent,
} from "@/lib/auth-logger";

describe("Auth Logger Module", () => {
  let consoleLogSpy: ReturnType<typeof vi.spyOn>;
  let consoleWarnSpy: ReturnType<typeof vi.spyOn>;
  let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    consoleLogSpy = vi.spyOn(console, "log").mockImplementation(() => {});
    consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
    consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  });

  afterEach(() => {
    consoleLogSpy.mockRestore();
    consoleWarnSpy.mockRestore();
    consoleErrorSpy.mockRestore();
    vi.unstubAllEnvs();
  });

  describe("logAuthEvent", () => {
    it("should log events in development mode", () => {
      vi.stubEnv("NODE_ENV", "development");

      logAuthEvent("login_success");

      expect(consoleLogSpy).toHaveBeenCalled();
      const logCall = consoleLogSpy.mock.calls[0];
      expect(logCall?.[0]).toContain("[AUTH:INFO]");
      expect(logCall?.[0]).toContain("login_success");
    });

    it("should log events as JSON in production mode", () => {
      vi.stubEnv("NODE_ENV", "production");

      logAuthEvent("login_success", { userId: "user-123" });

      expect(consoleLogSpy).toHaveBeenCalled();
      const logCall = consoleLogSpy.mock.calls[0];
      const parsedLog = JSON.parse(logCall?.[0] as string);

      expect(parsedLog.event).toBe("login_success");
      expect(parsedLog.source).toBe("auth");
      expect(parsedLog.timestamp).toBeDefined();
    });

    it("should partially mask userId for privacy", () => {
      vi.stubEnv("NODE_ENV", "production");

      logAuthEvent("login_success", { userId: "user-12345678" });

      const logCall = consoleLogSpy.mock.calls[0];
      const parsedLog = JSON.parse(logCall?.[0] as string);

      expect(parsedLog.userId).toBe("user...5678");
    });

    it("should not mask short userId", () => {
      vi.stubEnv("NODE_ENV", "production");

      logAuthEvent("login_success", { userId: "short" });

      const logCall = consoleLogSpy.mock.calls[0];
      const parsedLog = JSON.parse(logCall?.[0] as string);

      expect(parsedLog.userId).toBe("short");
    });

    it("should include metadata in log", () => {
      vi.stubEnv("NODE_ENV", "production");

      logAuthEvent("rate_limit_exceeded", {
        metadata: { endpoint: "/login", retryAfter: 60 },
      });

      const logCall = consoleWarnSpy.mock.calls[0];
      const parsedLog = JSON.parse(logCall?.[0] as string);

      expect(parsedLog.metadata.endpoint).toBe("/login");
      expect(parsedLog.metadata.retryAfter).toBe(60);
    });

    it("should include IP address when provided", () => {
      vi.stubEnv("NODE_ENV", "production");

      logAuthEvent("login_failed", { ip: "192.168.1.1" });

      const logCall = consoleWarnSpy.mock.calls[0];
      const parsedLog = JSON.parse(logCall?.[0] as string);

      expect(parsedLog.ip).toBe("192.168.1.1");
    });

    describe("log levels", () => {
      beforeEach(() => {
        vi.stubEnv("NODE_ENV", "production");
      });

      it("should use info level for success events", () => {
        const infoEvents: AuthEvent[] = [
          "login_started",
          "login_success",
          "logout",
          "session_refresh",
          "session_expired",
          "encryption_setup_started",
          "encryption_setup_success",
          "encryption_unlock",
          "encryption_lock",
          "passkey_registration_started",
          "passkey_registration_success",
          "passkey_auth_started",
          "passkey_auth_success",
          "magic_link_sent",
        ];

        for (const event of infoEvents) {
          consoleLogSpy.mockClear();
          logAuthEvent(event);
          expect(consoleLogSpy).toHaveBeenCalled();
        }
      });

      it("should use warn level for failure events", () => {
        const warnEvents: AuthEvent[] = [
          "login_failed",
          "encryption_setup_failed",
          "encryption_failed",
          "passkey_registration_failed",
          "passkey_auth_failed",
          "magic_link_failed",
          "rate_limit_exceeded",
        ];

        for (const event of warnEvents) {
          consoleWarnSpy.mockClear();
          logAuthEvent(event);
          expect(consoleWarnSpy).toHaveBeenCalled();
        }
      });

      it("should use error level for security events", () => {
        const errorEvents: AuthEvent[] = [
          "csrf_validation_failed",
          "redirect_blocked",
        ];

        for (const event of errorEvents) {
          consoleErrorSpy.mockClear();
          logAuthEvent(event);
          expect(consoleErrorSpy).toHaveBeenCalled();
        }
      });

      it("should allow overriding log level", () => {
        logAuthEvent("login_success", { level: "error" });

        expect(consoleErrorSpy).toHaveBeenCalled();
        expect(consoleLogSpy).not.toHaveBeenCalled();
      });
    });

    describe("sensitive data redaction", () => {
      beforeEach(() => {
        vi.stubEnv("NODE_ENV", "production");
      });

      it("should redact password in metadata", () => {
        logAuthEvent("login_failed", {
          metadata: { password: "secret123", email: "test@example.com" },
        });

        const logCall = consoleWarnSpy.mock.calls[0];
        const parsedLog = JSON.parse(logCall?.[0] as string);

        expect(parsedLog.metadata.password).toBe("[REDACTED]");
        expect(parsedLog.metadata.email).toBe("test@example.com");
      });

      it("should redact token in metadata", () => {
        logAuthEvent("session_refresh", {
          metadata: { accessToken: "abc123", refreshToken: "xyz789" },
        });

        const logCall = consoleLogSpy.mock.calls[0];
        const parsedLog = JSON.parse(logCall?.[0] as string);

        expect(parsedLog.metadata.accessToken).toBe("[REDACTED]");
        expect(parsedLog.metadata.refreshToken).toBe("[REDACTED]");
      });

      it("should redact credential in metadata", () => {
        logAuthEvent("passkey_auth_success", {
          metadata: { credentialId: "cred-123", username: "user" },
        });

        const logCall = consoleLogSpy.mock.calls[0];
        const parsedLog = JSON.parse(logCall?.[0] as string);

        expect(parsedLog.metadata.credentialId).toBe("[REDACTED]");
        expect(parsedLog.metadata.username).toBe("user");
      });

      it("should redact nested sensitive data", () => {
        logAuthEvent("login_failed", {
          metadata: {
            user: { email: "test@example.com", passwordHash: "hashed" },
          },
        });

        const logCall = consoleWarnSpy.mock.calls[0];
        const parsedLog = JSON.parse(logCall?.[0] as string);

        expect(parsedLog.metadata.user.passwordHash).toBe("[REDACTED]");
        expect(parsedLog.metadata.user.email).toBe("test@example.com");
      });
    });
  });

  describe("createUserLogger", () => {
    it("should create logger bound to user", () => {
      vi.stubEnv("NODE_ENV", "production");

      const userLogger = createUserLogger("user-12345678");
      userLogger("login_success");

      const logCall = consoleLogSpy.mock.calls[0];
      const parsedLog = JSON.parse(logCall?.[0] as string);

      expect(parsedLog.userId).toBe("user...5678");
    });

    it("should allow additional options", () => {
      vi.stubEnv("NODE_ENV", "production");

      const userLogger = createUserLogger("user-123");
      userLogger("encryption_unlock", {
        metadata: { method: "passkey" },
        ip: "10.0.0.1",
      });

      const logCall = consoleLogSpy.mock.calls[0];
      const parsedLog = JSON.parse(logCall?.[0] as string);

      expect(parsedLog.metadata.method).toBe("passkey");
      expect(parsedLog.ip).toBe("10.0.0.1");
    });
  });
});
