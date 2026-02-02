/**
 * Centralized logging utility
 *
 * LOGGING STRATEGY:
 * - Development: All log levels (log, warn, info, debug, error) are output to console
 * - Production: Only error logs are output (with sanitization), other levels are suppressed
 *
 * RATIONALE:
 * - Errors are critical and need to be logged in production for monitoring/debugging
 * - Other log levels (log, warn, info, debug) are primarily for development debugging
 * - Production error logs are sanitized to prevent exposure of sensitive data
 * - This reduces production log noise while maintaining error visibility
 *
 * SECURITY NOTES (for auditors):
 * - Sensitive keys (passwords, tokens, secrets) are automatically redacted from logged objects
 * - String messages may contain identifiers (user IDs, entity IDs) for debugging
 * - These identifiers are UUIDs/internal IDs, not personal data (no emails, names, etc.)
 * - Info/warn/debug logs containing identifiers are suppressed in production
 * - Only error logs are output in production, and only for critical debugging
 * - Access to production logs should be restricted at the infrastructure level
 *   (e.g., Vercel logs, cloud provider logging services)
 */

const isDevelopment = process.env.NODE_ENV === "development";

/**
 * Error tracking service interface
 * Allows integration with services like Sentry, LogRocket, etc.
 */
interface ErrorTrackingService {
  captureException(error: Error, context?: Record<string, unknown>): void;
  captureMessage(
    message: string,
    level?: "error" | "warning" | "info",
    context?: Record<string, unknown>
  ): void;
}

/**
 * Safe internal logger for error tracking failures
 * Uses console directly to avoid circular dependencies when error tracking itself fails
 * This is only used internally and never exposed to prevent bypassing the main logger
 * @param {...any} args
 */
function safeInternalErrorLog(...args: unknown[]): void {
  // Direct console.error is necessary here to prevent infinite loops
  // if the error tracking service fails and tries to log through logger.error
  if (isDevelopment) {
    console.error("[Logger Internal Error]", ...args);
  } else {
    // In production, still log but with a clear marker
    console.error("[Logger Internal Error]", ...args);
  }
}

/**
 * Error tracking service implementation
 * Currently a no-op, but can be extended to integrate with actual services
 */
class ErrorTracker implements ErrorTrackingService {
  private service: ErrorTrackingService | null = null;

  /**
   * Initialize error tracking service
   * Call this method to set up integration with services like Sentry
   * @param service
   */
  init(service: ErrorTrackingService): void {
    this.service = service;
  }

  captureException(error: Error, context?: Record<string, unknown>): void {
    if (this.service) {
      try {
        this.service.captureException(error, context);
      } catch (e) {
        // Use safe internal logger to avoid circular dependency
        // Cannot use logger.error here as it would call errorTracker again
        safeInternalErrorLog("Error tracking failed:", e);
      }
    }
  }

  captureMessage(
    message: string,
    level: "error" | "warning" | "info" = "error",
    context?: Record<string, unknown>
  ): void {
    if (this.service) {
      try {
        this.service.captureMessage(message, level, context);
      } catch (e) {
        // Use safe internal logger to avoid circular dependency
        // Cannot use logger.error here as it would call errorTracker again
        safeInternalErrorLog("Error tracking failed:", e);
      }
    }
  }
}

/**
 * Global error tracker instance
 * Initialize with: errorTracker.init(yourService)
 */
export const errorTracker = new ErrorTracker();

/**
 * Type guard to check if a value is a record-like object
 */
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/**
 * Sensitive keys that should be redacted from logs
 */
const SENSITIVE_KEYS = new Set([
  "password",
  "secret",
  "token",
  "key",
  "api_key",
  "apikey",
  "auth",
  "authorization",
  "credential",
  "private",
]);

/**
 * Check if a key is sensitive and should be redacted
 */
function isSensitiveKey(key: string): boolean {
  const lowerKey = key.toLowerCase();
  return (
    SENSITIVE_KEYS.has(lowerKey) ||
    Array.from(SENSITIVE_KEYS).some((sensitive) => lowerKey.includes(sensitive))
  );
}

/**
 * Recursively sanitizes an object by removing sensitive keys
 * Handles nested objects and arrays
 */
function sanitizeObject(
  obj: Record<string, unknown>,
  depth: number = 0
): Record<string, unknown> {
  // Prevent infinite recursion (max depth of 10)
  if (depth > 10) {
    return {};
  }

  const sanitized: Record<string, unknown> = {};

  for (const key in obj) {
    if (Object.prototype.hasOwnProperty.call(obj, key)) {
      // Skip sensitive keys
      if (isSensitiveKey(key)) {
        continue;
      }

      const value = obj[key];

      // Skip functions - they cannot be serialized and may cause errors
      if (typeof value === "function") {
        continue;
      }

      // Recursively sanitize nested objects
      if (isRecord(value)) {
        sanitized[key] = sanitizeObject(value, depth + 1);
      }
      // Recursively sanitize arrays containing objects
      else if (Array.isArray(value)) {
        sanitized[key] = value
          .filter((item) => typeof item !== "function") // Remove functions from arrays
          .map((item) => {
            if (isRecord(item)) {
              return sanitizeObject(item, depth + 1);
            }
            return item;
          });
      }
      // Keep primitive values and other types as-is
      else {
        sanitized[key] = value;
      }
    }
  }

  return sanitized;
}

export const logger = {
  log: (...args: unknown[]): void => {
    if (isDevelopment) {
      // eslint-disable-next-line no-console -- Intentional: logger utility for development debugging
      console.log(...args);
    }
  },

  error: (...args: unknown[]): void => {
    if (isDevelopment) {
      console.error(...args);
    } else {
      // In production, sanitize errors before logging
      // Uses recursive sanitization to handle nested objects and arrays
      const sanitizedArgs = args.map((arg) => {
        if (isRecord(arg)) {
          return sanitizeObject(arg);
        }
        // Handle arrays that might contain sensitive objects
        if (Array.isArray(arg)) {
          return arg.map((item) => {
            if (isRecord(item)) {
              return sanitizeObject(item);
            }
            return item;
          });
        }
        return arg;
      });
      console.error(...sanitizedArgs);
    }

    // Send to error tracking service (works in both dev and prod)
    const firstArg = args[0];
    if (firstArg instanceof Error) {
      const context =
        args.length > 1 && isRecord(args[1])
          ? sanitizeObject(args[1])
          : undefined;
      errorTracker.captureException(firstArg, context);
    } else if (typeof firstArg === "string") {
      const context =
        args.length > 1 && isRecord(args[1])
          ? sanitizeObject(args[1])
          : undefined;
      errorTracker.captureMessage(firstArg, "error", context);
    }
  },

  warn: (...args: unknown[]): void => {
    if (isDevelopment) {
      console.warn(...args);
    }
  },

  info: (...args: unknown[]): void => {
    if (isDevelopment) {
      // eslint-disable-next-line no-console -- Intentional: logger utility for development debugging
      console.info(...args);
    }
  },

  debug: (...args: unknown[]): void => {
    if (isDevelopment) {
      // eslint-disable-next-line no-console -- Intentional: logger utility for development debugging
      console.debug(...args);
    }
  },
};
