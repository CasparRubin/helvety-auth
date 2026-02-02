/**
 * Authentication Event Logger
 *
 * Provides structured logging for authentication and security events.
 * In production, logs are formatted as JSON for easy parsing by log aggregation services.
 * In development, logs are formatted for human readability.
 *
 * IMPORTANT: Never log sensitive data like passwords, tokens, or full credentials.
 */

/**
 * Authentication event types
 */
export type AuthEvent =
  | "login_started"
  | "login_success"
  | "login_failed"
  | "logout"
  | "session_refresh"
  | "session_expired"
  | "encryption_setup_started"
  | "encryption_setup_success"
  | "encryption_setup_failed"
  | "encryption_unlock"
  | "encryption_lock"
  | "encryption_failed"
  | "passkey_registration_started"
  | "passkey_registration_success"
  | "passkey_registration_failed"
  | "passkey_auth_started"
  | "passkey_auth_success"
  | "passkey_auth_failed"
  | "magic_link_sent"
  | "magic_link_failed"
  | "rate_limit_exceeded"
  | "csrf_validation_failed"
  | "redirect_blocked";

/**
 * Log severity levels
 */
export type LogLevel = "info" | "warn" | "error";

/**
 * Auth log entry structure
 */
export interface AuthLogEntry {
  timestamp: string;
  level: LogLevel;
  event: AuthEvent;
  userId?: string;
  metadata?: Record<string, unknown>;
  userAgent?: string;
  ip?: string;
}

/**
 * Map events to their default severity levels
 */
const EVENT_LEVELS: Record<AuthEvent, LogLevel> = {
  login_started: "info",
  login_success: "info",
  login_failed: "warn",
  logout: "info",
  session_refresh: "info",
  session_expired: "info",
  encryption_setup_started: "info",
  encryption_setup_success: "info",
  encryption_setup_failed: "warn",
  encryption_unlock: "info",
  encryption_lock: "info",
  encryption_failed: "warn",
  passkey_registration_started: "info",
  passkey_registration_success: "info",
  passkey_registration_failed: "warn",
  passkey_auth_started: "info",
  passkey_auth_success: "info",
  passkey_auth_failed: "warn",
  magic_link_sent: "info",
  magic_link_failed: "warn",
  rate_limit_exceeded: "warn",
  csrf_validation_failed: "error",
  redirect_blocked: "error",
};

/**
 * Sanitize metadata to remove sensitive information
 */
function sanitizeMetadata(
  metadata: Record<string, unknown>
): Record<string, unknown> {
  const sensitiveKeys = [
    "password",
    "token",
    "secret",
    "key",
    "credential",
    "authorization",
    "cookie",
  ];

  const sanitized: Record<string, unknown> = {};

  for (const [key, value] of Object.entries(metadata)) {
    const lowerKey = key.toLowerCase();
    const isSensitive = sensitiveKeys.some((sensitive) =>
      lowerKey.includes(sensitive)
    );

    if (isSensitive) {
      sanitized[key] = "[REDACTED]";
    } else if (typeof value === "object" && value !== null) {
      sanitized[key] = sanitizeMetadata(value as Record<string, unknown>);
    } else {
      sanitized[key] = value;
    }
  }

  return sanitized;
}

/**
 * Get the user agent from the browser (client-side only)
 */
function getUserAgent(): string | undefined {
  if (typeof navigator !== "undefined") {
    return navigator.userAgent;
  }
  return undefined;
}

/**
 * Log an authentication event
 *
 * @param event - The type of auth event
 * @param options - Optional additional data
 * @param options.userId - User ID if available (will be partially masked)
 * @param options.metadata - Additional context (sensitive data will be redacted)
 * @param options.ip - Client IP address
 * @param options.level - Override the default log level for this event
 *
 * @example
 * // Log a successful login
 * logAuthEvent("login_success", { userId: "user_123" });
 *
 * // Log a failed login with reason
 * logAuthEvent("login_failed", {
 *   metadata: { reason: "invalid_email" },
 *   ip: "192.168.1.1"
 * });
 *
 * // Log rate limiting
 * logAuthEvent("rate_limit_exceeded", {
 *   metadata: { endpoint: "/login", retryAfter: 60 },
 *   ip: clientIp
 * });
 */
export function logAuthEvent(
  event: AuthEvent,
  options: {
    userId?: string;
    metadata?: Record<string, unknown>;
    ip?: string;
    level?: LogLevel;
  } = {}
): void {
  const { userId, metadata, ip, level } = options;

  const logEntry: AuthLogEntry = {
    timestamp: new Date().toISOString(),
    level: level ?? EVENT_LEVELS[event],
    event,
  };

  // Add user ID (partially masked for privacy)
  if (userId) {
    logEntry.userId =
      userId.length > 8 ? `${userId.slice(0, 4)}...${userId.slice(-4)}` : userId;
  }

  // Add sanitized metadata
  if (metadata && Object.keys(metadata).length > 0) {
    logEntry.metadata = sanitizeMetadata(metadata);
  }

  // Add user agent (client-side only)
  const userAgent = getUserAgent();
  if (userAgent) {
    logEntry.userAgent = userAgent;
  }

  // Add IP (if provided)
  if (ip) {
    logEntry.ip = ip;
  }

  // Output the log
  if (process.env.NODE_ENV === "production") {
    // JSON format for log aggregation services
    const logFn =
      logEntry.level === "error"
        ? console.error
        : logEntry.level === "warn"
          ? console.warn
          : // eslint-disable-next-line no-console -- Logger module intentionally uses console.log
            console.log;
    logFn(JSON.stringify({ ...logEntry, source: "auth" }));
  } else {
    // Human-readable format for development
    const prefix = `[AUTH:${logEntry.level.toUpperCase()}]`;
    const message = `${prefix} ${event}`;
    const details = {
      ...(logEntry.userId && { userId: logEntry.userId }),
      ...(logEntry.metadata && { ...logEntry.metadata }),
      ...(logEntry.ip && { ip: logEntry.ip }),
    };

    if (Object.keys(details).length > 0) {
      // eslint-disable-next-line no-console -- Logger module intentionally uses console.log
      console.log(message, details);
    } else {
      // eslint-disable-next-line no-console -- Logger module intentionally uses console.log
      console.log(message);
    }
  }
}

/**
 * Create a logger instance bound to a specific user
 *
 * @param userId - The user ID to bind to all logs
 * @returns A logger function that includes the user ID
 */
export function createUserLogger(userId: string) {
  return (
    event: AuthEvent,
    options: Omit<Parameters<typeof logAuthEvent>[1], "userId"> = {}
  ) => {
    logAuthEvent(event, { ...options, userId });
  };
}
