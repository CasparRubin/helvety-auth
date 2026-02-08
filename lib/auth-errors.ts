/**
 * Authentication Error Types
 *
 * Provides standardized error codes and classes for authentication operations.
 * Use these for consistent error handling and user-facing messages across the app.
 */

/**
 * Authentication error codes
 */
export enum AuthErrorCode {
  /** Invalid email or credentials */
  INVALID_CREDENTIALS = "invalid_credentials",
  /** User session has expired */
  SESSION_EXPIRED = "session_expired",
  /** Too many requests, rate limited */
  RATE_LIMITED = "rate_limited",
  /** CSRF token validation failed */
  CSRF_INVALID = "csrf_invalid",
  /** Passkey authentication failed */
  PASSKEY_FAILED = "passkey_failed",
  /** Passkey registration failed */
  PASSKEY_REGISTRATION_FAILED = "passkey_registration_failed",
  /** Passkey not supported by browser */
  PASSKEY_NOT_SUPPORTED = "passkey_not_supported",
  /** PRF extension not supported */
  PRF_NOT_SUPPORTED = "prf_not_supported",
  /** Encryption operation failed */
  ENCRYPTION_FAILED = "encryption_failed",
  /** Network or connectivity error */
  NETWORK_ERROR = "network_error",
  /** User not found */
  USER_NOT_FOUND = "user_not_found",
  /** User is not authenticated */
  UNAUTHORIZED = "unauthorized",
  /** User lacks required permissions */
  FORBIDDEN = "forbidden",
  /** Invalid redirect URI */
  INVALID_REDIRECT = "invalid_redirect",
  /** Verification code expired or invalid */
  OTP_INVALID = "otp_invalid",
  /** Email already in use */
  EMAIL_IN_USE = "email_in_use",
  /** Generic server error */
  SERVER_ERROR = "server_error",
}

/**
 * User-facing error messages
 *
 * These messages are safe to display to users.
 * They don't reveal sensitive implementation details.
 */
export const AUTH_ERROR_MESSAGES: Record<AuthErrorCode, string> = {
  [AuthErrorCode.INVALID_CREDENTIALS]:
    "Invalid email or password. Please try again.",
  [AuthErrorCode.SESSION_EXPIRED]:
    "Your session has expired. Please sign in again.",
  [AuthErrorCode.RATE_LIMITED]:
    "Too many attempts. Please wait a moment before trying again.",
  [AuthErrorCode.CSRF_INVALID]:
    "Security validation failed. Please refresh the page and try again.",
  [AuthErrorCode.PASSKEY_FAILED]:
    "Passkey authentication failed. Please try again.",
  [AuthErrorCode.PASSKEY_REGISTRATION_FAILED]:
    "Failed to register passkey. Please try again.",
  [AuthErrorCode.PASSKEY_NOT_SUPPORTED]:
    "Your browser doesn't support passkeys. Please use a modern browser.",
  [AuthErrorCode.PRF_NOT_SUPPORTED]:
    "Your browser doesn't support secure encryption. Please use Chrome 128+, Safari 18+, or Edge 128+.",
  [AuthErrorCode.ENCRYPTION_FAILED]:
    "Failed to set up encryption. Please try again.",
  [AuthErrorCode.NETWORK_ERROR]:
    "Unable to connect. Please check your internet connection.",
  [AuthErrorCode.USER_NOT_FOUND]: "No account found with this email address.",
  [AuthErrorCode.UNAUTHORIZED]: "Please sign in to continue.",
  [AuthErrorCode.FORBIDDEN]:
    "You don't have permission to perform this action.",
  [AuthErrorCode.INVALID_REDIRECT]: "Invalid redirect destination.",
  [AuthErrorCode.OTP_INVALID]:
    "This verification code has expired or is invalid. Please request a new one.",
  [AuthErrorCode.EMAIL_IN_USE]:
    "An account with this email already exists. Please sign in instead.",
  [AuthErrorCode.SERVER_ERROR]: "Something went wrong. Please try again later.",
};

/**
 * Custom error class for authentication errors
 *
 * @example
 * throw new AuthError(AuthErrorCode.SESSION_EXPIRED, "Token expired");
 *
 * @example
 * try {
 *   await authenticate();
 * } catch (error) {
 *   if (error instanceof AuthError) {
 *     // Handle known auth error
 *     showToast(error.userMessage);
 *   }
 * }
 */
export class AuthError extends Error {
  /** Error code for programmatic handling */
  public readonly code: AuthErrorCode;

  /** User-friendly message safe to display */
  public readonly userMessage: string;

  /** Original error that caused this error */
  public override readonly cause?: Error;

  constructor(code: AuthErrorCode, message?: string, cause?: Error) {
    super(message ?? AUTH_ERROR_MESSAGES[code]);
    this.name = "AuthError";
    this.code = code;
    this.userMessage = AUTH_ERROR_MESSAGES[code];
    this.cause = cause;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, AuthError);
    }
  }

  /**
   * Convert to a plain object for serialization
   */
  toJSON(): { code: AuthErrorCode; message: string; userMessage: string } {
    return {
      code: this.code,
      message: this.message,
      userMessage: this.userMessage,
    };
  }
}

/**
 * Check if an error is an AuthError
 */
export function isAuthError(error: unknown): error is AuthError {
  return error instanceof AuthError;
}

/**
 * Convert any error to an AuthError
 *
 * Useful for wrapping unknown errors in a consistent format.
 *
 * @param error - Any error to convert
 * @param defaultCode - Code to use if error is not an AuthError
 * @returns An AuthError instance
 */
export function toAuthError(
  error: unknown,
  defaultCode: AuthErrorCode = AuthErrorCode.SERVER_ERROR
): AuthError {
  if (error instanceof AuthError) {
    return error;
  }

  if (error instanceof Error) {
    return new AuthError(defaultCode, error.message, error);
  }

  return new AuthError(defaultCode, String(error));
}

/**
 * Get user-friendly message for any error
 *
 * @param error - Any error
 * @returns A safe message to display to users
 */
export function getErrorMessage(error: unknown): string {
  if (error instanceof AuthError) {
    return error.userMessage;
  }

  // Don't expose internal error messages to users
  return AUTH_ERROR_MESSAGES[AuthErrorCode.SERVER_ERROR];
}

/**
 * Result type for auth operations
 *
 * Use this for operations that can fail gracefully.
 */
export type AuthResult<T> =
  | { success: true; data: T }
  | { success: false; error: AuthError };

/**
 * Create a successful auth result
 */
export function authSuccess<T>(data: T): AuthResult<T> {
  return { success: true, data };
}

/**
 * Create a failed auth result
 */
export function authFailure<T>(
  code: AuthErrorCode,
  message?: string
): AuthResult<T> {
  return { success: false, error: new AuthError(code, message) };
}
