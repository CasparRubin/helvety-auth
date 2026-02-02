import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

import { logger } from "./logger";

/**
 * Merges Tailwind CSS class names, resolving conflicts intelligently.
 */
export function cn(...inputs: ClassValue[]): string {
  return twMerge(clsx(inputs));
}

/**
 * Generates a secure random ID using crypto.randomUUID() when available,
 * or falls back to a cryptographically secure alternative.
 * Throws an error if no secure random number generator is available.
 */
export function generateSecureId(): string {
  // Use crypto.randomUUID() if available (browser/Node.js 14.17.0+)
  if (typeof crypto !== "undefined" && crypto.randomUUID) {
    try {
      return crypto.randomUUID();
    } catch (error) {
      // If randomUUID fails, fall through to getRandomValues
      if (process.env.NODE_ENV === "development") {
        logger.warn(
          "crypto.randomUUID() failed, falling back to getRandomValues:",
          error
        );
      }
    }
  }

  // Fallback for environments without crypto.randomUUID
  // Use crypto.getRandomValues() which is widely available
  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    try {
      const array = new Uint8Array(16);
      crypto.getRandomValues(array);
      // Convert to hex string (32 characters)
      const hexString = Array.from(array)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");
      // Format as UUID-like string: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      return [
        hexString.slice(0, 8),
        hexString.slice(8, 12),
        hexString.slice(12, 16),
        hexString.slice(16, 20),
        hexString.slice(20, 32),
      ].join("-");
    } catch (error) {
      // If getRandomValues fails, throw error in production
      if (process.env.NODE_ENV === "production") {
        throw new Error(
          "Secure random number generation is not available in this environment"
        );
      }
      // In development, log warning and continue to last resort
      logger.warn("crypto.getRandomValues() failed:", error);
    }
  }

  // Last resort fallback (should rarely be needed in modern environments)
  // Only use in development - throw error in production for security
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "Secure random number generation is not available. " +
        "This environment does not support crypto.randomUUID() or crypto.getRandomValues()."
    );
  }

  // Development fallback with warning
  logger.warn(
    "Using insecure fallback for ID generation. " +
      "This should only happen in development environments without proper crypto support."
  );
  const timestamp = Date.now().toString(36);
  const randomPart = Math.random().toString(36).substring(2, 15);
  return `${timestamp}-${randomPart}`;
}
