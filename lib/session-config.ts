/**
 * Session Configuration
 *
 * Centralized configuration for session management across the app.
 */

export const SESSION_CONFIG = {
  /**
   * Maximum session age in milliseconds (24 hours)
   * After this time, the user must re-authenticate
   */
  maxAge: 24 * 60 * 60 * 1000,

  /**
   * Idle timeout in milliseconds (30 minutes)
   * User will be logged out after this period of inactivity
   */
  idleTimeout: 30 * 60 * 1000,

  /**
   * Session refresh threshold in milliseconds (5 minutes)
   * If session expires in less than this time, refresh it
   */
  refreshThreshold: 5 * 60 * 1000,

  /**
   * Activity check interval in milliseconds (1 minute)
   * How often to check for user activity
   */
  activityCheckInterval: 60 * 1000,

  /**
   * Key cache duration in milliseconds (24 hours)
   * How long encryption keys are cached in IndexedDB
   */
  keyCacheDuration: 24 * 60 * 60 * 1000,
} as const;

/**
 * Session configuration type
 */
export type SessionConfig = typeof SESSION_CONFIG;
