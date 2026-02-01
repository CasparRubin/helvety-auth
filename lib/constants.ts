/**
 * Toast notification durations (in milliseconds)
 */
export const TOAST_DURATIONS = {
  /** Success messages */
  SUCCESS: 5000,
  /** Informational messages */
  INFO: 4000,
  /** Error messages (auto-dismiss) */
  ERROR: 8000,
  /** Critical errors (manual dismiss) */
  ERROR_CRITICAL: Infinity,
} as const;
