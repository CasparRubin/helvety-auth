import { z } from "zod";

import { logger } from "./logger";

/**
 * Validates that a Supabase key appears to be an anon key (not service role key)
 * Security: Prevents accidentally using service role key in client-side code
 *
 * Note: This is a best-effort check. Supabase supports multiple key formats:
 * - Legacy JWT format (starts with "eyJ")
 * - New format (starts with "sb_" or similar)
 *
 * This validation is intentionally lenient to avoid breaking valid setups while
 * still catching obvious mistakes (like empty keys or obviously wrong values).
 */
function validateAnonKey(key: string): boolean {
  if (!key || typeof key !== "string") {
    return false;
  }

  const trimmedKey = key.trim();

  // Must not be empty
  if (trimmedKey.length === 0) {
    return false;
  }

  // Check minimum reasonable length
  // Supabase keys are typically 20+ characters (new format) or 100+ (JWT format)
  if (trimmedKey.length < 10) {
    return false; // Too short to be a valid Supabase key
  }

  // Check for known Supabase key formats
  const isNewFormat =
    trimmedKey.startsWith("sb_") || trimmedKey.startsWith("eyJ");
  const isJWTFormat =
    trimmedKey.includes(".") && trimmedKey.split(".").length >= 2;

  // Accept if it's either:
  // 1. New Supabase format (sb_*)
  // 2. JWT format (has dots and at least 2 parts)
  // 3. Or just long enough to be reasonable (lenient fallback)
  if (isNewFormat || isJWTFormat || trimmedKey.length >= 20) {
    // If it's JWT format, validate structure
    if (isJWTFormat) {
      const parts = trimmedKey.split(".");
      // Each part should be non-empty
      if (parts.some((part) => part.length === 0)) {
        return false;
      }

      // If it's JWT but doesn't start with "eyJ", warn (might be valid but unusual)
      if (!trimmedKey.startsWith("eyJ")) {
        logger.warn(
          "WARNING: NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY appears to be JWT format but doesn't start with 'eyJ'. " +
            "Ensure this is the anon/public key, not the service role key."
        );
      }
    }

    return true;
  }

  // If it doesn't match any known format and is short, reject it
  return false;
}

/**
 * Environment variable schema validation
 */
const envSchema = z.object({
  NEXT_PUBLIC_SUPABASE_PROJECT_URL: z
    .string()
    .url("NEXT_PUBLIC_SUPABASE_PROJECT_URL must be a valid URL")
    .refine((url) => url.startsWith("https://") || url.startsWith("http://"), {
      message:
        "NEXT_PUBLIC_SUPABASE_PROJECT_URL must start with http:// or https://",
    }),
  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY: z
    .string()
    .min(1, "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY is required")
    .refine((key) => validateAnonKey(key), {
      message:
        "NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY must be a valid Supabase anon/publishable key. " +
        "WARNING: Do NOT use the service role key here - it should only be used server-side and never exposed to the client. " +
        "Get your anon/publishable key from: Supabase Dashboard > Project Settings > API > Project API keys > anon/public key or Publishable key",
    }),
});

/** Validated environment variable types */
type Env = z.infer<typeof envSchema>;

let validatedEnv: Env | null = null;
let hasLoggedValidationSuccess = false;

/**
 * Validates and returns environment variables
 * Throws an error if validation fails
 *
 * Security: This function validates that only safe environment variables are used.
 * In development, it provides helpful warnings and error messages.
 */
export function getValidatedEnv(): Env {
  if (validatedEnv) {
    return validatedEnv;
  }

  const rawEnv = {
    NEXT_PUBLIC_SUPABASE_PROJECT_URL:
      process.env.NEXT_PUBLIC_SUPABASE_PROJECT_URL?.trim() ?? "",
    NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY:
      process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY?.trim() ?? "",
  };

  // Development: Check if variables are missing before validation
  if (process.env.NODE_ENV === "development") {
    if (!rawEnv.NEXT_PUBLIC_SUPABASE_PROJECT_URL) {
      logger.warn(
        "⚠️  NEXT_PUBLIC_SUPABASE_PROJECT_URL is not set. " +
          "Please create a .env.local file with your Supabase project URL."
      );
    }
    if (!rawEnv.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY) {
      logger.warn(
        "⚠️  NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY is not set. " +
          "Please create a .env.local file with your Supabase publishable key."
      );
    }
  }

  const result = envSchema.safeParse(rawEnv);

  if (!result.success) {
    const errors = result.error.issues
      .map((err) => {
        const path = err.path.join(".");
        return `  - ${path}: ${err.message}`;
      })
      .join("\n");

    const errorMessage =
      `Invalid environment variables:\n${errors}\n\n` +
      "Please check your .env.local file and ensure all required variables are set.\n" +
      "See env.template for an example.\n\n" +
      "Security Note: NEXT_PUBLIC_ variables are exposed to the client. " +
      "Only use safe, public keys (anon/publishable keys) in these variables. " +
      "Never use service role keys or other sensitive credentials.";

    throw new Error(errorMessage);
  }

  validatedEnv = result.data;
  return validatedEnv;
}

/**
 * Gets Supabase URL with validation
 * Security: This URL is safe to expose to the client as it's a public API endpoint
 */
export function getSupabaseUrl(): string {
  const env = getValidatedEnv();
  return env.NEXT_PUBLIC_SUPABASE_PROJECT_URL;
}

/**
 * Gets Supabase publishable key with validation
 * Security: Ensures the key is an anon key format (not service role key)
 *
 * WARNING: This key will be exposed to the client. Only use the anon key here.
 * Never use the service role key in NEXT_PUBLIC_ environment variables.
 */
export function getSupabaseKey(): string {
  const env = getValidatedEnv();
  const key = env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  // Additional runtime check (in case validation was bypassed)
  if (!validateAnonKey(key)) {
    const errorMessage =
      "SECURITY WARNING: NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY does not appear to be a valid anon key. " +
      "Ensure you are using the anon/public key, not the service role key. " +
      "Service role keys should NEVER be exposed to the client.";

    logger.error(errorMessage);

    // In development, throw an error to prevent accidental deployment
    if (process.env.NODE_ENV === "development") {
      throw new Error(
        `${errorMessage}\n\n` +
          "This error is thrown in development to prevent security issues. " +
          "Please check your .env.local file and ensure you're using the correct key.\n" +
          "Get your anon/publishable key from: Supabase Dashboard > Project Settings > API > Project API keys"
      );
    }
  }

  // Development warning for common mistakes
  if (process.env.NODE_ENV === "development") {
    // Check for obvious service role key patterns (though format may vary)
    if (key.length > 200 && key.includes("service_role")) {
      logger.warn(
        "⚠️  WARNING: Your NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY appears to contain 'service_role'. " +
          "This is likely a service role key, which should NEVER be exposed to the client. " +
          "Please use the anon/publishable key instead."
      );
    }

    // Remind developers about security (only log once to avoid spam)
    if (key && validateAnonKey(key) && !hasLoggedValidationSuccess) {
      hasLoggedValidationSuccess = true;
    }
  }

  return key;
}
