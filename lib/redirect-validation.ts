/**
 * Redirect URI validation utilities
 *
 * Prevents open redirect vulnerabilities by validating redirect URIs
 * against a strict allowlist of trusted domains.
 */

/**
 * Allowed redirect URI patterns
 * Only these domains are permitted as redirect destinations
 *
 * Supports:
 * - helvety.com (root domain)
 * - Any subdomain of helvety.com (e.g., auth.helvety.com, store.helvety.com, pdf.helvety.com)
 * - localhost with any port (development)
 * - 127.0.0.1 with any port (development)
 */
const ALLOWED_REDIRECT_PATTERNS = [
  // Production: helvety.com and any subdomain (*.helvety.com)
  // Matches: helvety.com, auth.helvety.com, store.helvety.com, new-app.helvety.com, etc.
  /^https:\/\/([a-z0-9-]+\.)?helvety\.com(\/.*)?$/,
  // Development (localhost with any port)
  /^http:\/\/localhost(:\d+)?(\/.*)?$/,
  /^http:\/\/127\.0\.0\.1(:\d+)?(\/.*)?$/,
];

/**
 * Validates a redirect URI against the allowlist
 *
 * @param uri - The redirect URI to validate
 * @returns true if the URI is allowed, false otherwise
 */
export function isValidRedirectUri(uri: string | null | undefined): boolean {
  if (!uri) {
    return false;
  }

  try {
    // Ensure it's a valid URL
    const url = new URL(uri);

    // Block javascript: and data: protocols
    if (url.protocol !== "http:" && url.protocol !== "https:") {
      return false;
    }

    // Check against allowed patterns
    return ALLOWED_REDIRECT_PATTERNS.some((pattern) => pattern.test(uri));
  } catch {
    // Invalid URL
    return false;
  }
}

/**
 * Validates and returns a safe redirect URI
 *
 * @param uri - The redirect URI to validate
 * @param defaultUri - Default URI to return if validation fails (optional)
 * @returns The validated URI or the default URI
 */
export function getSafeRedirectUri(
  uri: string | null | undefined,
  defaultUri?: string | null
): string | null {
  if (isValidRedirectUri(uri)) {
    return uri!;
  }
  return defaultUri ?? null;
}

/**
 * Validates that a path is a safe relative path (for internal redirects)
 *
 * @param path - The path to validate
 * @returns true if the path is a safe relative path
 */
export function isValidRelativePath(path: string | null | undefined): boolean {
  if (!path) {
    return false;
  }

  // Must start with / but not // (protocol-relative URL)
  if (!path.startsWith("/") || path.startsWith("//")) {
    return false;
  }

  // Must not contain protocol indicators
  if (path.includes(":")) {
    return false;
  }

  return true;
}

/**
 * Gets a safe relative path, returning default if invalid
 *
 * @param path - The path to validate
 * @param defaultPath - Default path to return if validation fails
 * @returns The validated path or the default path
 */
export function getSafeRelativePath(
  path: string | null | undefined,
  defaultPath: string = "/"
): string {
  if (isValidRelativePath(path)) {
    return path!;
  }
  return defaultPath;
}
