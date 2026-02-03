/**
 * Auth redirect utilities for centralized authentication
 *
 * These functions handle redirects to/from the centralized auth service
 * at auth.helvety.com for login and logout flows.
 */

/**
 * Get the base URL for the auth service
 */
function getAuthBaseUrl(): string {
  if (process.env.NODE_ENV === "development") {
    return "http://localhost:3002";
  }
  return "https://auth.helvety.com";
}

/**
 * Get the login URL for redirecting to the auth service
 *
 * @param currentUrl - The current URL to redirect back to after login
 * @returns The login URL with redirect_uri parameter
 */
export function getLoginUrl(currentUrl?: string): string {
  const authBase = getAuthBaseUrl();

  // Use provided URL or construct from window.location
  let redirectUri: string;
  if (currentUrl) {
    redirectUri = currentUrl;
  } else if (typeof window !== "undefined") {
    redirectUri = window.location.href;
  } else {
    // Server-side fallback
    redirectUri =
      process.env.NODE_ENV === "development"
        ? "http://localhost:3000"
        : "https://helvety.com";
  }

  return `${authBase}/login?redirect_uri=${encodeURIComponent(redirectUri)}`;
}

/**
 * Get the logout URL for signing out via the auth service
 *
 * @param redirectUri - Optional URL to redirect to after logout
 * @returns The logout URL with optional redirect_uri parameter
 */
export function getLogoutUrl(redirectUri?: string): string {
  const authBase = getAuthBaseUrl();

  const redirect =
    redirectUri ??
    (process.env.NODE_ENV === "development"
      ? "http://localhost:3000"
      : "https://helvety.com");

  return `${authBase}/logout?redirect_uri=${encodeURIComponent(redirect)}`;
}

/**
 * Redirect to the login page
 * Call this from client components when user needs to authenticate
 *
 * @param currentUrl - Optional current URL (defaults to window.location.href)
 */
export function redirectToLogin(currentUrl?: string): void {
  if (typeof window !== "undefined") {
    window.location.href = getLoginUrl(currentUrl);
  }
}

/**
 * Redirect to logout
 * Call this from client components to sign out
 *
 * @param redirectUri - Optional URL to redirect to after logout
 */
export function redirectToLogout(redirectUri?: string): void {
  if (typeof window !== "undefined") {
    window.location.href = getLogoutUrl(redirectUri);
  }
}
