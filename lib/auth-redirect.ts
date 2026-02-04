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
 * Get the login URL for redirecting to the auth service.
 * Includes the current URL as redirect_uri parameter for post-login return.
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
    // Server-side: use app URL from environment
    redirectUri = process.env.NEXT_PUBLIC_APP_URL ?? "https://helvety.com";
  }

  return `${authBase}/login?redirect_uri=${encodeURIComponent(redirectUri)}`;
}

/**
 * Get the logout URL for signing out via the auth service.
 * Includes an optional redirect_uri parameter for post-logout navigation.
 */
export function getLogoutUrl(redirectUri?: string): string {
  const authBase = getAuthBaseUrl();

  // Use provided URI or app URL from environment
  const redirect =
    redirectUri ?? process.env.NEXT_PUBLIC_APP_URL ?? "https://helvety.com";

  return `${authBase}/logout?redirect_uri=${encodeURIComponent(redirect)}`;
}

/**
 * Redirect to the login page.
 * Call this from client components when user needs to authenticate.
 * Uses window.location.href to navigate to the auth service.
 */
export function redirectToLogin(currentUrl?: string): void {
  if (typeof window !== "undefined") {
    window.location.href = getLoginUrl(currentUrl);
  }
}

/**
 * Redirect to logout.
 * Call this from client components to sign out.
 * Navigates to the auth service logout endpoint.
 */
export function redirectToLogout(redirectUri?: string): void {
  if (typeof window !== "undefined") {
    window.location.href = getLogoutUrl(redirectUri);
  }
}
