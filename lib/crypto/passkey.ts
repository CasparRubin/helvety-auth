/**
 * Passkey Module
 * Handles WebAuthn passkey registration and authentication
 *
 * This module provides the bridge between WebAuthn/passkeys and authentication.
 * It uses SimpleWebAuthn browser helpers.
 */

import { browserSupportsWebAuthn } from "@simplewebauthn/browser";

/**
 * Relying Party configuration
 */
export interface RPConfig {
  /** Domain name (e.g., 'localhost' for dev, 'helvety.com' for prod) */
  rpId: string;
  /** Human-readable name shown in passkey prompts */
  rpName: string;
  /** Origin URL (e.g., 'https://auth.helvety.com') */
  origin: string;
}

/**
 * Get RP config based on the current browser location
 *
 * IMPORTANT: For centralized auth, we use 'helvety.com' as the rpId in production.
 * This allows passkeys registered on auth.helvety.com to work across all subdomains
 * (pdf.helvety.com, store.helvety.com, etc.)
 */
export function getRPConfig(): RPConfig {
  const rpName = "Helvety";

  if (typeof window === "undefined") {
    // Server-side fallback (passkey operations should only happen client-side)
    return {
      rpId: "localhost",
      rpName,
      origin: "http://localhost:3002",
    };
  }

  // In production, use the root domain for cross-subdomain passkey sharing
  // In development, use localhost
  const isDev =
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1";

  return {
    rpId: isDev ? "localhost" : "helvety.com",
    rpName,
    origin: window.location.origin,
  };
}

/**
 * Check if the browser supports WebAuthn passkeys
 */
export function isPasskeySupported(): boolean {
  return browserSupportsWebAuthn();
}
