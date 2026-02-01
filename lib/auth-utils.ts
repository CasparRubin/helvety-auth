/**
 * Client-side auth utilities for determining the required authentication step
 *
 * These utilities help both AuthTokenHandler and the login page determine
 * what step the user needs to complete (passkey setup, signin, or complete).
 */

import {
  checkUserPasskeyStatus,
  hasEncryptionSetup,
} from "@/app/actions/passkey-auth-actions";

/** The authentication step the user needs to complete */
export type AuthStep = "encryption-setup" | "passkey-signin" | "complete";

/**
 * Determines the final redirect destination
 * Always redirects to helvety.com when no redirect_uri is provided
 */
export function getFinalRedirectUrl(redirectUri?: string | null): string {
  return redirectUri ?? "https://helvety.com";
}

/** Result of checking the required auth step */
export interface AuthStepResult {
  step: AuthStep;
  hasPasskey: boolean;
  hasEncryption: boolean;
}

/**
 * Determines the required authentication step for a user
 *
 * @param userId - The user's ID
 * @returns The required step and current status
 *
 * Logic:
 * - No passkey: needs encryption-setup (which includes passkey creation)
 * - Has passkey but no encryption: needs encryption-setup
 * - Has both: needs passkey-signin (to authenticate with passkey)
 *
 * Note: After passkey auth completes, the callback receives `passkey_verified=true`
 * which triggers redirect to final destination instead of showing passkey-signin again.
 */
export async function getRequiredAuthStep(
  userId: string
): Promise<AuthStepResult> {
  // Check if user has a passkey registered
  const passkeyResult = await checkUserPasskeyStatus(userId);
  const hasPasskey = passkeyResult.success && passkeyResult.data?.hasPasskey;

  // Check if user has encryption setup (PRF params)
  const encryptionResult = await hasEncryptionSetup();
  const hasEncryption = encryptionResult.success && encryptionResult.data;

  // Determine the appropriate step
  let step: AuthStep;
  if (!hasPasskey) {
    // New user - needs full passkey + encryption setup
    step = "encryption-setup";
  } else if (!hasEncryption) {
    // Has passkey but no encryption - needs encryption setup only
    step = "encryption-setup";
  } else {
    // Has everything - needs to authenticate with passkey
    step = "passkey-signin";
  }

  return {
    step,
    hasPasskey: !!hasPasskey,
    hasEncryption: !!hasEncryption,
  };
}

/**
 * Builds a login URL with the appropriate step and redirect_uri
 *
 * @param step - The authentication step
 * @param redirectUri - Optional redirect URI to preserve
 * @param baseUrl - Base URL for the login page (defaults to /login)
 * @returns The complete login URL
 */
export function buildLoginUrl(
  step: AuthStep,
  redirectUri?: string | null,
  baseUrl: string = "/login"
): string {
  const url = new URL(baseUrl, window.location.origin);
  url.searchParams.set("step", step);
  if (redirectUri) {
    url.searchParams.set("redirect_uri", redirectUri);
  }
  return url.toString();
}
