import { NextResponse } from "next/server";

import {
  checkUserPasskeyStatus,
  hasEncryptionSetup,
} from "@/app/actions/passkey-auth-actions";
import { logger } from "@/lib/logger";
import { getSafeRedirectUri } from "@/lib/redirect-validation";
import { createClient } from "@/lib/supabase/server";

import type { EmailOtpType } from "@supabase/supabase-js";

/**
 * Auth callback route for handling Supabase magic links and OAuth
 *
 * This route is called when users click email magic links (new users or existing
 * users without a passkey) or complete OAuth flows. It exchanges the auth code
 * for a session and redirects to the appropriate destination.
 *
 * NOTE: This route is NOT used for passkey sign-in. Passkey authentication
 * creates the session directly server-side in verifyPasskeyAuthentication()
 * and returns a redirect URL to the client without going through this callback.
 *
 * After successful email auth, checks if user has passkey and encryption:
 * - If no passkey: redirects to login with step=encryption-setup (new user flow)
 * - If has passkey but no encryption: redirects to login with step=encryption-setup
 * - If has passkey and encryption: redirects to passkey-signin step
 *
 * Supports redirect_uri query param for cross-app SSO flows.
 * Redirect URIs are validated against an allowlist to prevent open redirects.
 */
export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const token_hash = searchParams.get("token_hash");
  const type = searchParams.get("type");
  const rawRedirectUri = searchParams.get("redirect_uri");
  const passkeyVerified = searchParams.get("passkey_verified") === "true";

  // Validate redirect URI against allowlist (prevents open redirect attacks)
  const safeRedirectUri = getSafeRedirectUri(rawRedirectUri, null);

  // Helper to get final redirect URL
  const getFinalRedirectUrl = () => {
    if (safeRedirectUri) {
      return safeRedirectUri;
    }
    // Default to helvety.com (works in both dev and prod)
    return "https://helvety.com";
  };

  // Helper to build login redirect with passkey step
  const buildPasskeyRedirect = async (
    supabase: Awaited<ReturnType<typeof createClient>>
  ) => {
    const {
      data: { user },
    } = await supabase.auth.getUser();

    if (!user) {
      return `${origin}/login?error=auth_failed`;
    }

    // Check if user has a passkey registered
    const passkeyResult = await checkUserPasskeyStatus(user.id);
    const hasPasskey = passkeyResult.success && passkeyResult.data?.hasPasskey;

    // Check if user has encryption setup (PRF params)
    const encryptionResult = await hasEncryptionSetup();
    const hasEncryption = encryptionResult.success && encryptionResult.data;

    // Determine the appropriate step
    let step: string;
    if (!hasPasskey) {
      // New user - needs full passkey + encryption setup
      step = "encryption-setup";
    } else if (!hasEncryption) {
      // Has passkey but no encryption - needs encryption setup only
      step = "encryption-setup";
    } else if (passkeyVerified) {
      // Legacy fallback: passkey_verified param present
      // Note: Passkey auth now creates the session directly in verifyPasskeyAuthentication()
      // and redirects without going through this callback. This check remains for backwards
      // compatibility in case of edge cases.
      return getFinalRedirectUrl();
    } else {
      // User has passkey + encryption but hasn't done passkey auth yet
      // (this is after email verification for returning users)
      step = "passkey-signin";
    }

    // Redirect to login with appropriate step
    const loginUrl = new URL(`${origin}/login`);
    loginUrl.searchParams.set("step", step);
    // Pass user status to frontend for stepper display
    loginUrl.searchParams.set("is_new_user", hasPasskey ? "false" : "true");
    if (safeRedirectUri) {
      loginUrl.searchParams.set("redirect_uri", safeRedirectUri);
    }
    return loginUrl.toString();
  };

  // Helper to build error/fallback redirect URL preserving redirect_uri and passkey_verified
  const buildErrorRedirect = (error?: string) => {
    const loginUrl = new URL(`${origin}/login`);
    if (error) {
      loginUrl.searchParams.set("error", error);
    }
    if (safeRedirectUri) {
      loginUrl.searchParams.set("redirect_uri", safeRedirectUri);
    }
    if (passkeyVerified) {
      loginUrl.searchParams.set("passkey_verified", "true");
    }
    return loginUrl.toString();
  };

  // Handle PKCE flow (code exchange)
  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);

    if (!error) {
      const redirectUrl = await buildPasskeyRedirect(supabase);
      return NextResponse.redirect(redirectUrl);
    }

    logger.error("Auth callback error (code exchange):", error);
    return NextResponse.redirect(buildErrorRedirect("auth_failed"));
  }

  // Handle token hash (email OTP verification link)
  // Supports all Supabase email types: magiclink, signup, recovery, invite, email_change
  if (token_hash && type) {
    const supabase = await createClient();
    const { error } = await supabase.auth.verifyOtp({
      token_hash,
      type: type as EmailOtpType,
    });

    if (!error) {
      const redirectUrl = await buildPasskeyRedirect(supabase);
      return NextResponse.redirect(redirectUrl);
    }

    logger.error("Auth callback error (token hash):", error);
    return NextResponse.redirect(buildErrorRedirect("auth_failed"));
  }

  // No valid auth params (code or token_hash)
  // This happens when Supabase uses hash fragments (#access_token=...) instead of query params
  // The hash fragment is only visible client-side, so we redirect to /login
  // PRESERVING the redirect_uri so AuthTokenHandler can use it after processing the hash
  return NextResponse.redirect(buildErrorRedirect());
}
