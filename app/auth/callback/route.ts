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
 * This route is called when users click magic links or complete OAuth flows.
 * It exchanges the auth code for a session and redirects to the appropriate destination.
 *
 * After successful auth, checks if user has passkey and encryption:
 * - If no passkey: redirects to login with step=passkey-setup
 * - If has passkey but no encryption: redirects to login with step=encryption-setup
 * - If has passkey and encryption: redirects to login with step=passkey-signin
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

  // Validate redirect URI against allowlist (prevents open redirect attacks)
  const safeRedirectUri = getSafeRedirectUri(rawRedirectUri, null);

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
    } else {
      // Has everything - just sign in
      step = "passkey-signin";
    }

    // Build redirect URL with step parameter
    const loginUrl = new URL(`${origin}/login`);
    loginUrl.searchParams.set("step", step);

    if (safeRedirectUri) {
      loginUrl.searchParams.set("redirect_uri", safeRedirectUri);
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
    return NextResponse.redirect(`${origin}/login?error=auth_failed`);
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
    return NextResponse.redirect(`${origin}/login?error=auth_failed`);
  }

  // No valid auth params
  return NextResponse.redirect(`${origin}/login?error=missing_params`);
}
