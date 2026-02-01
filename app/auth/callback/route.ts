import { NextResponse } from "next/server";

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
  // Returns "/" as default if the URI is invalid or not provided
  const safeRedirectUri = getSafeRedirectUri(rawRedirectUri, "/");

  // Helper to create redirect response
  const createRedirect = (path: string) => {
    // If path starts with http, it's an absolute URL (validated external redirect)
    if (path.startsWith("http")) {
      return NextResponse.redirect(path);
    }
    // Otherwise, it's a relative path - resolve against origin
    return NextResponse.redirect(new URL(path, origin));
  };

  // Handle PKCE flow (code exchange)
  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);

    if (!error) {
      return createRedirect(safeRedirectUri);
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
      return createRedirect(safeRedirectUri);
    }

    logger.error("Auth callback error (token hash):", error);
    return NextResponse.redirect(`${origin}/login?error=auth_failed`);
  }

  // No valid auth params
  return NextResponse.redirect(`${origin}/login?error=missing_params`);
}
