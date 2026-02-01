import { NextResponse } from "next/server";

import { logger } from "@/lib/logger";
import { isValidRedirectUri } from "@/lib/redirect-validation";
import { createClient } from "@/lib/supabase/server";

/**
 * Logout route for signing out users
 *
 * This route signs out the user and redirects to the specified destination.
 * Supports redirect_uri query param for cross-app SSO flows.
 * Redirect URIs are validated against an allowlist to prevent open redirects.
 *
 * Usage: GET /logout?redirect_uri=https://pdf.helvety.com
 */
export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const rawRedirectUri = searchParams.get("redirect_uri");

  try {
    const supabase = await createClient();
    await supabase.auth.signOut();
  } catch (error) {
    logger.error("Logout error:", error);
    // Continue with redirect even if signOut fails
  }

  // Default redirect destination
  const defaultRedirect =
    process.env.NODE_ENV === "production"
      ? "https://helvety.com"
      : `${origin}/login`;

  // Validate redirect URI against allowlist (prevents open redirect attacks)
  if (rawRedirectUri && isValidRedirectUri(rawRedirectUri)) {
    return NextResponse.redirect(rawRedirectUri);
  }

  return NextResponse.redirect(defaultRedirect);
}
