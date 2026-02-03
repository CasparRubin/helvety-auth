"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef } from "react";

import { getRequiredAuthStep, buildLoginUrl } from "@/lib/auth-utils";
import { logger } from "@/lib/logger";
import { createClient } from "@/lib/supabase/client";

/**
 * Handles auth tokens from URL hash fragments on any page.
 *
 * This component provides a safety net for magic link authentication when
 * Supabase redirects to a page other than /auth/callback. Magic links are
 * only sent to new users or existing users without a passkey. Hash fragments
 * (#access_token=...) are not sent to the server, so we handle them client-side.
 *
 * After setting the session, this component checks if the user needs to complete
 * passkey/encryption setup before redirecting to the final destination.
 *
 * Place this component in the root layout to ensure tokens are processed
 * regardless of which page the user lands on.
 */
export function AuthTokenHandler() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const supabase = createClient();
  const processingRef = useRef(false);

  useEffect(() => {
    // Handle hash fragment tokens that may arrive on any page
    if (typeof window === "undefined" || !window.location.hash) {
      return;
    }

    // Prevent double processing
    if (processingRef.current) {
      return;
    }

    const hashParams = new URLSearchParams(window.location.hash.substring(1));
    const accessToken = hashParams.get("access_token");
    const refreshToken = hashParams.get("refresh_token");

    if (!accessToken || !refreshToken) {
      return;
    }

    processingRef.current = true;

    // Get redirect_uri from query params BEFORE we do anything
    const redirectUri = searchParams.get("redirect_uri");

    // Set the session from hash tokens
    void (async () => {
      try {
        const { error, data } = await supabase.auth.setSession({
          access_token: accessToken,
          refresh_token: refreshToken,
        });

        // Clear hash but preserve query params
        const currentUrl = new URL(window.location.href);
        currentUrl.hash = "";
        window.history.replaceState(null, "", currentUrl.toString());

        if (error) {
          logger.error("Failed to set session from hash tokens:", error);
          processingRef.current = false;
          return;
        }

        const user = data.user;
        if (!user) {
          logger.error("Session set but no user found");
          processingRef.current = false;
          return;
        }

        // Check for passkey_verified param (legacy fallback - passkey auth now creates session directly)
        const passkeyVerified = searchParams.get("passkey_verified") === "true";

        // Check what auth step the user needs to complete
        const { step, hasPasskey, hasEncryption } = await getRequiredAuthStep(
          user.id
        );

        // If user has everything set up and passkey_verified is present, redirect to final destination
        // Note: This is a legacy fallback - passkey authentication now creates the session
        // directly in verifyPasskeyAuthentication() without going through hash fragments
        if (passkeyVerified && hasPasskey && hasEncryption) {
          window.location.href = redirectUri ?? "https://helvety.com";
          return;
        }

        // User needs to complete setup or passkey auth
        const loginUrl = buildLoginUrl(step, redirectUri);
        window.location.href = loginUrl;
      } catch (err) {
        logger.error("Error processing hash tokens:", err);
        processingRef.current = false;
      }
    })();
  }, [router, supabase, searchParams]);

  return null;
}
