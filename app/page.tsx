import { redirect } from "next/navigation";

import { getSafeRedirectUri } from "@/lib/redirect-validation";

/**
 * Root page - redirects to login with any redirect_uri preserved
 *
 * The login page handles all authentication logic including:
 * - Checking if user is authenticated
 * - Checking passkey/encryption status
 * - Redirecting to appropriate step or final destination
 */
export default async function Home({
  searchParams,
}: {
  searchParams: Promise<{ redirect_uri?: string }>;
}) {
  const params = await searchParams;
  const rawRedirectUri = params.redirect_uri;

  // Validate redirect URI against allowlist
  const safeRedirectUri = getSafeRedirectUri(rawRedirectUri, null);

  // Build login URL with redirect_uri if valid
  const loginUrl = safeRedirectUri
    ? `/login?redirect_uri=${encodeURIComponent(safeRedirectUri)}`
    : "/login";

  // Redirect to login page - it handles all auth logic
  redirect(loginUrl);
}
