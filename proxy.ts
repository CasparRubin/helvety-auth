import { createServerClient } from "@supabase/ssr";
import { NextResponse, type NextRequest } from "next/server";

/**
 * Proxy to refresh Supabase auth sessions on every request.
 *
 * This ensures:
 * 1. Sessions are refreshed before they expire
 * 2. Cookies are properly set with the correct domain for cross-subdomain SSO
 * 3. Server components always have access to fresh session data
 *
 * IMPORTANT: Per CVE-2025-29927, this proxy should ONLY handle session refresh,
 * NOT route protection. Use Server Layout Guards for authentication checks.
 */
export async function proxy(request: NextRequest) {
  let supabaseResponse = NextResponse.next({ request });

  const supabaseUrl = process.env.NEXT_PUBLIC_SUPABASE_URL;
  const supabaseKey = process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY;

  if (!supabaseUrl || !supabaseKey) {
    // Skip auth refresh if env vars are missing (shouldn't happen in production)
    return supabaseResponse;
  }

  const supabase = createServerClient(supabaseUrl, supabaseKey, {
    cookies: {
      getAll() {
        return request.cookies.getAll();
      },
      setAll(cookiesToSet) {
        // First, set cookies on the request (for downstream server components)
        cookiesToSet.forEach(({ name, value }) =>
          request.cookies.set(name, value)
        );

        // Create a new response with the updated request
        supabaseResponse = NextResponse.next({ request });

        // Set cookies on the response with proper domain for cross-subdomain SSO
        cookiesToSet.forEach(({ name, value, options }) => {
          const cookieOptions = {
            ...options,
            // In production, use .helvety.com domain for cross-subdomain session sharing
            ...(process.env.NODE_ENV === "production" && {
              domain: ".helvety.com",
            }),
          };
          supabaseResponse.cookies.set(name, value, cookieOptions);
        });
      },
    },
  });

  // Validate JWT and refresh session only when needed (getClaims validates
  // locally; Auth API is called only on refresh). Avoids 429 rate limits
  // from calling getUser() on every request.
  await supabase.auth.getClaims();

  return supabaseResponse;
}

export const config = {
  matcher: [
    /*
     * Match all request paths except:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - Static assets (svg, png, jpg, etc.)
     */
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
