import "server-only";

import { createServerClient } from "@supabase/ssr";
import { cookies } from "next/headers";

import { getSupabaseUrl, getSupabaseKey } from "@/lib/env-validation";

import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Get cookie domain for cross-subdomain session sharing
 * In production, uses .helvety.com to share sessions across subdomains
 */
function getCookieDomain(): string | undefined {
  if (process.env.NODE_ENV === "production") {
    return ".helvety.com";
  }
  return undefined;
}

/**
 * Creates a Supabase server client with cookie handling for Server Components.
 * This is the standard way to create a client in Server Components, Server Actions, etc.
 *
 * Cookies are configured to share sessions across helvety.com subdomains in production.
 *
 * @returns Promise that resolves to a Supabase client instance
 */
export async function createServerComponentClient(): Promise<SupabaseClient> {
  const supabaseUrl = getSupabaseUrl();
  const supabaseKey = getSupabaseKey();
  const cookieStore = await cookies();
  const cookieDomain = getCookieDomain();

  return createServerClient(supabaseUrl, supabaseKey, {
    cookies: {
      getAll() {
        return cookieStore.getAll();
      },
      setAll(
        cookiesToSet: Array<{
          name: string;
          value: string;
          options?: Record<string, unknown>;
        }>
      ): void {
        try {
          cookiesToSet.forEach(({ name, value, options }) => {
            // Add domain for cross-subdomain session sharing
            const cookieOptions = {
              ...options,
              ...(cookieDomain && { domain: cookieDomain }),
            } as Parameters<typeof cookieStore.set>[2];
            cookieStore.set(name, value, cookieOptions);
          });
        } catch {
          // The `setAll` method was called from a Server Component.
          // Session refresh happens automatically through Supabase client in server components.
        }
      },
    },
  });
}
