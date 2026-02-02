import "server-only";

import { redirect } from "next/navigation";

import { createClient } from "@/lib/supabase/server";

import type { User } from "@supabase/supabase-js";

/**
 * Server-side authentication guard for protected routes.
 *
 * Use this in Server Components or Server Actions to ensure the user is authenticated.
 * Redirects to the login page if not authenticated.
 *
 * IMPORTANT: Per CVE-2025-29927, authentication checks should be done in
 * Server Layout Guards or Route Handlers, NOT in proxy.ts.
 *
 * @example
 * // In a protected layout
 * export default async function ProtectedLayout({ children }) {
 *   await requireAuth();
 *   return <>{children}</>;
 * }
 *
 * @returns The authenticated user
 * @throws Redirects to login if not authenticated
 */
export async function requireAuth(): Promise<User> {
  const supabase = await createClient();
  const {
    data: { user },
    error,
  } = await supabase.auth.getUser();

  if (error || !user) {
    // In auth service, redirect to login page directly
    redirect("/login");
  }

  return user;
}

/**
 * Get the current user without requiring authentication.
 *
 * Use this when you want to check if a user is logged in
 * but don't want to redirect if they're not.
 *
 * @example
 * // In a page that shows different content for logged in users
 * const user = await getOptionalUser();
 * if (user) {
 *   // Show personalized content
 * }
 *
 * @returns The user if authenticated, null otherwise
 */
export async function getOptionalUser(): Promise<User | null> {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();

  return user;
}

/**
 * Check if the current request is authenticated.
 *
 * Use this for conditional logic without getting the full user object.
 *
 * @returns true if authenticated, false otherwise
 */
export async function isAuthenticated(): Promise<boolean> {
  const user = await getOptionalUser();
  return user !== null;
}
