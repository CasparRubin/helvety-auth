import { createBrowserClient } from "@supabase/ssr";

import { getSupabaseUrl, getSupabaseKey } from "@/lib/env-validation";

import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Singleton instance of the Supabase client for browser usage.
 * This prevents creating multiple client instances, improving performance.
 */
let browserClient: SupabaseClient | null = null;

/**
 * Creates or returns the existing Supabase browser client instance.
 * Uses a singleton pattern to ensure only one client instance exists per browser context.
 *
 * SECURITY NOTES:
 * - This client uses the anon/publishable key (NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY)
 * - All database operations are protected by Row Level Security (RLS) policies
 * - For mutations (insert, update, delete), prefer using server actions when possible
 * - Server actions provide additional validation and authorization checks
 * - Direct client mutations are acceptable when RLS policies are properly configured
 *
 * @returns The Supabase client instance
 */
export function createClient(): SupabaseClient {
  // Return existing client if available (singleton pattern)
  if (browserClient) {
    return browserClient;
  }

  const supabaseUrl = getSupabaseUrl();
  const supabaseKey = getSupabaseKey();

  browserClient = createBrowserClient(supabaseUrl, supabaseKey);
  return browserClient;
}
