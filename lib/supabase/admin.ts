import "server-only";

import { createClient } from "@supabase/supabase-js";

import { getSupabaseUrl } from "@/lib/env-validation";

import type { SupabaseClient } from "@supabase/supabase-js";

/**
 * Get the service role key from environment
 * This key has full access to the database, bypassing RLS
 */
function getServiceRoleKey(): string {
  const key = process.env.SUPABASE_SECRET_KEY;
  if (!key) {
    throw new Error(
      "SUPABASE_SECRET_KEY is not set. " +
        "This key is required for admin operations like creating sessions. " +
        "Add it to your .env.local file (never commit this key to git)."
    );
  }
  return key;
}

/**
 * Singleton instance of the Supabase admin client
 * Uses service role key for full database access (bypasses RLS)
 */
let adminClient: SupabaseClient | null = null;

/**
 * Creates or returns the existing Supabase admin client instance.
 * Uses a singleton pattern for efficiency.
 *
 * SECURITY NOTES:
 * - This client uses the SERVICE ROLE key which bypasses RLS
 * - ONLY use this for admin operations that require elevated privileges
 * - NEVER expose this client or its operations to the client
 * - Common use cases: creating sessions, looking up credentials by ID
 *
 * @returns The Supabase admin client instance
 */
export function createAdminClient(): SupabaseClient {
  if (adminClient) {
    return adminClient;
  }

  const supabaseUrl = getSupabaseUrl();
  const serviceRoleKey = getServiceRoleKey();

  adminClient = createClient(supabaseUrl, serviceRoleKey, {
    auth: {
      autoRefreshToken: false,
      persistSession: false,
    },
  });

  return adminClient;
}
