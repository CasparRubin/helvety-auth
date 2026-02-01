"use server";

import "server-only";

import {
  generateRegistrationOptions as generateRegOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions as generateAuthOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { cookies } from "next/headers";

import { logger } from "@/lib/logger";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";

import type { UserAuthCredential } from "@/lib/types";
import type {
  GenerateRegistrationOptionsOpts,
  GenerateAuthenticationOptionsOpts,
  VerifyRegistrationResponseOpts,
  VerifyAuthenticationResponseOpts,
  VerifiedRegistrationResponse,
  VerifiedAuthenticationResponse,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  AuthenticatorTransportFuture,
  AuthenticationExtensionsClientInputs,
} from "@simplewebauthn/server";

// =============================================================================
// TYPES
// =============================================================================

/** Response type for passkey-related server actions */
export type PasskeyActionResponse<T = void> = {
  success: boolean;
  data?: T;
  error?: string;
};

/** Challenge data stored in cookie for WebAuthn ceremony verification */
type StoredChallenge = {
  challenge: string;
  userId?: string; // For authenticated user flows
  timestamp: number;
  redirectUri?: string;
  prfSalt?: string; // PRF salt for encryption (base64 encoded)
};

// =============================================================================
// CONFIGURATION
// =============================================================================

const RP_NAME = "Helvety";
const CHALLENGE_COOKIE_NAME = "webauthn_challenge";
const CHALLENGE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const PRF_VERSION = 1; // Current PRF encryption version
const PRF_SALT_LENGTH = 32; // PRF salt length in bytes

/**
 * Generate a random PRF salt for encryption
 */
function generatePRFSalt(): string {
  const salt = crypto.getRandomValues(new Uint8Array(PRF_SALT_LENGTH));
  return Buffer.from(salt).toString("base64");
}

// =============================================================================
// EMAIL + MAGIC LINK AUTHENTICATION
// =============================================================================

/**
 * Send a magic link to the user's email
 * Creates a new user if they don't exist, otherwise sends login link
 *
 * @param email - The user's email address
 * @param redirectUri - Optional redirect URI to preserve through auth flow
 * @returns Success status with information about whether user is new
 */
export async function sendMagicLink(
  email: string,
  redirectUri?: string
): Promise<PasskeyActionResponse<{ isNewUser: boolean }>> {
  try {
    const adminClient = createAdminClient();
    const normalizedEmail = email.toLowerCase().trim();

    // Validate email format
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(normalizedEmail)) {
      return { success: false, error: "Please enter a valid email address" };
    }

    // Check if user exists
    const { data: existingUsers, error: listError } =
      await adminClient.auth.admin.listUsers();

    if (listError) {
      logger.error("Error listing users:", listError);
      return { success: false, error: "Failed to check user status" };
    }

    const existingUser = existingUsers.users.find(
      (u) => u.email?.toLowerCase() === normalizedEmail
    );

    let isNewUser = false;

    if (!existingUser) {
      // Create new user
      const { error: createError } = await adminClient.auth.admin.createUser({
        email: normalizedEmail,
        email_confirm: false, // Will be confirmed when they click the link
      });

      if (createError) {
        logger.error("Error creating user:", createError);
        return { success: false, error: "Failed to create account" };
      }

      isNewUser = true;
    }

    // Build the callback URL with redirect_uri if provided
    const origin =
      process.env.NEXT_PUBLIC_APP_URL ?? "https://auth.helvety.com";
    const callbackUrl = redirectUri
      ? `${origin}/auth/callback?redirect_uri=${encodeURIComponent(redirectUri)}`
      : `${origin}/auth/callback`;

    // Send magic link (this also confirms email for new users)
    const { error: signInError } = await adminClient.auth.signInWithOtp({
      email: normalizedEmail,
      options: {
        emailRedirectTo: callbackUrl,
      },
    });

    if (signInError) {
      logger.error("Error sending magic link:", signInError);
      return { success: false, error: "Failed to send verification email" };
    }

    return {
      success: true,
      data: { isNewUser },
    };
  } catch (error) {
    logger.error("Error in sendMagicLink:", error);
    return { success: false, error: "Failed to send verification email" };
  }
}

/**
 * Check if a user has any passkey credentials registered
 *
 * @param userId - The user's ID
 * @returns Whether the user has passkeys and the count
 */
export async function checkUserPasskeyStatus(
  userId: string
): Promise<PasskeyActionResponse<{ hasPasskey: boolean; count: number }>> {
  try {
    const adminClient = createAdminClient();

    const { data, error, count } = await adminClient
      .from("user_auth_credentials")
      .select("id", { count: "exact" })
      .eq("user_id", userId);

    if (error) {
      logger.error("Error checking passkey status:", error);
      return { success: false, error: "Failed to check passkey status" };
    }

    const credentialCount = count ?? data?.length ?? 0;

    return {
      success: true,
      data: {
        hasPasskey: credentialCount > 0,
        count: credentialCount,
      },
    };
  } catch (error) {
    logger.error("Error in checkUserPasskeyStatus:", error);
    return { success: false, error: "Failed to check passkey status" };
  }
}

/**
 * Get the Relying Party ID
 *
 * IMPORTANT: For centralized auth, we use 'helvety.com' as the rpId in production.
 * This allows passkeys registered on auth.helvety.com to work across all subdomains.
 *
 * @param origin - The origin URL (used only for development detection)
 */
function getRpId(origin: string): string {
  try {
    const url = new URL(origin);
    // In development, use localhost
    if (url.hostname === "localhost" || url.hostname === "127.0.0.1") {
      return "localhost";
    }
    // In production, always use the root domain for cross-subdomain passkey sharing
    return "helvety.com";
  } catch {
    // Fallback for development
    return "localhost";
  }
}

/**
 * Get expected origins for verification
 * Includes all Helvety subdomains for cross-origin passkey usage
 */
function getExpectedOrigins(rpId: string): string[] {
  if (rpId === "localhost") {
    return [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:3002",
    ];
  }
  // All Helvety subdomains
  return [
    "https://helvety.com",
    "https://auth.helvety.com",
    "https://pdf.helvety.com",
    "https://store.helvety.com",
  ];
}

// =============================================================================
// CHALLENGE STORAGE (using cookies)
// =============================================================================

/**
 * Store challenge in a secure httpOnly cookie
 */
async function storeChallenge(
  data: Omit<StoredChallenge, "timestamp">
): Promise<void> {
  const cookieStore = await cookies();
  const challengeData: StoredChallenge = {
    ...data,
    timestamp: Date.now(),
  };

  cookieStore.set(CHALLENGE_COOKIE_NAME, JSON.stringify(challengeData), {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax", // Allow cross-site for redirects
    maxAge: CHALLENGE_EXPIRY_MS / 1000,
    path: "/",
  });
}

/**
 * Retrieve and validate stored challenge
 */
async function getStoredChallenge(): Promise<StoredChallenge | null> {
  const cookieStore = await cookies();
  const cookie = cookieStore.get(CHALLENGE_COOKIE_NAME);

  if (!cookie?.value) {
    return null;
  }

  try {
    const data = JSON.parse(cookie.value) as StoredChallenge;

    // Check if challenge has expired
    if (Date.now() - data.timestamp > CHALLENGE_EXPIRY_MS) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

/**
 * Clear the stored challenge
 */
async function clearChallenge(): Promise<void> {
  const cookieStore = await cookies();
  cookieStore.delete(CHALLENGE_COOKIE_NAME);
}

// =============================================================================
// PASSKEY REGISTRATION (for authenticated users)
// =============================================================================

/**
 * Generate passkey registration options for an authenticated user
 * Called when a user wants to add a new passkey to their existing account
 *
 * This includes PRF extension for E2EE encryption key derivation.
 *
 * @param origin - The origin URL (e.g., 'https://auth.helvety.com')
 * @returns Registration options to pass to the WebAuthn API
 */
export async function generatePasskeyRegistrationOptions(
  origin: string
): Promise<
  PasskeyActionResponse<
    PublicKeyCredentialCreationOptionsJSON & { prfSalt: string }
  >
> {
  try {
    const supabase = await createClient();

    // Get current user - must be authenticated to register a passkey
    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();
    if (userError || !user) {
      return {
        success: false,
        error: "Must be authenticated to register a passkey",
      };
    }

    const rpId = getRpId(origin);

    // Get existing credentials to exclude them
    const { data: existingCredentials } = await supabase
      .from("user_auth_credentials")
      .select("credential_id, transports")
      .eq("user_id", user.id);

    const excludeCredentials =
      existingCredentials?.map((cred) => ({
        id: cred.credential_id,
        transports: (cred.transports ?? []) as AuthenticatorTransportFuture[],
      })) ?? [];

    const opts: GenerateRegistrationOptionsOpts = {
      rpName: RP_NAME,
      rpID: rpId,
      userName: user.id, // Use ID as unique identifier
      userDisplayName: "Helvety User",
      userID: new TextEncoder().encode(user.id),
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: {
        // Force cross-platform authenticators (phone via QR code)
        authenticatorAttachment: "cross-platform",
        userVerification: "required",
        residentKey: "required",
        requireResidentKey: true,
      },
      timeout: 60000,
    };

    const options = await generateRegOptions(opts);

    // Generate PRF salt for encryption key derivation
    const prfSalt = generatePRFSalt();

    // Add hints to prefer phone/hybrid authenticators over USB security keys
    // Add PRF extension for encryption
    const optionsWithExtensions = {
      ...options,
      hints: ["hybrid"] as ("hybrid" | "security-key" | "client-device")[],
      extensions: {
        prf: {
          eval: {
            first: Buffer.from(prfSalt, "base64"),
          },
        },
      } as AuthenticationExtensionsClientInputs,
    };

    // Store challenge and PRF salt for verification
    await storeChallenge({
      challenge: options.challenge,
      userId: user.id,
      prfSalt,
    });

    return {
      success: true,
      data: { ...optionsWithExtensions, prfSalt },
    };
  } catch (error) {
    logger.error("Error generating registration options:", error);
    return { success: false, error: "Failed to generate registration options" };
  }
}

/**
 * Verify passkey registration and store the credential
 * Called after the user completes the WebAuthn registration ceremony
 *
 * Also stores PRF params for encryption if PRF was enabled.
 *
 * @param response - The registration response from the browser
 * @param origin - The origin URL
 * @param prfEnabled - Whether PRF was enabled during registration
 * @returns Success status and credential info
 */
export async function verifyPasskeyRegistration(
  response: RegistrationResponseJSON,
  origin: string,
  prfEnabled: boolean = false
): Promise<
  PasskeyActionResponse<{ credentialId: string; prfSalt?: string }>
> {
  try {
    const supabase = await createClient();

    // Get current user
    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();
    if (userError || !user) {
      return {
        success: false,
        error: "Must be authenticated to verify registration",
      };
    }

    // Retrieve stored challenge
    const storedData = await getStoredChallenge();
    if (!storedData) {
      return { success: false, error: "Challenge expired or not found" };
    }

    // Verify the user ID matches
    if (storedData.userId !== user.id) {
      return { success: false, error: "User mismatch" };
    }

    const rpId = getRpId(origin);
    const expectedOrigins = getExpectedOrigins(rpId);

    const opts: VerifyRegistrationResponseOpts = {
      response,
      expectedChallenge: storedData.challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpId,
      requireUserVerification: true,
    };

    let verification: VerifiedRegistrationResponse;
    try {
      verification = await verifyRegistrationResponse(opts);
    } catch (error) {
      logger.error("Registration verification failed:", error);
      return { success: false, error: "Registration verification failed" };
    }

    if (!verification.verified || !verification.registrationInfo) {
      return { success: false, error: "Registration verification failed" };
    }

    const { registrationInfo } = verification;
    const { credential, credentialDeviceType, credentialBackedUp } =
      registrationInfo;

    // Convert Uint8Array to base64url string for storage
    const publicKeyBase64 = Buffer.from(credential.publicKey).toString(
      "base64url"
    );

    // Store the credential in the database
    const { error: insertError } = await supabase
      .from("user_auth_credentials")
      .insert({
        user_id: user.id,
        credential_id: credential.id,
        public_key: publicKeyBase64,
        counter: credential.counter,
        transports: credential.transports ?? [],
        device_type: credentialDeviceType,
        backed_up: credentialBackedUp,
      });

    if (insertError) {
      logger.error("Error storing credential:", insertError);
      return { success: false, error: "Failed to store credential" };
    }

    // If PRF was enabled, store PRF params for encryption
    let savedPrfSalt: string | undefined;
    if (prfEnabled && storedData.prfSalt) {
      const { error: prfError } = await supabase
        .from("user_passkey_params")
        .upsert(
          {
            user_id: user.id,
            prf_salt: storedData.prfSalt,
            credential_id: credential.id,
            version: PRF_VERSION,
          },
          { onConflict: "user_id" }
        );

      if (prfError) {
        logger.error("Error storing PRF params:", prfError);
        // Don't fail the entire registration, just log the error
        // The user can still use the passkey for auth
      } else {
        savedPrfSalt = storedData.prfSalt;
      }
    }

    // Clear the challenge
    await clearChallenge();

    return {
      success: true,
      data: { credentialId: credential.id, prfSalt: savedPrfSalt },
    };
  } catch (error) {
    logger.error("Error verifying registration:", error);
    return { success: false, error: "Failed to verify registration" };
  }
}

// =============================================================================
// AUTHENTICATION (returning users)
// =============================================================================

/**
 * Generate passkey authentication options
 * Called when a user wants to sign in with a passkey
 *
 * @param origin - The origin URL
 * @param redirectUri - Optional redirect URI to preserve through auth flow
 * @returns Authentication options to pass to the WebAuthn API
 */
export async function generatePasskeyAuthOptions(
  origin: string,
  redirectUri?: string
): Promise<PasskeyActionResponse<PublicKeyCredentialRequestOptionsJSON>> {
  try {
    const rpId = getRpId(origin);

    // For discoverable credentials (passkeys), we don't need to specify allowCredentials
    // The authenticator will discover which credentials are available
    const opts: GenerateAuthenticationOptionsOpts = {
      rpID: rpId,
      userVerification: "required",
      timeout: 60000,
      // Empty allowCredentials means "discover credentials" (resident keys)
      allowCredentials: [],
    };

    const options = await generateAuthOptions(opts);

    // Add hints to prefer phone/hybrid authenticators over USB security keys
    const optionsWithHints = {
      ...options,
      hints: ["hybrid"] as ("hybrid" | "security-key" | "client-device")[],
    };

    // Store challenge for verification (no userId yet - we don't know who's authenticating)
    await storeChallenge({
      challenge: options.challenge,
      redirectUri,
    });

    return { success: true, data: optionsWithHints };
  } catch (error) {
    logger.error("Error generating authentication options:", error);
    return {
      success: false,
      error: "Failed to generate authentication options",
    };
  }
}

/**
 * Verify passkey authentication and create a session
 * Called after the user completes the WebAuthn authentication ceremony
 *
 * After successful passkey verification, this generates a magic link that
 * the client will use to complete authentication with Supabase.
 *
 * @param response - The authentication response from the browser
 * @param origin - The origin URL
 * @returns Success status with auth link URL and optional redirect URI
 */
export async function verifyPasskeyAuthentication(
  response: AuthenticationResponseJSON,
  origin: string
): Promise<
  PasskeyActionResponse<{
    authUrl: string;
    userId: string;
    redirectUri?: string;
  }>
> {
  try {
    // Retrieve stored challenge
    const storedData = await getStoredChallenge();
    if (!storedData) {
      return { success: false, error: "Challenge expired or not found" };
    }

    const rpId = getRpId(origin);
    const expectedOrigins = getExpectedOrigins(rpId);

    // Use admin client to look up the credential (before authentication)
    const adminClient = createAdminClient();

    // Find the credential by ID
    const { data: credentialData, error: credError } = await adminClient
      .from("user_auth_credentials")
      .select("*")
      .eq("credential_id", response.id)
      .single();

    if (credError || !credentialData) {
      logger.error("Credential not found:", credError);
      return { success: false, error: "Credential not found" };
    }

    const credential = credentialData as UserAuthCredential;

    // Convert stored public key from base64url back to Uint8Array
    const publicKeyUint8 = new Uint8Array(
      Buffer.from(credential.public_key, "base64url")
    );

    const opts: VerifyAuthenticationResponseOpts = {
      response,
      expectedChallenge: storedData.challenge,
      expectedOrigin: expectedOrigins,
      expectedRPID: rpId,
      credential: {
        id: credential.credential_id,
        publicKey: publicKeyUint8,
        counter: credential.counter,
        transports: (credential.transports ||
          []) as AuthenticatorTransportFuture[],
      },
      requireUserVerification: true,
    };

    let verification: VerifiedAuthenticationResponse;
    try {
      verification = await verifyAuthenticationResponse(opts);
    } catch (error) {
      logger.error("Authentication verification failed:", error);
      return { success: false, error: "Authentication verification failed" };
    }

    if (!verification.verified) {
      return { success: false, error: "Authentication verification failed" };
    }

    // Update the counter to prevent replay attacks
    // Security: Counter update is CRITICAL - if it fails, we must fail the
    // authentication to prevent replay attacks where the same authentication
    // response is used multiple times.
    const { error: updateError } = await adminClient
      .from("user_auth_credentials")
      .update({
        counter: verification.authenticationInfo.newCounter,
        last_used_at: new Date().toISOString(),
      })
      .eq("credential_id", response.id);

    if (updateError) {
      logger.error("Error updating counter - failing auth for security:", updateError);
      return {
        success: false,
        error: "Authentication failed - please try again",
      };
    }

    // Get user email for generating magic link
    const { data: userData, error: userError } =
      await adminClient.auth.admin.getUserById(credential.user_id);

    if (userError || !userData.user) {
      logger.error("Error getting user:", userError);
      return { success: false, error: "User not found" };
    }

    if (!userData.user.email) {
      return { success: false, error: "User has no email" };
    }

    // Generate a magic link for the user
    // This creates a one-time use link that creates a session when clicked
    // Include redirect_uri in the callback URL if provided
    const callbackUrl = storedData.redirectUri
      ? `${origin}/auth/callback?redirect_uri=${encodeURIComponent(storedData.redirectUri)}`
      : `${origin}/auth/callback`;

    const { data: linkData, error: linkError } =
      await adminClient.auth.admin.generateLink({
        type: "magiclink",
        email: userData.user.email,
        options: {
          redirectTo: callbackUrl,
        },
      });

    if (linkError || !linkData.properties?.action_link) {
      logger.error("Error generating auth link:", linkError);
      return { success: false, error: "Failed to create session" };
    }

    // Clear the challenge
    await clearChallenge();

    // Return the action link - client will navigate to this to complete auth
    return {
      success: true,
      data: {
        authUrl: linkData.properties.action_link,
        userId: credential.user_id,
        redirectUri: storedData.redirectUri,
      },
    };
  } catch (error) {
    logger.error("Error verifying authentication:", error);
    return { success: false, error: "Failed to verify authentication" };
  }
}

// =============================================================================
// CREDENTIAL MANAGEMENT
// =============================================================================

/**
 * Get user's registered credentials (for management UI)
 * Requires authentication
 */
export async function getUserCredentials(): Promise<
  PasskeyActionResponse<UserAuthCredential[]>
> {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();
    if (userError || !user) {
      return { success: false, error: "Not authenticated" };
    }

    const { data, error } = await supabase
      .from("user_auth_credentials")
      .select("*")
      .eq("user_id", user.id)
      .order("created_at", { ascending: false });

    if (error) {
      logger.error("Error getting credentials:", error);
      return { success: false, error: "Failed to get credentials" };
    }

    return { success: true, data: data as UserAuthCredential[] };
  } catch (error) {
    logger.error("Error getting user credentials:", error);
    return { success: false, error: "Failed to get credentials" };
  }
}

/**
 * Delete a credential (for management UI)
 * Requires authentication
 */
export async function deleteCredential(
  credentialId: string
): Promise<PasskeyActionResponse> {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();
    if (userError || !user) {
      return { success: false, error: "Not authenticated" };
    }

    const { error } = await supabase
      .from("user_auth_credentials")
      .delete()
      .eq("user_id", user.id)
      .eq("credential_id", credentialId);

    if (error) {
      logger.error("Error deleting credential:", error);
      return { success: false, error: "Failed to delete credential" };
    }

    return { success: true };
  } catch (error) {
    logger.error("Error deleting credential:", error);
    return { success: false, error: "Failed to delete credential" };
  }
}

// =============================================================================
// ENCRYPTION (PRF PARAMS)
// =============================================================================

/**
 * User passkey params for encryption
 */
export interface UserPasskeyParams {
  user_id: string;
  prf_salt: string;
  credential_id: string;
  version: number;
  created_at: string;
}

/**
 * Check if user has encryption (PRF params) set up
 */
export async function hasEncryptionSetup(): Promise<
  PasskeyActionResponse<boolean>
> {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();
    if (userError || !user) {
      return { success: false, error: "Not authenticated" };
    }

    const { data, error } = await supabase
      .from("user_passkey_params")
      .select("user_id")
      .eq("user_id", user.id)
      .single();

    if (error) {
      // PGRST116 = no rows found (user hasn't set up encryption)
      if (error.code === "PGRST116") {
        return { success: true, data: false };
      }
      logger.error("Error checking encryption setup:", error);
      return { success: false, error: "Failed to check encryption status" };
    }

    return { success: true, data: !!data };
  } catch (error) {
    logger.error("Error in hasEncryptionSetup:", error);
    return { success: false, error: "Failed to check encryption status" };
  }
}

/**
 * Get user's PRF params for encryption
 */
export async function getPasskeyParams(): Promise<
  PasskeyActionResponse<UserPasskeyParams | null>
> {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();
    if (userError || !user) {
      return { success: false, error: "Not authenticated" };
    }

    const { data, error } = await supabase
      .from("user_passkey_params")
      .select("*")
      .eq("user_id", user.id)
      .single();

    if (error) {
      // PGRST116 = no rows found
      if (error.code === "PGRST116") {
        return { success: true, data: null };
      }
      logger.error("Error getting PRF params:", error);
      return { success: false, error: "Failed to get encryption params" };
    }

    return { success: true, data: data as UserPasskeyParams };
  } catch (error) {
    logger.error("Error in getPasskeyParams:", error);
    return { success: false, error: "Failed to get encryption params" };
  }
}

/**
 * Save user's passkey encryption params (PRF salt and credential ID)
 * Used during encryption setup flow
 */
export async function savePasskeyParams(params: {
  prf_salt: string;
  credential_id: string;
  version: number;
}): Promise<PasskeyActionResponse> {
  try {
    const supabase = await createClient();

    const {
      data: { user },
      error: userError,
    } = await supabase.auth.getUser();
    if (userError || !user) {
      return { success: false, error: "Not authenticated" };
    }

    const { error } = await supabase.from("user_passkey_params").upsert(
      {
        user_id: user.id,
        prf_salt: params.prf_salt,
        credential_id: params.credential_id,
        version: params.version,
      },
      { onConflict: "user_id" }
    );

    if (error) {
      logger.error("Error saving PRF params:", error);
      return { success: false, error: "Failed to save encryption settings" };
    }

    return { success: true };
  } catch (error) {
    logger.error("Error in savePasskeyParams:", error);
    return { success: false, error: "Failed to save encryption settings" };
  }
}
