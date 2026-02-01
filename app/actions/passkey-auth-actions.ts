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
} from "@simplewebauthn/server";

// =============================================================================
// TYPES
// =============================================================================

export type PasskeyActionResponse<T = void> = {
  success: boolean;
  data?: T;
  error?: string;
};

type StoredChallenge = {
  challenge: string;
  pendingUserId?: string; // For new user registration flow
  userId?: string; // For existing user flows
  syntheticEmail?: string; // Store synthetic email for new user registration
  timestamp: number;
  redirectUri?: string;
};

// =============================================================================
// CONFIGURATION
// =============================================================================

const RP_NAME = "Helvety";
const CHALLENGE_COOKIE_NAME = "webauthn_challenge";
const CHALLENGE_EXPIRY_MS = 5 * 60 * 1000; // 5 minutes
const SYNTHETIC_EMAIL_DOMAIN = "helvety.internal";

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

/**
 * Generate a synthetic email for a new user
 * Format: user_{uuid}@helvety.internal
 */
function generateSyntheticEmail(): string {
  const uuid = crypto.randomUUID();
  return `user_${uuid}@${SYNTHETIC_EMAIL_DOMAIN}`;
}

// =============================================================================
// CHALLENGE STORAGE (using cookies)
// =============================================================================

/**
 * Store challenge in a secure httpOnly cookie
 */
async function storeChallenge(data: Omit<StoredChallenge, "timestamp">): Promise<void> {
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
// NEW USER REGISTRATION (Passkey-only flow)
// =============================================================================

/**
 * Start new user registration - creates a user with synthetic email and returns passkey options
 * This is the first step for a new user who wants to create an account with just a passkey
 *
 * @param origin - The origin URL (e.g., 'https://auth.helvety.com')
 * @param redirectUri - Optional redirect URI to preserve through auth flow
 * @returns Registration options to pass to the WebAuthn API
 */
export async function registerNewUser(
  origin: string,
  redirectUri?: string
): Promise<PasskeyActionResponse<PublicKeyCredentialCreationOptionsJSON>> {
  try {
    const adminClient = createAdminClient();
    const rpId = getRpId(origin);

    // Generate a synthetic email for this user
    const syntheticEmail = generateSyntheticEmail();

    // Create the user in Supabase Auth with the synthetic email
    const { data: createData, error: createError } =
      await adminClient.auth.admin.createUser({
        email: syntheticEmail,
        email_confirm: true, // Auto-confirm since it's synthetic
      });

    if (createError || !createData.user) {
      logger.error("Error creating user:", createError);
      return { success: false, error: "Failed to create account" };
    }

    const newUser = createData.user;

    // Generate passkey registration options for this new user
    const opts: GenerateRegistrationOptionsOpts = {
      rpName: RP_NAME,
      rpID: rpId,
      userName: newUser.id, // Use ID since email is synthetic
      userDisplayName: "Helvety User",
      userID: new TextEncoder().encode(newUser.id),
      attestationType: "none",
      excludeCredentials: [], // New user has no existing credentials
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

    // Add hints to prefer phone/hybrid authenticators over USB security keys
    const optionsWithHints = {
      ...options,
      hints: ["hybrid"] as ("hybrid" | "security-key" | "client-device")[],
    };

    // Store challenge with pending user info for verification
    await storeChallenge({
      challenge: options.challenge,
      pendingUserId: newUser.id,
      syntheticEmail: syntheticEmail,
      redirectUri,
    });

    return { success: true, data: optionsWithHints };
  } catch (error) {
    logger.error("Error in registerNewUser:", error);
    return { success: false, error: "Failed to start registration" };
  }
}

/**
 * Complete new user registration - verifies passkey and creates session
 * This is the second step after the user completes the WebAuthn registration ceremony
 *
 * @param response - The registration response from the browser
 * @param origin - The origin URL
 * @returns Success status with auth URL for session creation
 */
export async function completeUserRegistration(
  response: RegistrationResponseJSON,
  origin: string
): Promise<PasskeyActionResponse<{ authUrl: string; userId: string; redirectUri?: string }>> {
  try {
    const adminClient = createAdminClient();

    // Retrieve stored challenge with pending user info
    const storedData = await getStoredChallenge();
    if (!storedData || !storedData.pendingUserId || !storedData.syntheticEmail) {
      return { success: false, error: "Registration session expired" };
    }

    const rpId = getRpId(origin);
    const expectedOrigins = getExpectedOrigins(rpId);

    // Verify the passkey registration
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
      // Clean up: delete the user since registration failed
      await adminClient.auth.admin.deleteUser(storedData.pendingUserId);
      return { success: false, error: "Passkey verification failed" };
    }

    if (!verification.verified || !verification.registrationInfo) {
      // Clean up: delete the user since registration failed
      await adminClient.auth.admin.deleteUser(storedData.pendingUserId);
      return { success: false, error: "Passkey verification failed" };
    }

    const { registrationInfo } = verification;
    const { credential, credentialDeviceType, credentialBackedUp } =
      registrationInfo;

    // Convert Uint8Array to base64url string for storage
    const publicKeyBase64 = Buffer.from(credential.publicKey).toString(
      "base64url"
    );

    // Store the credential in the database (using admin client since user isn't authenticated yet)
    const { error: insertError } = await adminClient
      .from("user_auth_credentials")
      .insert({
        user_id: storedData.pendingUserId,
        credential_id: credential.id,
        public_key: publicKeyBase64,
        counter: credential.counter,
        transports: credential.transports ?? [],
        device_type: credentialDeviceType,
        backed_up: credentialBackedUp,
      });

    if (insertError) {
      logger.error("Error storing credential:", insertError);
      // Clean up: delete the user since we couldn't store the credential
      await adminClient.auth.admin.deleteUser(storedData.pendingUserId);
      return { success: false, error: "Failed to complete registration" };
    }

    // Generate a magic link for the user to create their session
    const callbackUrl = storedData.redirectUri
      ? `${origin}/auth/callback?redirect_uri=${encodeURIComponent(storedData.redirectUri)}`
      : `${origin}/auth/callback`;

    const { data: linkData, error: linkError } =
      await adminClient.auth.admin.generateLink({
        type: "magiclink",
        email: storedData.syntheticEmail,
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

    return {
      success: true,
      data: {
        authUrl: linkData.properties.action_link,
        userId: storedData.pendingUserId,
        redirectUri: storedData.redirectUri,
      },
    };
  } catch (error) {
    logger.error("Error in completeUserRegistration:", error);
    return { success: false, error: "Failed to complete registration" };
  }
}

// =============================================================================
// EXISTING USER REGISTRATION (add passkey to existing account)
// =============================================================================

/**
 * Generate passkey registration options for an authenticated user
 * Called when a user wants to add a new passkey to their existing account
 *
 * @param origin - The origin URL (e.g., 'https://auth.helvety.com')
 * @returns Registration options to pass to the WebAuthn API
 */
export async function generatePasskeyRegistrationOptions(
  origin: string
): Promise<PasskeyActionResponse<PublicKeyCredentialCreationOptionsJSON>> {
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
      userName: user.id, // Use ID since email may be synthetic
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

    // Add hints to prefer phone/hybrid authenticators over USB security keys
    const optionsWithHints = {
      ...options,
      hints: ["hybrid"] as ("hybrid" | "security-key" | "client-device")[],
    };

    // Store challenge for verification
    await storeChallenge({
      challenge: options.challenge,
      userId: user.id,
    });

    return { success: true, data: optionsWithHints };
  } catch (error) {
    logger.error("Error generating registration options:", error);
    return { success: false, error: "Failed to generate registration options" };
  }
}

/**
 * Verify passkey registration and store the credential
 * Called after the user completes the WebAuthn registration ceremony
 *
 * @param response - The registration response from the browser
 * @param origin - The origin URL
 * @returns Success status and credential info
 */
export async function verifyPasskeyRegistration(
  response: RegistrationResponseJSON,
  origin: string
): Promise<PasskeyActionResponse<{ credentialId: string }>> {
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

    // Clear the challenge
    await clearChallenge();

    return {
      success: true,
      data: { credentialId: credential.id },
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
    const { error: updateError } = await adminClient
      .from("user_auth_credentials")
      .update({
        counter: verification.authenticationInfo.newCounter,
        last_used_at: new Date().toISOString(),
      })
      .eq("credential_id", response.id);

    if (updateError) {
      logger.error("Error updating counter:", updateError);
      // Continue anyway - counter update is not critical for auth
    }

    // Get user email for generating magic link (will be synthetic email)
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
