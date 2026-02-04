"use server";

import "server-only";

import {
  generateRegistrationOptions as generateRegOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions as generateAuthOptions,
  verifyAuthenticationResponse,
} from "@simplewebauthn/server";
import { cookies, headers } from "next/headers";

import { logAuthEvent } from "@/lib/auth-logger";
import { logger } from "@/lib/logger";
import { checkRateLimit, RATE_LIMITS, resetRateLimit } from "@/lib/rate-limit";
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
import type { EmailOtpType } from "@supabase/supabase-js";

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
 * Get client IP for rate limiting
 */
async function getClientIP(): Promise<string> {
  const headersList = await headers();
  return (
    headersList.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    headersList.get("x-real-ip") ??
    "unknown"
  );
}

/**
 * Send a magic link to the user's email, or skip to passkey sign-in for existing users with a passkey.
 * Magic link is sent only for new users or existing users without a passkey (so they can complete setup).
 * Existing users with a passkey skip the email and go straight to passkey sign-in.
 *
 * Security:
 * - Rate limited to prevent email spam attacks
 * - Email is normalized to prevent duplicates
 * - Logs all attempts for audit trail
 *
 * @param email - The user's email address
 * @param redirectUri - Optional redirect URI to preserve through auth flow
 * @returns Success status with isNewUser and skipToPasskey (true when existing user with passkey)
 */
export async function sendMagicLink(
  email: string,
  redirectUri?: string
): Promise<
  PasskeyActionResponse<{ isNewUser: boolean; skipToPasskey?: boolean }>
> {
  const normalizedEmail = email.toLowerCase().trim();
  const clientIP = await getClientIP();

  // Rate limit by email AND IP to prevent abuse
  const emailRateLimit = checkRateLimit(
    `magic_link:email:${normalizedEmail}`,
    RATE_LIMITS.MAGIC_LINK.maxRequests,
    RATE_LIMITS.MAGIC_LINK.windowMs
  );
  const ipRateLimit = checkRateLimit(
    `magic_link:ip:${clientIP}`,
    RATE_LIMITS.MAGIC_LINK.maxRequests * 3, // Allow more per IP (multiple users)
    RATE_LIMITS.MAGIC_LINK.windowMs
  );

  if (!emailRateLimit.allowed || !ipRateLimit.allowed) {
    const retryAfter =
      emailRateLimit.retryAfter ?? ipRateLimit.retryAfter ?? 60;
    logAuthEvent("rate_limit_exceeded", {
      metadata: {
        action: "sendMagicLink",
        email: `${normalizedEmail.slice(0, 3)}***`,
        retryAfter,
      },
      ip: clientIP,
    });
    return {
      success: false,
      error: `Too many requests. Please wait ${retryAfter} seconds before trying again.`,
    };
  }

  logAuthEvent("login_started", {
    metadata: { method: "magic_link" },
    ip: clientIP,
  });

  try {
    const adminClient = createAdminClient();

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

    // Existing user with passkey: skip magic link, go straight to passkey sign-in
    if (existingUser) {
      const passkeyStatus = await checkUserPasskeyStatus(existingUser.id);
      if (passkeyStatus.success && passkeyStatus.data?.hasPasskey) {
        logAuthEvent("login_started", {
          metadata: { method: "passkey", skipMagicLink: true },
          ip: clientIP,
        });
        return {
          success: true,
          data: { isNewUser: false, skipToPasskey: true },
        };
      }
    }

    // Send magic link for new users or existing users without passkey
    const origin =
      process.env.NEXT_PUBLIC_APP_URL ?? "https://auth.helvety.com";
    const callbackUrl = redirectUri
      ? `${origin}/auth/callback?redirect_uri=${encodeURIComponent(redirectUri)}`
      : `${origin}/auth/callback`;

    const { error: signInError } = await adminClient.auth.signInWithOtp({
      email: normalizedEmail,
      options: {
        emailRedirectTo: callbackUrl,
      },
    });

    if (signInError) {
      logger.error("Error sending magic link:", signInError);
      logAuthEvent("magic_link_failed", {
        metadata: { reason: signInError.message },
        ip: clientIP,
      });
      return { success: false, error: "Failed to send verification email" };
    }

    logAuthEvent("magic_link_sent", {
      metadata: { isNewUser },
      ip: clientIP,
    });

    return {
      success: true,
      data: { isNewUser, skipToPasskey: false },
    };
  } catch (error) {
    logger.error("Error in sendMagicLink:", error);
    logAuthEvent("magic_link_failed", {
      metadata: { reason: "unexpected_error" },
      ip: clientIP,
    });
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
    // All local development ports for Helvety apps
    // 3000: reserved for new dev, 3001: helvety.com, 3002: auth, 3003: store, 3004: pdf
    return [
      "http://localhost:3000",
      "http://localhost:3001",
      "http://localhost:3002",
      "http://localhost:3003",
      "http://localhost:3004",
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
 * When isMobile is true, uses platform authenticator (this device); otherwise
 * uses cross-platform/hybrid (phone via QR) for desktop.
 *
 * @param origin - The origin URL (e.g., 'https://auth.helvety.com')
 * @param options - Optional { isMobile } to choose platform vs hybrid flow
 * @returns Registration options to pass to the WebAuthn API
 */
export async function generatePasskeyRegistrationOptions(
  origin: string,
  options?: { isMobile?: boolean }
): Promise<
  PasskeyActionResponse<
    PublicKeyCredentialCreationOptionsJSON & { prfSalt: string }
  >
> {
  const isMobile = options?.isMobile === true;

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
      userName: user.email ?? user.id, // Show email in passkey dialog
      userDisplayName: user.email ?? "Helvety User",
      userID: new TextEncoder().encode(user.id), // Keep UUID for internal WebAuthn ID
      attestationType: "none",
      excludeCredentials,
      authenticatorSelection: isMobile
        ? {
            authenticatorAttachment: "platform",
            userVerification: "required",
            residentKey: "required",
            requireResidentKey: true,
          }
        : {
            authenticatorAttachment: "cross-platform",
            userVerification: "required",
            residentKey: "required",
            requireResidentKey: true,
          },
      timeout: 60000,
    };

    const regOptions = await generateRegOptions(opts);

    // Generate PRF salt for encryption key derivation
    const prfSalt = generatePRFSalt();

    // Hints: mobile = this device; desktop = phone via QR (hybrid)
    // Note: PRF extension is added client-side in encryption-setup.tsx since
    // Uint8Array cannot be serialized from server to client components
    const optionsWithHints = {
      ...regOptions,
      hints: (isMobile ? ["client-device"] : ["hybrid"]) as (
        | "hybrid"
        | "security-key"
        | "client-device"
      )[],
    };

    // Store challenge and PRF salt for verification
    await storeChallenge({
      challenge: regOptions.challenge,
      userId: user.id,
      prfSalt,
    });

    return {
      success: true,
      data: { ...optionsWithHints, prfSalt },
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
): Promise<PasskeyActionResponse<{ credentialId: string; prfSalt?: string }>> {
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
 * Security:
 * - Rate limited to prevent brute force attacks
 * - Logs all attempts for audit trail
 *
 * When isMobile is true, hints client-device (this device); otherwise hybrid (phone via QR).
 *
 * @param origin - The origin URL
 * @param redirectUri - Optional redirect URI to preserve through auth flow
 * @param options - Optional { isMobile } to choose platform vs hybrid flow
 * @returns Authentication options to pass to the WebAuthn API
 */
export async function generatePasskeyAuthOptions(
  origin: string,
  redirectUri?: string,
  authOptions?: { isMobile?: boolean }
): Promise<PasskeyActionResponse<PublicKeyCredentialRequestOptionsJSON>> {
  const isMobile = authOptions?.isMobile === true;
  const clientIP = await getClientIP();

  // Rate limit by IP
  const rateLimit = checkRateLimit(
    `passkey_auth:ip:${clientIP}`,
    RATE_LIMITS.PASSKEY.maxRequests,
    RATE_LIMITS.PASSKEY.windowMs
  );

  if (!rateLimit.allowed) {
    logAuthEvent("rate_limit_exceeded", {
      metadata: {
        action: "generatePasskeyAuthOptions",
        retryAfter: rateLimit.retryAfter,
      },
      ip: clientIP,
    });
    return {
      success: false,
      error: `Too many attempts. Please wait ${rateLimit.retryAfter} seconds.`,
    };
  }

  logAuthEvent("passkey_auth_started", { ip: clientIP });

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

    const authOpts = await generateAuthOptions(opts);

    // Hints: mobile = this device; desktop = phone via QR (hybrid)
    const optionsWithHints = {
      ...authOpts,
      hints: (isMobile ? ["client-device"] : ["hybrid"]) as (
        | "hybrid"
        | "security-key"
        | "client-device"
      )[],
    };

    // Store challenge for verification (no userId yet - we don't know who's authenticating)
    await storeChallenge({
      challenge: authOpts.challenge,
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
 * After successful passkey verification, this verifies a magic link token
 * server-side to create the session immediately, then returns a redirect URL.
 *
 * Security:
 * - Rate limited to prevent brute force attacks
 * - Counter updates are critical for replay attack prevention
 * - Logs all attempts for audit trail
 *
 * @param response - The authentication response from the browser
 * @param origin - The origin URL
 * @returns Success status with redirect URL to final destination
 */
export async function verifyPasskeyAuthentication(
  response: AuthenticationResponseJSON,
  origin: string
): Promise<
  PasskeyActionResponse<{
    redirectUrl: string;
    userId: string;
  }>
> {
  const clientIP = await getClientIP();

  try {
    // Retrieve stored challenge
    const storedData = await getStoredChallenge();
    if (!storedData) {
      logAuthEvent("passkey_auth_failed", {
        metadata: { reason: "challenge_expired" },
        ip: clientIP,
      });
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
      logAuthEvent("passkey_auth_failed", {
        metadata: { reason: "credential_not_found" },
        ip: clientIP,
      });
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
      logAuthEvent("passkey_auth_failed", {
        userId: credential.user_id,
        metadata: { reason: "verification_error" },
        ip: clientIP,
      });
      return { success: false, error: "Authentication verification failed" };
    }

    if (!verification.verified) {
      logAuthEvent("passkey_auth_failed", {
        userId: credential.user_id,
        metadata: { reason: "verification_failed" },
        ip: clientIP,
      });
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
      logger.error(
        "Error updating counter - failing auth for security:",
        updateError
      );
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

    // Generate a magic link for the user and verify it server-side immediately
    // This creates the session directly without requiring client navigation to Supabase
    // which would lose the session tokens in hash fragments during server redirect
    const { data: linkData, error: linkError } =
      await adminClient.auth.admin.generateLink({
        type: "magiclink",
        email: userData.user.email,
      });

    if (linkError || !linkData.properties?.hashed_token) {
      logger.error("Error generating auth link:", linkError);
      return { success: false, error: "Failed to create session" };
    }

    // Verify the magic link token server-side to create the session immediately
    // This avoids the PKCE/hash fragment issue where tokens are lost on server redirect
    const supabase = await createClient();
    const { error: verifyError } = await supabase.auth.verifyOtp({
      token_hash: linkData.properties.hashed_token,
      type: linkData.properties.verification_type as EmailOtpType,
    });

    if (verifyError) {
      logger.error("Error verifying OTP:", verifyError);
      return { success: false, error: "Failed to create session" };
    }

    // Clear the challenge
    await clearChallenge();

    // Reset rate limit on successful auth
    resetRateLimit(`passkey_auth:ip:${clientIP}`);

    logAuthEvent("passkey_auth_success", {
      userId: credential.user_id,
      ip: clientIP,
    });

    // Return the redirect URL - session is already set via cookies
    const redirectUrl = storedData.redirectUri ?? "https://helvety.com";
    return {
      success: true,
      data: {
        redirectUrl,
        userId: credential.user_id,
      },
    };
  } catch (error) {
    logger.error("Error verifying authentication:", error);
    logAuthEvent("passkey_auth_failed", {
      metadata: { reason: "unexpected_error" },
      ip: clientIP,
    });
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
