/**
 * Passkey Module
 * Handles WebAuthn passkey registration and authentication with PRF extension
 *
 * This module provides the bridge between WebAuthn/passkeys and both authentication
 * and encryption. It uses SimpleWebAuthn browser helpers and integrates PRF extension
 * for E2EE key derivation.
 */

import {
  startRegistration,
  startAuthentication,
  browserSupportsWebAuthn,
  platformAuthenticatorIsAvailable,
} from "@simplewebauthn/browser";

import type {
  PublicKeyCredentialCreationOptionsJSON,
  PublicKeyCredentialRequestOptionsJSON,
  RegistrationResponseJSON,
  AuthenticationResponseJSON,
} from "@simplewebauthn/browser";

/**
 * Relying Party configuration
 */
export interface RPConfig {
  /** Domain name (e.g., 'localhost' for dev, 'helvety.com' for prod) */
  rpId: string;
  /** Human-readable name shown in passkey prompts */
  rpName: string;
  /** Origin URL (e.g., 'https://auth.helvety.com') */
  origin: string;
}

/**
 * Get RP config based on the current browser location
 *
 * IMPORTANT: For centralized auth, we use 'helvety.com' as the rpId in production.
 * This allows passkeys registered on auth.helvety.com to work across all subdomains
 * (pdf.helvety.com, store.helvety.com, etc.)
 */
export function getRPConfig(): RPConfig {
  const rpName = "Helvety";

  if (typeof window === "undefined") {
    // Server-side fallback (passkey operations should only happen client-side)
    return {
      rpId: "localhost",
      rpName,
      origin: "http://localhost:3002",
    };
  }

  // In production, use the root domain for cross-subdomain passkey sharing
  // In development, use localhost
  const isDev =
    window.location.hostname === "localhost" ||
    window.location.hostname === "127.0.0.1";

  return {
    rpId: isDev ? "localhost" : "helvety.com",
    rpName,
    origin: window.location.origin,
  };
}

/**
 * Check if the browser supports WebAuthn passkeys
 */
export function isPasskeySupported(): boolean {
  return browserSupportsWebAuthn();
}

/**
 * Check if a platform authenticator is available (Face ID, Touch ID, Windows Hello)
 */
export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  return platformAuthenticatorIsAvailable();
}

/**
 * Crypto error types for passkey operations
 */
export enum PasskeyErrorType {
  NOT_SUPPORTED = "NOT_SUPPORTED",
  CANCELLED = "CANCELLED",
  ALREADY_EXISTS = "ALREADY_EXISTS",
  SECURITY_ERROR = "SECURITY_ERROR",
  UNKNOWN = "UNKNOWN",
}

/**
 * Passkey error class
 */
export class PasskeyError extends Error {
  constructor(
    public type: PasskeyErrorType,
    message: string,
    public override cause?: Error
  ) {
    super(message);
    this.name = "PasskeyError";
  }
}

/**
 * Passkey registration result with PRF output for encryption setup
 */
export interface PasskeyRegistrationResult {
  /** The WebAuthn registration response to send to server */
  response: RegistrationResponseJSON;
  /** Credential ID (base64url encoded) */
  credentialId: string;
  /** PRF output for deriving encryption key (if PRF supported) */
  prfOutput?: ArrayBuffer;
  /** Whether PRF was enabled during registration */
  prfEnabled: boolean;
}

/**
 * Passkey authentication result with PRF output for encryption unlock
 */
export interface PasskeyAuthenticationResult {
  /** The WebAuthn authentication response to send to server */
  response: AuthenticationResponseJSON;
  /** Credential ID used (base64url encoded) */
  credentialId: string;
  /** PRF output for deriving encryption key */
  prfOutput?: ArrayBuffer;
  /** Whether PRF was used during authentication */
  prfEnabled: boolean;
}

/**
 * Base64 encode a Uint8Array
 */
function base64Encode(data: Uint8Array): string {
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]!);
  }
  return btoa(binary);
}

/**
 * Base64 decode a string to Uint8Array
 */
function base64Decode(str: string): Uint8Array {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate registration options for creating a new passkey
 * This should be called on the server, but we provide client-side generation for simplicity
 *
 * @param userId - The user's ID
 * @param userEmail - The user's email
 * @param userName - The user's display name
 * @param prfSalt - Optional PRF salt for encryption (base64 encoded)
 */
export function generateRegistrationOptions(
  userId: string,
  userEmail: string,
  userName: string,
  prfSalt?: string
): PublicKeyCredentialCreationOptionsJSON {
  const rpConfig = getRPConfig();

  // Generate a random challenge
  const challenge = base64Encode(crypto.getRandomValues(new Uint8Array(32)));

  const options: PublicKeyCredentialCreationOptionsJSON = {
    challenge,
    rp: {
      id: rpConfig.rpId,
      name: rpConfig.rpName,
    },
    user: {
      id: base64Encode(new TextEncoder().encode(userId)),
      name: userEmail,
      displayName: userName || userEmail,
    },
    pubKeyCredParams: [
      { alg: -7, type: "public-key" }, // ES256
      { alg: -257, type: "public-key" }, // RS256
    ],
    authenticatorSelection: {
      // Force cross-platform authenticators only (phones via QR code)
      // This excludes Windows Hello, Touch ID, and other platform authenticators
      authenticatorAttachment: "cross-platform",
      userVerification: "required",
      residentKey: "required",
      requireResidentKey: true,
    },
    timeout: 60000,
    attestation: "none",
  };

  // Hint to prefer phone authenticators (hybrid) over security keys
  (
    options as PublicKeyCredentialCreationOptionsJSON & { hints?: string[] }
  ).hints = ["hybrid"];

  // Add PRF extension if salt provided
  if (prfSalt) {
    (
      options as PublicKeyCredentialCreationOptionsJSON & {
        extensions?: Record<string, unknown>;
      }
    ).extensions = {
      prf: {
        eval: {
          first: base64Decode(prfSalt),
        },
      },
    };
  }

  return options;
}

/**
 * Generate authentication options for signing in with a passkey
 *
 * @param allowCredentials - Optional list of credential IDs to allow
 * @param prfSalt - PRF salt for encryption key derivation (base64 encoded)
 */
export function generateAuthenticationOptions(
  allowCredentials?: string[],
  prfSalt?: string
): PublicKeyCredentialRequestOptionsJSON {
  const rpConfig = getRPConfig();

  // Generate a random challenge
  const challenge = base64Encode(crypto.getRandomValues(new Uint8Array(32)));

  const options: PublicKeyCredentialRequestOptionsJSON = {
    challenge,
    rpId: rpConfig.rpId,
    timeout: 60000,
    userVerification: "required",
  };

  // Add allowed credentials if provided
  if (allowCredentials && allowCredentials.length > 0) {
    options.allowCredentials = allowCredentials.map((id) => ({
      id,
      type: "public-key",
      // Only hint hybrid (phone via QR) since we force cross-platform authenticators
      transports: ["hybrid"],
    }));
  }

  // Hint to prefer phone authenticators over security keys
  (
    options as PublicKeyCredentialRequestOptionsJSON & { hints?: string[] }
  ).hints = ["hybrid"];

  // Add PRF extension if salt provided
  if (prfSalt) {
    (
      options as PublicKeyCredentialRequestOptionsJSON & {
        extensions?: Record<string, unknown>;
      }
    ).extensions = {
      prf: {
        eval: {
          first: base64Decode(prfSalt),
        },
      },
    };
  }

  return options;
}

/**
 * Register a new passkey with PRF extension for encryption
 *
 * Note: PRF output is only returned during authentication, not registration.
 * Registration only tells us if PRF is enabled/supported by the authenticator.
 *
 * @param options - Registration options from server or generateRegistrationOptions
 * @returns Registration result (prfEnabled indicates if PRF is supported)
 */
export async function registerPasskey(
  options: PublicKeyCredentialCreationOptionsJSON
): Promise<PasskeyRegistrationResult> {
  try {
    const response = await startRegistration({ optionsJSON: options });

    // During registration, PRF only returns 'enabled' status, not actual output
    // The actual PRF output is only available during authentication
    const clientExtResults = response.clientExtensionResults as {
      prf?: { enabled?: boolean };
    };

    // PRF is considered enabled if the extension was processed
    // Note: Some authenticators return enabled:true, others just include the prf object
    const prfEnabled = clientExtResults.prf !== undefined;

    return {
      response,
      credentialId: response.id,
      prfOutput: undefined, // PRF output only available during authentication
      prfEnabled,
    };
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === "NotAllowedError") {
        throw new PasskeyError(
          PasskeyErrorType.CANCELLED,
          "Passkey registration was cancelled or not allowed"
        );
      }
      if (error.name === "InvalidStateError") {
        throw new PasskeyError(
          PasskeyErrorType.ALREADY_EXISTS,
          "A passkey already exists for this account on this device"
        );
      }
    }
    throw new PasskeyError(
      PasskeyErrorType.UNKNOWN,
      "Failed to register passkey",
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Authenticate with a passkey and get PRF output for encryption
 *
 * @param options - Authentication options from server or generateAuthenticationOptions
 * @returns Authentication result with PRF output for encryption unlock
 */
export async function authenticateWithPasskey(
  options: PublicKeyCredentialRequestOptionsJSON
): Promise<PasskeyAuthenticationResult> {
  try {
    const response = await startAuthentication({ optionsJSON: options });

    // Extract PRF output if available
    const clientExtResults = response.clientExtensionResults as {
      prf?: { results?: { first?: ArrayBuffer } };
    };

    const prfOutput = clientExtResults.prf?.results?.first;
    const prfEnabled = prfOutput !== undefined;

    return {
      response,
      credentialId: response.id,
      prfOutput,
      prfEnabled,
    };
  } catch (error) {
    if (error instanceof Error) {
      if (error.name === "NotAllowedError") {
        throw new PasskeyError(
          PasskeyErrorType.CANCELLED,
          "Passkey authentication was cancelled or not allowed"
        );
      }
      if (error.name === "SecurityError") {
        throw new PasskeyError(
          PasskeyErrorType.SECURITY_ERROR,
          "Security error during passkey authentication"
        );
      }
    }
    throw new PasskeyError(
      PasskeyErrorType.UNKNOWN,
      "Failed to authenticate with passkey",
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Combined passkey registration and encryption setup
 * Use this for new user onboarding
 *
 * @param userId - User's ID
 * @param userEmail - User's email
 * @param prfSalt - PRF salt for encryption (base64 encoded)
 */
export async function registerPasskeyWithEncryption(
  userId: string,
  userEmail: string,
  prfSalt: string
): Promise<PasskeyRegistrationResult> {
  const options = generateRegistrationOptions(
    userId,
    userEmail,
    userEmail,
    prfSalt
  );
  return registerPasskey(options);
}

/**
 * Combined passkey authentication and encryption unlock
 * Use this for returning user sign-in
 *
 * @param credentialIds - Optional list of allowed credential IDs
 * @param prfSalt - PRF salt for encryption (base64 encoded)
 */
export async function authenticatePasskeyWithEncryption(
  credentialIds?: string[],
  prfSalt?: string
): Promise<PasskeyAuthenticationResult> {
  const options = generateAuthenticationOptions(credentialIds, prfSalt);
  return authenticateWithPasskey(options);
}

/**
 * Check if the browser supports WebAuthn PRF extension
 *
 * PRF is supported on:
 * - iOS 18+, macOS 15.4+
 * - Android 14+
 * - Chrome 128+, Edge 128+
 * - Firefox 139+ (desktop only; Android not supported)
 * - Hardware security keys (YubiKey 5+)
 * - Cross-device (phone via QR code) on supported phones
 */
export async function isPRFSupported(): Promise<boolean> {
  // Check if WebAuthn is available
  if (typeof window === "undefined" || !window.PublicKeyCredential) {
    return false;
  }

  // Note: We don't use getClientCapabilities().prf here because it only checks
  // platform authenticator PRF support, not cross-device (phone) PRF support.
  // Cross-device PRF works on Chrome/Edge 128+ regardless of platform support.

  const ua = navigator.userAgent;
  const edgeMatch = ua.match(/Edg\/(\d+)/);
  const chromeMatch = ua.match(/Chrome\/(\d+)/);
  const safariMatch = ua.match(/Version\/(\d+).*Safari/);
  const firefoxMatch = ua.match(/Firefox\/(\d+)/);

  // Check Firefox - supports PRF on desktop from version 139+ (not on Android)
  if (firefoxMatch?.[1]) {
    const isAndroid = ua.includes("Android");
    if (isAndroid) {
      return false; // Firefox for Android doesn't support PRF
    }
    return parseInt(firefoxMatch[1]) >= 139;
  }

  // Check Edge first (Edge UA contains both "Chrome" and "Edg")
  if (edgeMatch?.[1]) {
    return parseInt(edgeMatch[1]) >= 128;
  }
  if (chromeMatch?.[1]) {
    return parseInt(chromeMatch[1]) >= 128;
  }
  if (safariMatch?.[1]) {
    return parseInt(safariMatch[1]) >= 18;
  }

  // For other browsers, we can't reliably detect PRF support
  // Return true and let the actual passkey operation fail if not supported
  return true;
}

/**
 * Get detailed PRF support information for UI display
 */
export interface PRFSupportInfo {
  supported: boolean;
  reason?: string;
  browserInfo?: string;
}

export async function getPRFSupportInfo(): Promise<PRFSupportInfo> {
  if (typeof window === "undefined") {
    return { supported: false, reason: "Not in browser environment" };
  }

  if (!window.PublicKeyCredential) {
    return { supported: false, reason: "WebAuthn not supported" };
  }

  const ua = navigator.userAgent;
  const chromeMatch = ua.match(/Chrome\/(\d+)/);
  const safariMatch = ua.match(/Version\/(\d+).*Safari/);
  const edgeMatch = ua.match(/Edg\/(\d+)/);
  const firefoxMatch = ua.match(/Firefox\/(\d+)/);

  // Check Firefox first
  if (firefoxMatch?.[1]) {
    const version = parseInt(firefoxMatch[1]);
    const isAndroid = ua.includes("Android");
    if (isAndroid) {
      return {
        supported: false,
        reason: "Firefox for Android does not support the PRF extension",
        browserInfo: `Firefox for Android ${version}`,
      };
    }
    if (version < 139) {
      return {
        supported: false,
        reason: `Firefox ${version} detected. PRF requires Firefox 139 or later.`,
        browserInfo: `Firefox ${version}`,
      };
    }
    return { supported: true, browserInfo: `Firefox ${version}` };
  }

  // Check Edge first (Edge UA contains both "Chrome" and "Edg")
  if (edgeMatch?.[1]) {
    const version = parseInt(edgeMatch[1]);
    if (version < 128) {
      return {
        supported: false,
        reason: `Edge ${version} detected. PRF requires Edge 128 or later.`,
        browserInfo: `Edge ${version}`,
      };
    }
    return { supported: true, browserInfo: `Edge ${version}` };
  }

  if (chromeMatch?.[1]) {
    const version = parseInt(chromeMatch[1]);
    if (version < 128) {
      return {
        supported: false,
        reason: `Chrome ${version} detected. PRF requires Chrome 128 or later.`,
        browserInfo: `Chrome ${version}`,
      };
    }
    return { supported: true, browserInfo: `Chrome ${version}` };
  }

  if (safariMatch?.[1]) {
    const version = parseInt(safariMatch[1]);
    if (version < 18) {
      return {
        supported: false,
        reason: `Safari ${version} detected. PRF requires Safari 18 or later.`,
        browserInfo: `Safari ${version}`,
      };
    }
    return { supported: true, browserInfo: `Safari ${version}` };
  }

  // Unknown browser - optimistically assume support
  return { supported: true, browserInfo: "Unknown browser" };
}
