/**
 * PRF Key Derivation Module
 * Derives encryption keys from WebAuthn PRF extension output using HKDF
 *
 * This replaces password-based key derivation (Argon2id) with passkey-based derivation.
 * The PRF (Pseudo-Random Function) extension in WebAuthn generates cryptographic material
 * that is deterministic per passkey + salt combination.
 */

import { base64Encode, base64Decode, generateSalt } from "./encoding";
import { CryptoError, CryptoErrorType } from "./types";

/** Current PRF encryption version */
export const PRF_VERSION = 1;

/** PRF salt length in bytes */
const PRF_SALT_LENGTH = 32;

/**
 * HKDF info string for cross-app compatibility
 * This is shared across all Helvety apps (pdf, store, auth, etc.)
 */
const HKDF_INFO = "helvety-e2ee-v1";

/**
 * PRF-based key parameters stored in the database
 */
export interface PRFKeyParams {
  /** Base64-encoded PRF salt */
  prfSalt: string;
  /** Version for future compatibility */
  version: number;
}

/**
 * Generate new PRF parameters for a user
 * Call this when registering a new passkey for encryption
 */
export function generatePRFParams(): PRFKeyParams {
  const salt = generateSalt(PRF_SALT_LENGTH);
  return {
    prfSalt: base64Encode(salt),
    version: PRF_VERSION,
  };
}

/**
 * Get the PRF salt as Uint8Array for use in WebAuthn options
 */
export function getPRFSaltBytes(params: PRFKeyParams): Uint8Array {
  return base64Decode(params.prfSalt);
}

/**
 * Derive an AES-256-GCM master key from PRF output using HKDF
 *
 * @param prfOutput - The raw PRF output from WebAuthn authentication
 * @param params - The stored PRF parameters
 * @returns A non-extractable CryptoKey for AES-GCM operations
 */
export async function deriveKeyFromPRF(
  prfOutput: ArrayBuffer,
  params: PRFKeyParams
): Promise<CryptoKey> {
  try {
    // Import PRF output as HKDF key material
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      prfOutput,
      "HKDF",
      false,
      ["deriveKey"]
    );

    // Use PRF salt for HKDF salt, and add app-specific info
    const salt = base64Decode(params.prfSalt);
    const info = new TextEncoder().encode(HKDF_INFO);

    // Derive AES-256-GCM key using HKDF
    return await crypto.subtle.deriveKey(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt,
        info,
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false, // non-extractable for security
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  } catch (error) {
    throw new CryptoError(
      CryptoErrorType.KEY_DERIVATION_FAILED,
      "Failed to derive key from PRF output",
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Initialize encryption for a new user using passkey PRF
 *
 * @param prfOutput - The raw PRF output from passkey registration
 * @returns The PRF params to store and the derived master key
 */
export async function initializePRFEncryption(prfOutput: ArrayBuffer): Promise<{
  params: PRFKeyParams;
  masterKey: CryptoKey;
}> {
  const params = generatePRFParams();
  const masterKey = await deriveKeyFromPRF(prfOutput, params);
  return { params, masterKey };
}

/**
 * Unlock user encryption using passkey PRF
 *
 * @param prfOutput - The raw PRF output from passkey authentication
 * @param params - The stored PRF parameters
 * @returns The derived master key
 */
export async function unlockPRFEncryption(
  prfOutput: ArrayBuffer,
  params: PRFKeyParams
): Promise<CryptoKey> {
  return deriveKeyFromPRF(prfOutput, params);
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

/** Get detailed PRF support information for UI display */
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
