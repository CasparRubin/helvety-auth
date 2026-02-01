/**
 * E2EE Crypto Types
 * TypeScript interfaces for the encryption system
 */

/**
 * Encrypted data structure stored in the database
 */
export interface EncryptedData {
  /** Base64-encoded initialization vector */
  iv: string;
  /** Base64-encoded ciphertext */
  ciphertext: string;
  /** Encryption version for future compatibility */
  version: number;
}

/**
 * User's PRF-based key parameters stored in the database
 * Used for passkey-based encryption
 */
export interface PRFKeyParams {
  /** Base64-encoded PRF salt for HKDF */
  prfSalt: string;
  /** Version for future compatibility */
  version: number;
}

/**
 * Stored passkey credential in the database
 */
export interface StoredPasskey {
  /** Unique credential ID (base64url encoded) */
  credentialId: string;
  /** User ID this passkey belongs to */
  userId: string;
  /** Public key for verification (base64url encoded) */
  publicKey: string;
  /** Signature counter for replay protection */
  counter: number;
  /** Authenticator AAGUID */
  aaguid?: string;
  /** User-friendly name for this passkey */
  name?: string;
  /** When this passkey was registered */
  createdAt: Date;
  /** When this passkey was last used */
  lastUsedAt?: Date;
}

/**
 * Wrapped key stored in the database
 * Unit keys are wrapped (encrypted) with the user's master key
 */
export interface WrappedKey {
  /** Base64-encoded wrapped key */
  wrappedKey: string;
  /** Base64-encoded IV used for wrapping */
  iv: string;
  /** Key version for rotation support */
  version: number;
}

/**
 * Stored key entry in IndexedDB
 */
export interface StoredKeyEntry {
  /** Unit ID this key belongs to */
  unitId: number;
  /** The CryptoKey object (non-extractable) */
  key: CryptoKey;
  /** When this key was cached */
  cachedAt: number;
}

/**
 * Error types for crypto operations
 */
export enum CryptoErrorType {
  KEY_DERIVATION_FAILED = "KEY_DERIVATION_FAILED",
  ENCRYPTION_FAILED = "ENCRYPTION_FAILED",
  DECRYPTION_FAILED = "DECRYPTION_FAILED",
  KEY_NOT_FOUND = "KEY_NOT_FOUND",
  STORAGE_ERROR = "STORAGE_ERROR",
  KEY_WRAP_FAILED = "KEY_WRAP_FAILED",
  KEY_UNWRAP_FAILED = "KEY_UNWRAP_FAILED",
  PASSKEY_NOT_SUPPORTED = "PASSKEY_NOT_SUPPORTED",
  PRF_NOT_SUPPORTED = "PRF_NOT_SUPPORTED",
  PASSKEY_REGISTRATION_FAILED = "PASSKEY_REGISTRATION_FAILED",
  PASSKEY_AUTHENTICATION_FAILED = "PASSKEY_AUTHENTICATION_FAILED",
}

/**
 * Custom error class for crypto operations
 */
export class CryptoError extends Error {
  constructor(
    public type: CryptoErrorType,
    message: string,
    public override cause?: Error
  ) {
    super(message);
    this.name = "CryptoError";
  }
}
