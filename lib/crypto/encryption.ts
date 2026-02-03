/**
 * Encryption Module
 * AES-256-GCM encryption and decryption for user data
 */

import { base64Encode, base64Decode, generateIV } from "./encoding";
import { CryptoError, CryptoErrorType } from "./types";

import type { EncryptedData } from "./types";

/** Current encryption version */
const ENCRYPTION_VERSION = 1;

/**
 * Encrypt a string using AES-256-GCM
 *
 * @param data - The plaintext string to encrypt
 * @param key - The CryptoKey to use for encryption
 * @returns Encrypted data with IV and ciphertext
 */
export async function encrypt(
  data: string,
  key: CryptoKey
): Promise<EncryptedData> {
  try {
    const iv = generateIV();
    const encoded = new TextEncoder().encode(data);

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      encoded
    );

    return {
      iv: base64Encode(iv),
      ciphertext: base64Encode(new Uint8Array(ciphertext)),
      version: ENCRYPTION_VERSION,
    };
  } catch (error) {
    throw new CryptoError(
      CryptoErrorType.ENCRYPTION_FAILED,
      "Failed to encrypt data",
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Decrypt encrypted data using AES-256-GCM
 *
 * @param encrypted - The encrypted data object
 * @param key - The CryptoKey to use for decryption
 * @returns The decrypted plaintext string
 */
export async function decrypt(
  encrypted: EncryptedData,
  key: CryptoKey
): Promise<string> {
  try {
    const iv = base64Decode(encrypted.iv);
    const ciphertext = base64Decode(encrypted.ciphertext);

    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv },
      key,
      ciphertext
    );

    return new TextDecoder().decode(decrypted);
  } catch (error) {
    throw new CryptoError(
      CryptoErrorType.DECRYPTION_FAILED,
      "Failed to decrypt data - possibly wrong key or corrupted data",
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Encrypt a JavaScript object by JSON-serializing it first
 *
 * @param data - The object to encrypt
 * @param key - The CryptoKey to use for encryption
 * @returns Encrypted data
 */
export async function encryptObject<T extends object>(
  data: T,
  key: CryptoKey
): Promise<EncryptedData> {
  const json = JSON.stringify(data);
  return encrypt(json, key);
}

/**
 * Decrypt and parse encrypted data as a JavaScript object
 *
 * @param encrypted - The encrypted data
 * @param key - The CryptoKey to use for decryption
 * @returns The decrypted and parsed object
 */
export async function decryptObject<T extends object>(
  encrypted: EncryptedData,
  key: CryptoKey
): Promise<T> {
  const json = await decrypt(encrypted, key);
  try {
    return JSON.parse(json) as T;
  } catch {
    throw new CryptoError(
      CryptoErrorType.DECRYPTION_FAILED,
      "Decrypted data is not valid JSON"
    );
  }
}

/**
 * Serialize encrypted data for database storage
 * Returns a JSON string that can be stored in a text column
 */
export function serializeEncryptedData(data: EncryptedData): string {
  return JSON.stringify(data);
}

/**
 * Parse encrypted data from database storage
 */
export function parseEncryptedData(serialized: string): EncryptedData {
  try {
    const parsed = JSON.parse(serialized);
    if (
      typeof parsed.iv !== "string" ||
      typeof parsed.ciphertext !== "string" ||
      typeof parsed.version !== "number"
    ) {
      throw new Error("Invalid encrypted data structure");
    }
    return parsed as EncryptedData;
  } catch (error) {
    throw new CryptoError(
      CryptoErrorType.DECRYPTION_FAILED,
      "Failed to parse encrypted data from storage",
      error instanceof Error ? error : undefined
    );
  }
}

/**
 * Check if a value looks like encrypted data
 */
export function isEncryptedData(value: unknown): value is EncryptedData {
  return (
    typeof value === "object" &&
    value !== null &&
    "iv" in value &&
    "ciphertext" in value &&
    "version" in value &&
    typeof (value as EncryptedData).iv === "string" &&
    typeof (value as EncryptedData).ciphertext === "string" &&
    typeof (value as EncryptedData).version === "number"
  );
}

/**
 * Batch encrypt multiple fields of an object
 * Only encrypts string values, leaves other types unchanged
 */
export async function encryptFields<T extends Record<string, unknown>>(
  data: T,
  fieldsToEncrypt: (keyof T)[],
  key: CryptoKey
): Promise<Record<string, unknown>> {
  const result: Record<string, unknown> = { ...data };

  await Promise.all(
    fieldsToEncrypt.map(async (field) => {
      const value = data[field];
      if (value !== null && value !== undefined) {
        if (typeof value === "string") {
          result[field as string] = await encrypt(value, key);
        } else if (typeof value === "object") {
          result[field as string] = await encryptObject(
            value as Record<string, unknown>,
            key
          );
        }
      }
    })
  );

  return result;
}

/**
 * Batch decrypt multiple fields of an object
 */
export async function decryptFields<T extends Record<string, unknown>>(
  data: Record<string, unknown>,
  fieldsToDecrypt: (keyof T)[],
  key: CryptoKey
): Promise<T> {
  const result: Record<string, unknown> = { ...data };

  await Promise.all(
    fieldsToDecrypt.map(async (field) => {
      const value = data[field as string];
      if (isEncryptedData(value)) {
        result[field as string] = await decrypt(value, key);
      }
    })
  );

  return result as T;
}
