/**
 * Base64 encoding/decoding utilities for crypto operations
 * Uses URL-safe base64 encoding
 */

/**
 * Encode a Uint8Array to base64 string
 */
export function base64Encode(data: Uint8Array): string {
  // Convert Uint8Array to binary string
  let binary = "";
  for (let i = 0; i < data.length; i++) {
    binary += String.fromCharCode(data[i]!);
  }
  // Use btoa for base64 encoding
  return btoa(binary);
}

/**
 * Decode a base64 string to Uint8Array
 */
export function base64Decode(base64: string): Uint8Array<ArrayBuffer> {
  // Use atob for base64 decoding
  const binary = atob(base64);
  const buffer = new ArrayBuffer(binary.length);
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Generate a cryptographically secure random salt
 * @param length - Length in bytes (default: 16)
 */
export function generateSalt(length: number = 16): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(length);
  const bytes = new Uint8Array(buffer);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Generate a random IV for AES-GCM (12 bytes as recommended by NIST)
 */
export function generateIV(): Uint8Array<ArrayBuffer> {
  const buffer = new ArrayBuffer(12);
  const bytes = new Uint8Array(buffer);
  crypto.getRandomValues(bytes);
  return bytes;
}

/**
 * Concatenate multiple Uint8Arrays
 */
export function concatBuffers(...buffers: Uint8Array[]): Uint8Array {
  const totalLength = buffers.reduce((sum, buf) => sum + buf.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const buffer of buffers) {
    result.set(buffer, offset);
    offset += buffer.length;
  }
  return result;
}

/**
 * Compare two Uint8Arrays in constant time to prevent timing attacks
 */
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  let result = 0;
  for (let i = 0; i < a.length; i++) {
    result |= a[i]! ^ b[i]!;
  }
  return result === 0;
}
