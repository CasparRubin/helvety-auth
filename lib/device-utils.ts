/**
 * Device detection for passkey flows (client-only).
 * Used to choose platform vs hybrid (QR) authenticator and matching UI copy.
 */

/**
 * Returns true when the current device should use the "mobile" passkey flow:
 * create/use passkey on this device (Face ID, fingerprint, or PIN) instead of
 * "scan QR code with your phone".
 *
 * Uses touch + viewport and pointer coarseness so phones and tablets get
 * the on-device flow; desktop (including touch laptops) gets the QR flow.
 * Safe for SSR: returns false when window is undefined.
 */
export function isMobileDevice(): boolean {
  if (
    typeof window === "undefined" ||
    typeof window.matchMedia !== "function"
  ) {
    return false;
  }
  const narrowViewport = window.matchMedia("(max-width: 768px)").matches;
  const touchPrimary = window.matchMedia("(pointer: coarse)").matches;
  const hasTouch = navigator.maxTouchPoints > 0;
  // Mobile: narrow screen (phone) or touch-primary device with touch (tablet/phone)
  return narrowViewport || (touchPrimary && hasTouch);
}
