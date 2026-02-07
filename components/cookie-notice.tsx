"use client";

import { useSyncExternalStore } from "react";

const STORAGE_KEY = "helvety-cookie-notice-dismissed";

/** Module-level cache of the dismissed state, lazily initialized from localStorage. */
let dismissedCache: boolean | null = null;
const listeners = new Set<() => void>();

/** Read dismissed state, initializing from localStorage on first call. */
function getClientSnapshot(): boolean {
  if (dismissedCache === null) {
    try {
      dismissedCache = localStorage.getItem(STORAGE_KEY) !== null;
    } catch {
      dismissedCache = true;
    }
  }
  return dismissedCache;
}

/** Server snapshot: always treat as dismissed so the notice is not rendered during SSR. */
function getServerSnapshot(): boolean {
  return true;
}

/** Subscribe to changes in the dismissed state. */
function subscribe(callback: () => void): () => void {
  listeners.add(callback);
  return () => {
    listeners.delete(callback);
  };
}

/**
 * Minimal informational cookie notice bar.
 *
 * Displays once for first-time visitors to inform them that only essential cookies
 * are used (authentication, security, preferences). No consent is collected because
 * all cookies are strictly necessary under Swiss nDSG and EU ePrivacy Directive.
 *
 * Dismissal state is stored in localStorage (not a cookie) so the notice does not
 * reappear after the user acknowledges it.
 *
 * Uses useSyncExternalStore to read localStorage without triggering cascading renders.
 */
export function CookieNotice() {
  const isDismissed = useSyncExternalStore(
    subscribe,
    getClientSnapshot,
    getServerSnapshot
  );

  /** Dismiss the notice and persist the choice to localStorage. */
  function dismiss() {
    dismissedCache = true;
    try {
      localStorage.setItem(STORAGE_KEY, "1");
    } catch {
      // Ignore storage errors
    }
    listeners.forEach((cb) => cb());
  }

  if (isDismissed) return null;

  return (
    <div
      role="status"
      aria-live="polite"
      className="bg-card border-border fixed bottom-0 left-0 z-50 w-full border-t shadow-lg"
    >
      <div className="mx-auto flex max-w-[2000px] flex-col items-center gap-2 px-4 py-3 sm:flex-row sm:justify-between">
        <p className="text-muted-foreground text-center text-xs sm:text-left">
          This site uses essential cookies for authentication and security. No
          tracking cookies are used.{" "}
          <a
            href="https://helvety.com/privacy#cookies"
            className="text-foreground hover:underline"
          >
            Learn more
          </a>
        </p>
        <button
          type="button"
          onClick={dismiss}
          className="bg-primary text-primary-foreground hover:bg-primary/80 shrink-0 rounded-md px-3 py-1.5 text-xs font-medium transition-colors"
        >
          Got it
        </button>
      </div>
    </div>
  );
}
