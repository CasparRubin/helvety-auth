"use client";

import { useEffect, useState } from "react";

const STORAGE_KEY = "helvety-cookie-notice-dismissed";

/**
 * Minimal informational cookie notice bar.
 *
 * Displays once for first-time visitors to inform them that only essential cookies
 * are used (authentication, security, preferences). No consent is collected because
 * all cookies are strictly necessary under Swiss nDSG and EU ePrivacy Directive.
 *
 * Dismissal state is stored in localStorage (not a cookie) so the notice does not
 * reappear after the user acknowledges it.
 */
export function CookieNotice() {
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    try {
      if (!localStorage.getItem(STORAGE_KEY)) {
        setVisible(true);
      }
    } catch {
      // localStorage unavailable (e.g. private browsing) — don't show
    }
  }, []);

  function dismiss() {
    setVisible(false);
    try {
      localStorage.setItem(STORAGE_KEY, "1");
    } catch {
      // Ignore storage errors
    }
  }

  if (!visible) return null;

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
