"use client";

import { useState, useEffect, useRef, useCallback } from "react";

import { logAuthEvent } from "@/lib/auth-logger";
import { clearAllKeys } from "@/lib/crypto";
import { SESSION_CONFIG } from "@/lib/session-config";
import { createClient } from "@/lib/supabase/client";

import type { User } from "@supabase/supabase-js";

/**
 * Auth session state
 */
export interface AuthSessionState {
  /** Current authenticated user, null if not authenticated */
  user: User | null;
  /** Whether the session is being loaded */
  loading: boolean;
  /** Whether the user is authenticated */
  isAuthenticated: boolean;
}

/**
 * Auth session hook options
 */
export interface UseAuthSessionOptions {
  /**
   * Whether to enable idle timeout
   * @default false (auth service doesn't need idle timeout during setup)
   */
  enableIdleTimeout?: boolean;

  /**
   * Custom idle timeout in milliseconds
   * @default SESSION_CONFIG.idleTimeout
   */
  idleTimeoutMs?: number;

  /**
   * Callback when user signs out (manually or due to idle)
   */
  onSignOut?: () => void;

  /**
   * Callback when session expires
   */
  onSessionExpired?: () => void;
}

/**
 * Hook for managing authentication session
 *
 * Features:
 * - Tracks current user state
 * - Listens for auth state changes
 * - Optional idle timeout for security
 * - Clears encryption keys on sign out
 *
 * Note: For the auth service, idle timeout is disabled by default
 * since users are actively completing authentication steps.
 *
 * @example
 * function MyComponent() {
 *   const { user, loading, isAuthenticated } = useAuthSession();
 *
 *   if (loading) return <Spinner />;
 *   if (!isAuthenticated) return <LoginForm />;
 *
 *   return <AuthenticatedContent user={user} />;
 * }
 */
export function useAuthSession(
  options: UseAuthSessionOptions = {}
): AuthSessionState {
  const {
    enableIdleTimeout = false, // Disabled by default for auth service
    idleTimeoutMs = SESSION_CONFIG.idleTimeout,
    onSignOut,
    onSessionExpired,
  } = options;

  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const lastActivityRef = useRef(Date.now());
  const supabaseRef = useRef(createClient());

  // Update last activity timestamp
  const updateActivity = useCallback(() => {
    lastActivityRef.current = Date.now();
  }, []);

  // Handle sign out (clear keys)
  const handleSignOut = useCallback(async () => {
    logAuthEvent("logout", { userId: user?.id });

    // Clear encryption keys
    try {
      await clearAllKeys();
    } catch (error) {
      console.error("Failed to clear encryption keys:", error);
    }

    onSignOut?.();
  }, [user?.id, onSignOut]);

  // Check for idle timeout
  const checkIdleTimeout = useCallback(() => {
    if (!user || !enableIdleTimeout) return;

    const idleTime = Date.now() - lastActivityRef.current;
    if (idleTime > idleTimeoutMs) {
      logAuthEvent("session_expired", {
        userId: user.id,
        metadata: { reason: "idle_timeout", idleTimeMs: idleTime },
      });
      onSessionExpired?.();
      void handleSignOut();
    }
  }, [user, enableIdleTimeout, idleTimeoutMs, onSessionExpired, handleSignOut]);

  useEffect(() => {
    const supabase = supabaseRef.current;

    // Initial user fetch
    const initializeAuth = async () => {
      try {
        const {
          data: { user },
        } = await supabase.auth.getUser();
        setUser(user);

        if (user) {
          logAuthEvent("session_refresh", { userId: user.id });
        }
      } catch (error) {
        console.error("Failed to get user:", error);
      } finally {
        setLoading(false);
      }
    };

    void initializeAuth();

    // Listen for auth state changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange(async (event, session) => {
      const newUser = session?.user ?? null;
      setUser(newUser);

      if (event === "SIGNED_IN" && newUser) {
        logAuthEvent("login_success", { userId: newUser.id });
        updateActivity();
      }

      if (event === "SIGNED_OUT") {
        logAuthEvent("logout", { userId: user?.id });
        // Clear encryption keys on sign out
        try {
          await clearAllKeys();
        } catch (error) {
          console.error("Failed to clear encryption keys:", error);
        }
        onSignOut?.();
      }

      if (event === "TOKEN_REFRESHED" && newUser) {
        logAuthEvent("session_refresh", { userId: newUser.id });
      }
    });

    return () => {
      subscription.unsubscribe();
    };
  }, [onSignOut, updateActivity, user?.id]);

  // Set up idle timeout checking (only if enabled)
  useEffect(() => {
    if (!enableIdleTimeout || !user) return;

    // Check idle status periodically
    const idleCheckInterval = setInterval(
      checkIdleTimeout,
      SESSION_CONFIG.activityCheckInterval
    );

    // Track user activity
    const activityEvents = [
      "mousemove",
      "keydown",
      "click",
      "scroll",
      "touchstart",
    ];

    activityEvents.forEach((event) => {
      window.addEventListener(event, updateActivity, { passive: true });
    });

    return () => {
      clearInterval(idleCheckInterval);
      activityEvents.forEach((event) => {
        window.removeEventListener(event, updateActivity);
      });
    };
  }, [enableIdleTimeout, user, checkIdleTimeout, updateActivity]);

  return {
    user,
    loading,
    isAuthenticated: user !== null,
  };
}
