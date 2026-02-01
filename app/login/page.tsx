"use client";

import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
import { Loader2, ArrowLeft, UserPlus, LogIn } from "lucide-react";
import Image from "next/image";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, Suspense, useCallback } from "react";

import {
  registerNewUser,
  completeUserRegistration,
  generatePasskeyAuthOptions,
  verifyPasskeyAuthentication,
} from "@/app/actions/passkey-auth-actions";
import { AuthStepper, type AuthStep } from "@/components/auth-stepper";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { isPasskeySupported } from "@/lib/crypto/passkey";
import { logger } from "@/lib/logger";
import { createClient } from "@/lib/supabase/client";

type LoginStep = "choose" | "registering" | "authenticating";

function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const supabase = createClient();
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [step, setStep] = useState<LoginStep>("choose");
  const [passkeySupported, setPasskeySupported] = useState(false);
  const [checkingAuth, setCheckingAuth] = useState(true);

  // Get redirect_uri from query params
  const redirectUri = searchParams.get("redirect_uri");

  // Check for auth errors from callback
  useEffect(() => {
    const authError = searchParams.get("error");
    const hasHashTokens =
      typeof window !== "undefined" &&
      window.location.hash.includes("access_token");

    if (authError === "auth_failed") {
      setError("Authentication failed. Please try again.");
    } else if (authError === "missing_params" && !hasHashTokens) {
      setError("Invalid authentication link.");
    }
  }, [searchParams]);

  // Check if user is already logged in, handle hash tokens, and check passkey support
  useEffect(() => {
    const init = async () => {
      // Check WebAuthn support
      const supported = isPasskeySupported();
      setPasskeySupported(supported);

      // Handle hash fragment tokens (from passkey auth via generateLink)
      if (typeof window !== "undefined" && window.location.hash) {
        const hashParams = new URLSearchParams(
          window.location.hash.substring(1)
        );
        const accessToken = hashParams.get("access_token");
        const refreshToken = hashParams.get("refresh_token");

        if (accessToken && refreshToken) {
          const { error: sessionError } = await supabase.auth.setSession({
            access_token: accessToken,
            refresh_token: refreshToken,
          });

          if (!sessionError) {
            window.history.replaceState(null, "", window.location.pathname);
            if (redirectUri) {
              window.location.href = redirectUri;
            } else if (process.env.NODE_ENV === "production") {
              // In production, redirect to main site
              window.location.href = "https://helvety.com";
            } else {
              // In development, just clear the checking state to show logged-in UI
              setCheckingAuth(false);
            }
            return;
          }

          logger.error("Failed to set session from hash:", sessionError);
          window.history.replaceState(
            null,
            "",
            window.location.pathname + window.location.search
          );
        }
      }

      // Check if user is already logged in
      const {
        data: { user },
      } = await supabase.auth.getUser();
      if (user) {
        if (redirectUri) {
          window.location.href = redirectUri;
          return;
        } else if (process.env.NODE_ENV === "production") {
          // In production, redirect to main site
          window.location.href = "https://helvety.com";
          return;
        }
        // In development with no redirect_uri, fall through to show the login page
        // This prevents the infinite loop and lets developers test the UI
      }

      setCheckingAuth(false);
    };
    void init();
  }, [router, supabase, redirectUri]);

  // Handle new user registration with passkey
  const handleCreateAccount = useCallback(async () => {
    if (!passkeySupported) {
      setError("Your browser doesn't support passkeys");
      return;
    }

    setError("");
    setIsLoading(true);
    setStep("registering");

    try {
      const origin = window.location.origin;

      // Step 1: Create user and get registration options
      const optionsResult = await registerNewUser(
        origin,
        redirectUri ?? undefined
      );
      if (!optionsResult.success || !optionsResult.data) {
        setError(optionsResult.error ?? "Failed to start registration");
        setStep("choose");
        setIsLoading(false);
        return;
      }

      // Step 2: Start WebAuthn registration (shows QR code for phone)
      let regResponse;
      try {
        regResponse = await startRegistration({
          optionsJSON: optionsResult.data,
        });
      } catch (err) {
        if (err instanceof Error) {
          if (err.name === "NotAllowedError") {
            setError("Registration was cancelled");
          } else if (err.name === "AbortError") {
            setError("Registration timed out");
          } else {
            setError("Failed to register passkey");
          }
        } else {
          setError("Failed to register passkey");
        }
        setStep("choose");
        setIsLoading(false);
        return;
      }

      // Step 3: Complete registration and get session
      const verifyResult = await completeUserRegistration(regResponse, origin);
      if (!verifyResult.success || !verifyResult.data) {
        setError(verifyResult.error ?? "Failed to complete registration");
        setStep("choose");
        setIsLoading(false);
        return;
      }

      // Step 4: Redirect to auth URL to complete session creation
      window.location.href = verifyResult.data.authUrl;
    } catch (err) {
      logger.error("Registration error:", err);
      setError("An unexpected error occurred");
      setStep("choose");
      setIsLoading(false);
    }
  }, [passkeySupported, redirectUri]);

  // Handle returning user authentication with passkey
  const handleSignIn = useCallback(async () => {
    if (!passkeySupported) {
      setError("Your browser doesn't support passkeys");
      return;
    }

    setError("");
    setIsLoading(true);
    setStep("authenticating");

    try {
      const origin = window.location.origin;

      // Step 1: Get authentication options
      const optionsResult = await generatePasskeyAuthOptions(
        origin,
        redirectUri ?? undefined
      );
      if (!optionsResult.success || !optionsResult.data) {
        setError(
          optionsResult.error ?? "Failed to start passkey authentication"
        );
        setStep("choose");
        setIsLoading(false);
        return;
      }

      // Step 2: Start WebAuthn authentication (shows QR code for phone)
      let authResponse;
      try {
        authResponse = await startAuthentication({
          optionsJSON: optionsResult.data,
        });
      } catch (err) {
        if (err instanceof Error) {
          if (err.name === "NotAllowedError") {
            setError("Authentication was cancelled");
          } else if (err.name === "AbortError") {
            setError("Authentication timed out");
          } else {
            setError("Failed to authenticate with passkey");
          }
        } else {
          setError("Failed to authenticate with passkey");
        }
        setStep("choose");
        setIsLoading(false);
        return;
      }

      // Step 3: Verify authentication on server
      const verifyResult = await verifyPasskeyAuthentication(
        authResponse,
        origin
      );
      if (!verifyResult.success || !verifyResult.data) {
        setError(verifyResult.error ?? "Authentication verification failed");
        setStep("choose");
        setIsLoading(false);
        return;
      }

      // Step 4: Redirect to the auth URL to complete session creation
      window.location.href = verifyResult.data.authUrl;
    } catch (err) {
      logger.error("Passkey auth error:", err);
      setError("An unexpected error occurred");
      setStep("choose");
      setIsLoading(false);
    }
  }, [passkeySupported, redirectUri]);

  // Go back to choose step
  const handleBack = () => {
    setStep("choose");
    setError("");
    setIsLoading(false);
  };

  // Show loading while checking auth
  if (checkingAuth) {
    return (
      <div className="flex min-h-screen flex-col items-center px-4 pt-8 md:pt-16 lg:pt-24">
        <Loader2 className="text-muted-foreground h-8 w-8 animate-spin" />
      </div>
    );
  }

  // Determine current step for the stepper
  const currentAuthStep: AuthStep = (() => {
    if (step === "choose") return "choose";
    return "authenticate";
  })();

  return (
    <div className="flex min-h-screen flex-col items-center px-4 pt-8 md:pt-16 lg:pt-24">
      {/* Logo */}
      <a
        href="https://helvety.com"
        target="_blank"
        rel="noopener noreferrer"
        className="mb-8 transition-opacity hover:opacity-80"
      >
        <Image
          src="/logo_whiteBg.svg"
          alt="Helvety"
          width={150}
          height={40}
          className="h-10 w-auto"
          priority
        />
      </a>

      <div className="flex w-full max-w-md flex-col items-center space-y-6">
        {/* Show stepper */}
        <AuthStepper currentStep={currentAuthStep} />

        <Card className="w-full">
          <CardHeader>
            <CardTitle>
              {step === "choose" && "Welcome to Helvety"}
              {step === "registering" && "Creating Account..."}
              {step === "authenticating" && "Signing In..."}
            </CardTitle>
            <CardDescription>
              {step === "choose" &&
                "Sign in or create an account using your device"}
              {step === "registering" &&
                "Complete passkey setup on your device"}
              {step === "authenticating" &&
                "Verify your identity on your device"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* Step 1: Choose action */}
            {step === "choose" && (
              <div className="space-y-4">
                {!passkeySupported && (
                  <div className="bg-destructive/10 text-destructive rounded-lg p-3 text-sm">
                    Your browser doesn&apos;t support passkeys. Please use a
                    modern browser like Chrome, Safari, or Edge.
                  </div>
                )}

                <div className="flex flex-col gap-3">
                  <Button
                    onClick={handleSignIn}
                    disabled={isLoading || !passkeySupported}
                    size="lg"
                    className="w-full"
                  >
                    {isLoading ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <LogIn className="mr-2 h-4 w-4" />
                    )}
                    Sign In
                  </Button>

                  <div className="relative">
                    <div className="absolute inset-0 flex items-center">
                      <span className="w-full border-t" />
                    </div>
                    <div className="relative flex justify-center text-xs uppercase">
                      <span className="bg-background text-muted-foreground px-2">
                        or
                      </span>
                    </div>
                  </div>

                  <Button
                    onClick={handleCreateAccount}
                    variant="outline"
                    disabled={isLoading || !passkeySupported}
                    size="lg"
                    className="w-full"
                  >
                    {isLoading ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <UserPlus className="mr-2 h-4 w-4" />
                    )}
                    Create Account
                  </Button>
                </div>

                {error && (
                  <p className="text-destructive text-center text-sm">
                    {error}
                  </p>
                )}

                <p className="text-muted-foreground text-center text-xs">
                  No password or email needed. Your device secures your account
                  with Face ID, fingerprint, or PIN.
                </p>
              </div>
            )}

            {/* Registering step - passkey creation in progress */}
            {step === "registering" && (
              <div className="space-y-4">
                <div className="flex items-center justify-center py-4">
                  <div className="bg-primary/10 flex h-12 w-12 items-center justify-center rounded-full">
                    <Loader2 className="text-primary h-6 w-6 animate-spin" />
                  </div>
                </div>
                <p className="text-muted-foreground text-center text-sm">
                  Scan the QR code with your phone and verify with Face ID,
                  fingerprint, or PIN.
                </p>
                {error && (
                  <p className="text-destructive text-center text-sm">
                    {error}
                  </p>
                )}
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full"
                  onClick={handleBack}
                  disabled={isLoading && !error}
                >
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Cancel
                </Button>
              </div>
            )}

            {/* Authenticating step - passkey authentication in progress */}
            {step === "authenticating" && (
              <div className="space-y-4">
                <div className="flex items-center justify-center py-4">
                  <div className="bg-primary/10 flex h-12 w-12 items-center justify-center rounded-full">
                    <Loader2 className="text-primary h-6 w-6 animate-spin" />
                  </div>
                </div>
                <p className="text-muted-foreground text-center text-sm">
                  Scan the QR code with your phone and verify with Face ID,
                  fingerprint, or PIN.
                </p>
                {error && (
                  <p className="text-destructive text-center text-sm">
                    {error}
                  </p>
                )}
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full"
                  onClick={handleBack}
                  disabled={isLoading && !error}
                >
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Cancel
                </Button>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Show where user will be redirected */}
        {redirectUri && (
          <p className="text-muted-foreground text-center text-xs">
            You&apos;ll be redirected back after signing in.
          </p>
        )}
      </div>
    </div>
  );
}

// Wrap in Suspense because useSearchParams requires it
export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen flex-col items-center px-4 pt-8 md:pt-16 lg:pt-24">
          <Loader2 className="text-muted-foreground h-8 w-8 animate-spin" />
        </div>
      }
    >
      <LoginContent />
    </Suspense>
  );
}
