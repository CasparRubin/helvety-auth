"use client";

import {
  startRegistration,
  startAuthentication,
} from "@simplewebauthn/browser";
import { Loader2, ArrowLeft, Mail, KeyRound, CheckCircle2 } from "lucide-react";
import Image from "next/image";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, Suspense, useCallback } from "react";

import {
  sendMagicLink,
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  generatePasskeyAuthOptions,
  verifyPasskeyAuthentication,
} from "@/app/actions/passkey-auth-actions";
import { AuthStepper, type AuthStep } from "@/components/auth-stepper";
import { EncryptionSetup } from "@/components/encryption-setup";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { isPasskeySupported } from "@/lib/crypto/passkey";
import { logger } from "@/lib/logger";
import { createClient } from "@/lib/supabase/client";

/**
 *
 */
type LoginStep =
  | "email" // Enter email
  | "email-sent" // Magic link sent, check your email
  | "passkey-setup" // Set up new passkey (deprecated, now uses encryption-setup)
  | "passkey-signin" // Sign in with existing passkey
  | "passkey-verify" // Verify newly created passkey
  | "encryption-setup"; // Set up encryption with passkey

/**
 *
 */
function LoginContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const supabase = createClient();

  const [isLoading, setIsLoading] = useState(false);
  const [email, setEmail] = useState("");
  const [checkingAuth, setCheckingAuth] = useState(true);
  const [passkeySupported, setPasskeySupported] = useState(false);

  // Get parameters from URL
  const redirectUri = searchParams.get("redirect_uri");
  const stepParam = searchParams.get("step") as LoginStep | null;
  const authError = searchParams.get("error");

  // Compute initial step from URL or default to email
  const initialStep: LoginStep =
    stepParam === "passkey-setup" ||
    stepParam === "passkey-signin" ||
    stepParam === "encryption-setup"
      ? stepParam
      : "email";

  // Compute initial error from URL
  const initialError =
    authError === "auth_failed"
      ? "Authentication failed. Please try again."
      : authError === "missing_params"
        ? "Invalid authentication link."
        : "";

  const [step, setStep] = useState<LoginStep>(initialStep);
  const [error, setError] = useState(initialError);
  const [userId, setUserId] = useState<string | null>(null);

  // Initialize: check passkey support and existing session
  useEffect(() => {
    const init = async () => {
      // Check WebAuthn support
      const supported = isPasskeySupported();
      setPasskeySupported(supported);

      // Get current user if any
      const {
        data: { user },
      } = await supabase.auth.getUser();

      // If user is authenticated and we're on passkey or encryption step, stay on that step
      if (
        user &&
        (step === "passkey-setup" ||
          step === "passkey-signin" ||
          step === "passkey-verify" ||
          step === "encryption-setup")
      ) {
        setEmail(user.email ?? "");
        setUserId(user.id);
        setCheckingAuth(false);
        return;
      }

      // If user is authenticated but on email step, they completed auth
      // Redirect to destination if they have a passkey, otherwise show setup
      if (user && step === "email") {
        // Check if coming from a passkey step that was completed
        if (redirectUri) {
          window.location.href = redirectUri;
          return;
        } else if (process.env.NODE_ENV === "production") {
          window.location.href = "https://helvety.com";
          return;
        }
      }

      setCheckingAuth(false);
    };
    void init();
  }, [supabase, step, redirectUri]);

  // Handle email submission - send magic link
  const handleEmailSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError("");
      setIsLoading(true);

      try {
        const result = await sendMagicLink(email, redirectUri ?? undefined);

        if (!result.success) {
          setError(result.error ?? "Failed to send verification email");
          setIsLoading(false);
          return;
        }

        // Move to email-sent step
        setStep("email-sent");
        setIsLoading(false);
      } catch (err) {
        logger.error("Email submission error:", err);
        setError("An unexpected error occurred");
        setIsLoading(false);
      }
    },
    [email, redirectUri]
  );

  // Handle passkey setup (for new users)
  const handlePasskeySetup = useCallback(async () => {
    if (!passkeySupported) {
      setError("Your browser doesn't support passkeys");
      return;
    }

    setError("");
    setIsLoading(true);

    try {
      const origin = window.location.origin;

      // Get registration options
      const optionsResult = await generatePasskeyRegistrationOptions(origin);
      if (!optionsResult.success || !optionsResult.data) {
        setError(optionsResult.error ?? "Failed to start passkey setup");
        setIsLoading(false);
        return;
      }

      // Start WebAuthn registration
      let regResponse;
      try {
        regResponse = await startRegistration({
          optionsJSON: optionsResult.data,
        });
      } catch (err) {
        if (err instanceof Error) {
          if (err.name === "NotAllowedError") {
            setError("Passkey setup was cancelled");
          } else if (err.name === "AbortError") {
            setError("Passkey setup timed out");
          } else {
            setError("Failed to set up passkey");
          }
        } else {
          setError("Failed to set up passkey");
        }
        setIsLoading(false);
        return;
      }

      // Verify registration
      const verifyResult = await verifyPasskeyRegistration(regResponse, origin);
      if (!verifyResult.success) {
        setError(verifyResult.error ?? "Failed to complete passkey setup");
        setIsLoading(false);
        return;
      }

      // Passkey created! Now require verification
      setStep("passkey-verify");
      setIsLoading(false);
    } catch (err) {
      logger.error("Passkey setup error:", err);
      setError("An unexpected error occurred");
      setIsLoading(false);
    }
  }, [passkeySupported]);

  // Handle passkey sign in (for existing users or verification after setup)
  const handlePasskeySignIn = useCallback(async () => {
    if (!passkeySupported) {
      setError("Your browser doesn't support passkeys");
      return;
    }

    setError("");
    setIsLoading(true);

    try {
      const origin = window.location.origin;

      // Get authentication options
      const optionsResult = await generatePasskeyAuthOptions(
        origin,
        redirectUri ?? undefined
      );
      if (!optionsResult.success || !optionsResult.data) {
        setError(
          optionsResult.error ?? "Failed to start passkey authentication"
        );
        setIsLoading(false);
        return;
      }

      // Start WebAuthn authentication
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
        setIsLoading(false);
        return;
      }

      // Verify authentication
      const verifyResult = await verifyPasskeyAuthentication(
        authResponse,
        origin
      );
      if (!verifyResult.success || !verifyResult.data) {
        setError(verifyResult.error ?? "Authentication verification failed");
        setIsLoading(false);
        return;
      }

      // Redirect to auth URL to complete session creation
      window.location.href = verifyResult.data.authUrl;
    } catch (err) {
      logger.error("Passkey auth error:", err);
      setError("An unexpected error occurred");
      setIsLoading(false);
    }
  }, [passkeySupported, redirectUri]);

  // Complete auth after passkey verification
  const handleCompleteAuth = useCallback(() => {
    if (redirectUri) {
      window.location.href = redirectUri;
    } else if (process.env.NODE_ENV === "production") {
      window.location.href = "https://helvety.com";
    } else {
      router.push("/");
    }
  }, [redirectUri, router]);

  // Go back to email step
  const handleBack = () => {
    setStep("email");
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

  // Determine current stepper step
  const currentAuthStep: AuthStep = (() => {
    if (step === "email") return "email";
    if (step === "email-sent") return "verify";
    if (step === "encryption-setup") return "passkey";
    return "passkey";
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

        {/* Show encryption setup component for encryption-setup step */}
        {step === "encryption-setup" && userId && (
          <EncryptionSetup
            userId={userId}
            userEmail={email}
            flowType="new_user"
            redirectUri={redirectUri ?? undefined}
            onComplete={() => {
              // Redirect to destination after encryption setup
              if (redirectUri) {
                window.location.href = redirectUri;
              } else if (process.env.NODE_ENV === "production") {
                window.location.href = "https://helvety.com";
              } else {
                router.push("/");
              }
            }}
          />
        )}

        {/* Show card for other steps */}
        {step !== "encryption-setup" && (
        <Card className="w-full">
          <CardHeader>
            <CardTitle>
              {step === "email" && "Welcome to Helvety"}
              {step === "email-sent" && "Check Your Email"}
              {step === "passkey-setup" && "Set Up Your Passkey"}
              {step === "passkey-signin" && "Sign In with Passkey"}
              {step === "passkey-verify" && "Verify Your Passkey"}
            </CardTitle>
            <CardDescription>
              {step === "email" &&
                "Enter your email to sign in or create an account"}
              {step === "email-sent" &&
                `We sent a verification link to ${email}`}
              {step === "passkey-setup" &&
                "Create a passkey to secure your account"}
              {step === "passkey-signin" && "Use your passkey to sign in"}
              {step === "passkey-verify" &&
                "Verify your new passkey to complete setup"}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {/* Step 1: Email input */}
            {step === "email" && (
              <form onSubmit={handleEmailSubmit} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email">Email address</Label>
                  <Input
                    id="email"
                    type="email"
                    placeholder="you@example.com"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    autoFocus
                    disabled={isLoading}
                  />
                </div>

                {error && (
                  <p className="text-destructive text-center text-sm">
                    {error}
                  </p>
                )}

                <Button
                  type="submit"
                  disabled={isLoading || !email}
                  size="lg"
                  className="w-full"
                >
                  {isLoading ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <Mail className="mr-2 h-4 w-4" />
                  )}
                  Continue
                </Button>

                <p className="text-muted-foreground text-center text-xs">
                  We&apos;ll send you a verification link to sign in securely.
                </p>
              </form>
            )}

            {/* Step 2: Email sent */}
            {step === "email-sent" && (
              <div className="space-y-4">
                <div className="flex items-center justify-center py-4">
                  <div className="bg-primary/10 flex h-16 w-16 items-center justify-center rounded-full">
                    <Mail className="text-primary h-8 w-8" />
                  </div>
                </div>

                <p className="text-muted-foreground text-center text-sm">
                  Click the link in the email to continue. The link will expire
                  in 1 hour.
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
                >
                  <ArrowLeft className="mr-2 h-4 w-4" />
                  Use a different email
                </Button>
              </div>
            )}

            {/* Step 3: Passkey setup (new users) */}
            {step === "passkey-setup" && (
              <div className="space-y-4">
                {!passkeySupported && (
                  <div className="bg-destructive/10 text-destructive rounded-lg p-3 text-sm">
                    Your browser doesn&apos;t support passkeys. Please use a
                    modern browser like Chrome, Safari, or Edge.
                  </div>
                )}

                <div className="flex items-center justify-center py-4">
                  <div className="bg-primary/10 flex h-16 w-16 items-center justify-center rounded-full">
                    {isLoading ? (
                      <Loader2 className="text-primary h-8 w-8 animate-spin" />
                    ) : (
                      <KeyRound className="text-primary h-8 w-8" />
                    )}
                  </div>
                </div>

                <p className="text-muted-foreground text-center text-sm">
                  {isLoading
                    ? "Scan the QR code with your phone and verify with Face ID, fingerprint, or PIN."
                    : "A passkey lets you sign in securely using Face ID, fingerprint, or PIN on your device."}
                </p>

                {error && (
                  <p className="text-destructive text-center text-sm">
                    {error}
                  </p>
                )}

                <Button
                  onClick={handlePasskeySetup}
                  disabled={isLoading || !passkeySupported}
                  size="lg"
                  className="w-full"
                >
                  {isLoading ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <KeyRound className="mr-2 h-4 w-4" />
                  )}
                  {isLoading ? "Setting up passkey..." : "Set Up Passkey"}
                </Button>
              </div>
            )}

            {/* Step 4: Passkey sign in (existing users) */}
            {step === "passkey-signin" && (
              <div className="space-y-4">
                {!passkeySupported && (
                  <div className="bg-destructive/10 text-destructive rounded-lg p-3 text-sm">
                    Your browser doesn&apos;t support passkeys. Please use a
                    modern browser like Chrome, Safari, or Edge.
                  </div>
                )}

                <div className="flex items-center justify-center py-4">
                  <div className="bg-primary/10 flex h-16 w-16 items-center justify-center rounded-full">
                    {isLoading ? (
                      <Loader2 className="text-primary h-8 w-8 animate-spin" />
                    ) : (
                      <KeyRound className="text-primary h-8 w-8" />
                    )}
                  </div>
                </div>

                <p className="text-muted-foreground text-center text-sm">
                  {isLoading
                    ? "Scan the QR code with your phone and verify with Face ID, fingerprint, or PIN."
                    : "Use your passkey to verify your identity and complete sign in."}
                </p>

                {error && (
                  <p className="text-destructive text-center text-sm">
                    {error}
                  </p>
                )}

                <Button
                  onClick={handlePasskeySignIn}
                  disabled={isLoading || !passkeySupported}
                  size="lg"
                  className="w-full"
                >
                  {isLoading ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <KeyRound className="mr-2 h-4 w-4" />
                  )}
                  {isLoading ? "Authenticating..." : "Sign In with Passkey"}
                </Button>
              </div>
            )}

            {/* Step 5: Verify passkey after setup */}
            {step === "passkey-verify" && (
              <div className="space-y-4">
                <div className="flex items-center justify-center py-4">
                  <div className="flex h-16 w-16 items-center justify-center rounded-full bg-green-500/10">
                    {isLoading ? (
                      <Loader2 className="h-8 w-8 animate-spin text-green-500" />
                    ) : (
                      <CheckCircle2 className="h-8 w-8 text-green-500" />
                    )}
                  </div>
                </div>

                <p className="text-muted-foreground text-center text-sm">
                  {isLoading
                    ? "Verifying your passkey..."
                    : "Your passkey has been created! Now verify it to complete your account setup."}
                </p>

                {error && (
                  <p className="text-destructive text-center text-sm">
                    {error}
                  </p>
                )}

                <Button
                  onClick={handlePasskeySignIn}
                  disabled={isLoading || !passkeySupported}
                  size="lg"
                  className="w-full"
                >
                  {isLoading ? (
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  ) : (
                    <KeyRound className="mr-2 h-4 w-4" />
                  )}
                  {isLoading ? "Verifying..." : "Verify Passkey"}
                </Button>

                <Button
                  type="button"
                  variant="ghost"
                  className="w-full"
                  onClick={handleCompleteAuth}
                  disabled={isLoading}
                >
                  Skip for now
                </Button>
              </div>
            )}
          </CardContent>
        </Card>
        )}

        {/* Show where user will be redirected */}
        {redirectUri && step === "email" && (
          <p className="text-muted-foreground text-center text-xs">
            You&apos;ll be redirected back after signing in.
          </p>
        )}
      </div>
    </div>
  );
}

// Wrap in Suspense because useSearchParams requires it
/**
 *
 */
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
