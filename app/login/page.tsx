"use client";

import { startAuthentication } from "@simplewebauthn/browser";
import { Loader2, ArrowLeft, Mail, KeyRound, CheckCircle2 } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState, Suspense, useCallback } from "react";

import {
  sendVerificationCode,
  verifyEmailCode,
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
import { getRequiredAuthStep } from "@/lib/auth-utils";
import { isPasskeySupported } from "@/lib/crypto/passkey";
import { isMobileDevice } from "@/lib/device-utils";
import { logger } from "@/lib/logger";
import { createClient } from "@/lib/supabase/client";

/** Steps in the login flow, rendered sequentially. */
type LoginStep =
  | "email" // Enter email
  | "verify-code" // Enter OTP code from email
  | "passkey-signin" // Sign in with existing passkey
  | "passkey-verify" // Verify newly created passkey
  | "encryption-setup"; // Set up encryption with passkey

/** Main login flow component handling email, OTP verification, and passkey steps. */
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
  const isNewUserParam = searchParams.get("is_new_user");

  // Compute initial step from URL or default to email
  const initialStep: LoginStep =
    stepParam === "passkey-signin" || stepParam === "encryption-setup"
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
  const [isMobile, setIsMobile] = useState(false);
  const [skippedToPasskey, setSkippedToPasskey] = useState(false);
  const [otpCode, setOtpCode] = useState("");
  const [resendCooldown, setResendCooldown] = useState(0);

  // Device detection for passkey flow (client-only, set on mount)
  useEffect(() => {
    const id = setTimeout(() => setIsMobile(isMobileDevice()), 0);
    return () => clearTimeout(id);
  }, []);

  // Resend cooldown timer
  useEffect(() => {
    if (resendCooldown <= 0) return;
    const timer = setInterval(() => {
      setResendCooldown((prev) => Math.max(0, prev - 1));
    }, 1000);
    return () => clearInterval(timer);
  }, [resendCooldown]);

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
        (step === "passkey-signin" ||
          step === "passkey-verify" ||
          step === "encryption-setup")
      ) {
        setEmail(user.email ?? "");
        setUserId(user.id);
        setCheckingAuth(false);
        return;
      }

      // If user is authenticated but on email step, check what they need to complete
      if (user && step === "email") {
        setEmail(user.email ?? "");
        setUserId(user.id);

        // Check passkey/encryption status to determine next step
        const { step: requiredStep } = await getRequiredAuthStep(user.id);

        if (
          requiredStep === "encryption-setup" ||
          requiredStep === "passkey-signin"
        ) {
          // User needs to complete passkey flow - show appropriate step
          setStep(requiredStep);
          setCheckingAuth(false);
          return;
        }

        // requiredStep is "complete" - user has everything set up
        // This shouldn't normally happen (callback handles this),
        // but as a fallback, redirect to final destination
        if (redirectUri) {
          window.location.href = redirectUri;
          return;
        } else {
          // Default to helvety.com when no redirect_uri is provided
          window.location.href = "https://helvety.com";
          return;
        }
      }

      setCheckingAuth(false);
    };
    void init();
  }, [supabase, step, redirectUri]);

  // Handle email submission; sends OTP code for new users (or existing without passkey), otherwise goes to passkey sign-in
  const handleEmailSubmit = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError("");
      setIsLoading(true);

      try {
        const result = await sendVerificationCode(email);

        if (!result.success) {
          setError(result.error ?? "Failed to send verification email");
          setIsLoading(false);
          return;
        }

        if (result.data?.hasPasskey) {
          // Existing user with passkey - go directly to passkey sign-in
          setSkippedToPasskey(true);
          setStep("passkey-signin");
        } else {
          // New user or no passkey - show code input
          setOtpCode("");
          setResendCooldown(120);
          setStep("verify-code");
        }
        setIsLoading(false);
      } catch (err) {
        logger.error("Email submission error:", err);
        setError("An unexpected error occurred");
        setIsLoading(false);
      }
    },
    [email]
  );

  // Handle OTP code verification
  const handleCodeVerify = useCallback(
    async (e: React.FormEvent) => {
      e.preventDefault();
      setError("");
      setIsLoading(true);

      try {
        const result = await verifyEmailCode(email, otpCode);

        if (!result.success) {
          setError(result.error ?? "Verification failed");
          setIsLoading(false);
          return;
        }

        if (result.data) {
          setUserId(result.data.userId);
          setStep(result.data.nextStep);
        }
        setIsLoading(false);
      } catch (err) {
        logger.error("Code verification error:", err);
        setError("An unexpected error occurred");
        setIsLoading(false);
      }
    },
    [email, otpCode]
  );

  // Handle resending OTP code
  const handleResendCode = useCallback(async () => {
    if (resendCooldown > 0) return;

    setError("");
    setIsLoading(true);

    try {
      const result = await sendVerificationCode(email);

      if (!result.success) {
        setError(result.error ?? "Failed to resend code");
      } else {
        setResendCooldown(120);
        setOtpCode("");
      }
      setIsLoading(false);
    } catch (err) {
      logger.error("Resend code error:", err);
      setError("An unexpected error occurred");
      setIsLoading(false);
    }
  }, [email, resendCooldown]);

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
        redirectUri ?? undefined,
        { isMobile: isMobileDevice() }
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

      // Redirect to final destination (session already created server-side)
      window.location.href = verifyResult.data.redirectUrl;
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

  // Auto-trigger passkey authentication for existing users who skipped email verification
  useEffect(() => {
    if (
      step === "passkey-signin" &&
      skippedToPasskey &&
      passkeySupported &&
      !isLoading
    ) {
      // Small delay to allow UI to render first
      const timer = setTimeout(() => {
        void handlePasskeySignIn();
      }, 100);
      return () => clearTimeout(timer);
    }
    return undefined;
  }, [
    step,
    skippedToPasskey,
    passkeySupported,
    isLoading,
    handlePasskeySignIn,
  ]);

  // Go back to email step
  const handleBack = () => {
    setStep("email");
    setError("");
    setIsLoading(false);
    setSkippedToPasskey(false);
    setOtpCode("");
    setResendCooldown(0);
  };

  // Show loading while checking auth
  if (checkingAuth) {
    return (
      <div className="flex flex-col items-center px-4 pt-8 md:pt-16 lg:pt-24">
        <Loader2 className="text-muted-foreground h-8 w-8 animate-spin" />
      </div>
    );
  }

  // Determine current stepper step
  const currentAuthStep: AuthStep = (() => {
    if (step === "email") return "email";
    if (step === "verify-code") return "verify";
    if (step === "encryption-setup") return "passkey";
    return "passkey";
  })();

  // Determine if this is a returning user (has passkey) for stepper display
  // From URL param (callback) or from having skipped to passkey after email submit
  const isReturningUser = isNewUserParam === "false" || skippedToPasskey;

  return (
    <div className="flex flex-col items-center px-4 pt-8 md:pt-16 lg:pt-24">
      <div className="flex w-full max-w-md flex-col items-center space-y-6">
        {/* Show stepper - hidden when EncryptionSetup is shown (it has its own stepper) */}
        {step !== "encryption-setup" && (
          <AuthStepper
            currentStep={currentAuthStep}
            isReturningUser={isReturningUser}
          />
        )}

        {/* Show encryption setup component for encryption-setup step */}
        {step === "encryption-setup" && userId && (
          <EncryptionSetup
            userId={userId}
            userEmail={email}
            flowType={isReturningUser ? "returning_user" : "new_user"}
            redirectUri={redirectUri ?? undefined}
          />
        )}

        {/* Show card for other steps */}
        {step !== "encryption-setup" && (
          <Card className="w-full">
            <CardHeader>
              <CardTitle>
                {step === "email" && "Welcome to Helvety"}
                {step === "verify-code" && "Check Your Email"}
                {step === "passkey-signin" && "Sign In with Passkey"}
                {step === "passkey-verify" && "Verify Your Passkey"}
              </CardTitle>
              <CardDescription>
                {step === "email" &&
                  "Enter your email to sign in or create an account"}
                {step === "verify-code" &&
                  `We sent a verification code to ${email}. Check your spam folder if you don\u2019t see it.`}
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
                    We&apos;ll send a verification code only if you&apos;re new;
                    otherwise sign in with your passkey.
                  </p>
                </form>
              )}

              {/* Step 2: Enter verification code */}
              {step === "verify-code" && (
                <form onSubmit={handleCodeVerify} className="space-y-4">
                  <div className="flex items-center justify-center py-4">
                    <div className="bg-primary/10 flex h-16 w-16 items-center justify-center rounded-full">
                      <Mail className="text-primary h-8 w-8" />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="otp-code">Verification code</Label>
                    <Input
                      id="otp-code"
                      type="text"
                      inputMode="numeric"
                      pattern="[0-9]*"
                      maxLength={8}
                      placeholder="00000000"
                      value={otpCode}
                      onChange={(e) => {
                        const value = e.target.value.replace(/\D/g, "");
                        setOtpCode(value);
                      }}
                      required
                      autoFocus
                      disabled={isLoading}
                      className="text-center text-2xl tracking-[0.3em]"
                      autoComplete="one-time-code"
                    />
                  </div>

                  <p className="text-muted-foreground text-center text-sm">
                    Enter the code we sent to your email. The code expires in 1
                    hour.
                  </p>

                  {error && (
                    <p className="text-destructive text-center text-sm">
                      {error}
                    </p>
                  )}

                  <Button
                    type="submit"
                    disabled={isLoading || otpCode.length < 6}
                    size="lg"
                    className="w-full"
                  >
                    {isLoading ? (
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    ) : (
                      <Mail className="mr-2 h-4 w-4" />
                    )}
                    Verify Code
                  </Button>

                  <div className="flex flex-col gap-2">
                    <Button
                      type="button"
                      variant="ghost"
                      className="w-full"
                      onClick={handleResendCode}
                      disabled={isLoading || resendCooldown > 0}
                    >
                      {resendCooldown > 0
                        ? `Resend code (${resendCooldown}s)`
                        : "Resend code"}
                    </Button>

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
                </form>
              )}

              {/* Step 3: Passkey sign in (existing users) */}
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
                      ? isMobile
                        ? "Use Face ID, fingerprint, or PIN on this device."
                        : "Scan the QR code with your phone and verify with Face ID, fingerprint, or PIN."
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

/** Login page wrapped in Suspense (required by useSearchParams). */
export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="flex flex-col items-center px-4 pt-8 md:pt-16 lg:pt-24">
          <Loader2 className="text-muted-foreground h-8 w-8 animate-spin" />
        </div>
      }
    >
      <LoginContent />
    </Suspense>
  );
}
