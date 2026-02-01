"use client";

import {
  Fingerprint,
  ShieldCheck,
  AlertTriangle,
  Loader2,
  Smartphone,
  CheckCircle2,
} from "lucide-react";
import { useRouter } from "next/navigation";
import { useState, useEffect, useRef } from "react";

import {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  savePasskeyParams,
} from "@/app/actions/passkey-auth-actions";
import {
  AuthStepper,
  getSetupStep,
  type AuthFlowType,
} from "@/components/encryption-stepper";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { useEncryptionContext, PRF_VERSION } from "@/lib/crypto";
import { storeMasterKey } from "@/lib/crypto/key-storage";
import {
  registerPasskey,
  authenticatePasskeyWithEncryption,
} from "@/lib/crypto/passkey";
import {
  deriveKeyFromPRF,
} from "@/lib/crypto/prf-key-derivation";
import { logger } from "@/lib/logger";

interface EncryptionSetupProps {
  userId: string;
  userEmail: string;
  flowType?: AuthFlowType;
  redirectUri?: string;
  onComplete?: () => void;
}

/** Setup step for tracking progress through the flow */
type SetupStep =
  | "initial"
  | "registering"
  | "ready_to_sign_in"
  | "signing_in"
  | "complete";

/** Data stored after registration, needed for sign-in step */
interface RegistrationData {
  credentialId: string;
  prfParams: { prfSalt: string; version: number };
}

/**
 * Component for setting up encryption with passkey
 * Uses WebAuthn PRF extension to derive encryption keys from device biometrics
 * Also registers the passkey for authentication (passwordless login)
 *
 * Flow: initial → registering → ready_to_sign_in → signing_in → complete
 * 1. User clicks "Set Up with Phone" → creates passkey on phone
 * 2. User clicks "Sign In with Phone" → authenticates to derive encryption key
 */
export function EncryptionSetup({
  userId,
  userEmail: _userEmail,
  flowType = "new_user",
  redirectUri,
  onComplete,
}: EncryptionSetupProps) {
  const router = useRouter();
  const {
    prfSupported,
    prfSupportInfo,
    checkPRFSupport,
    isLoading: contextLoading,
  } = useEncryptionContext();

  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isCheckingSupport, setIsCheckingSupport] = useState(true);
  const [setupStep, setSetupStep] = useState<SetupStep>("initial");
  const [registrationData, setRegistrationData] =
    useState<RegistrationData | null>(null);
  const setupInProgressRef = useRef(false);

  // Get the current auth step for the stepper
  const currentAuthStep = getSetupStep(setupStep);

  // Check PRF support on mount
  useEffect(() => {
    const checkSupport = async () => {
      await checkPRFSupport();
      setIsCheckingSupport(false);
    };
    void checkSupport();
  }, [checkPRFSupport]);

  // Reset to initial state (used when cancelling during registration)
  const resetSetup = () => {
    setSetupStep("initial");
    setRegistrationData(null);
    setIsLoading(false);
    setError("");
    setupInProgressRef.current = false;
  };

  // Step 1: Handle passkey registration only
  const handleSetup = async () => {
    // Prevent double submission
    if (setupInProgressRef.current) return;
    setupInProgressRef.current = true;

    setError("");
    setIsLoading(true);

    try {
      const origin = window.location.origin;

      // Generate server-side registration options for auth (includes PRF salt)
      const serverOptions = await generatePasskeyRegistrationOptions(origin);
      if (!serverOptions.success || !serverOptions.data) {
        setError(
          serverOptions.error ?? "Failed to generate registration options"
        );
        resetSetup();
        return;
      }

      // Extract PRF salt from server options
      const prfSalt = serverOptions.data.prfSalt;

      // Show registering step UI before triggering WebAuthn
      setSetupStep("registering");

      let regResult;
      try {
        // Cast to allow PRF extension (not in standard types but supported by browsers)
        const optionsWithPRF = serverOptions.data as Parameters<
          typeof registerPasskey
        >[0] & {
          extensions?: Record<string, unknown>;
        };

        // Add PRF extension for encryption key derivation
        optionsWithPRF.extensions = {
          ...(optionsWithPRF.extensions ?? {}),
          prf: {
            eval: {
              first: new Uint8Array(Buffer.from(prfSalt, "base64")),
            },
          },
        };

        regResult = await registerPasskey(optionsWithPRF);
      } catch (err) {
        const message =
          err instanceof Error ? err.message : "Passkey registration failed";
        // Check if user cancelled
        if (err instanceof Error && err.name === "NotAllowedError") {
          setError("Passkey creation was cancelled. Please try again.");
        } else {
          setError(message);
        }
        resetSetup();
        return;
      }

      if (!regResult.prfEnabled) {
        setError(
          "Your authenticator does not support encryption. Please try a different device."
        );
        resetSetup();
        return;
      }

      // Verify and store credential for authentication (server-side)
      const verifyResult = await verifyPasskeyRegistration(
        regResult.response,
        origin,
        true // PRF was enabled
      );
      if (!verifyResult.success) {
        // Log but don't fail - encryption is more important
        logger.warn("Failed to store auth credential:", verifyResult.error);
        // Continue with encryption setup
      }

      // Store registration data for the sign-in step
      setRegistrationData({
        credentialId: regResult.credentialId,
        prfParams: { prfSalt, version: PRF_VERSION },
      });

      // Move to ready_to_sign_in state - user must click button to proceed
      setSetupStep("ready_to_sign_in");
      setIsLoading(false);
      setupInProgressRef.current = false;
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "An unexpected error occurred";
      setError(message);
      resetSetup();
    }
  };

  // Step 2: Handle sign-in to complete encryption setup
  const handleSignIn = async () => {
    if (!registrationData) {
      setError("Registration data not found. Please start over.");
      resetSetup();
      return;
    }

    setError("");
    setIsLoading(true);
    setSetupStep("signing_in");

    try {
      let authResult;
      try {
        authResult = await authenticatePasskeyWithEncryption(
          [registrationData.credentialId],
          registrationData.prfParams.prfSalt
        );
      } catch (err) {
        const message =
          err instanceof Error
            ? err.message
            : "Failed to authenticate for encryption";
        // Check if user cancelled - they can retry since passkey is already created
        if (err instanceof Error && err.name === "NotAllowedError") {
          setError("Sign in was cancelled. Please try again.");
        } else {
          setError(message);
        }
        // Go back to ready_to_sign_in so user can retry
        setSetupStep("ready_to_sign_in");
        setIsLoading(false);
        return;
      }

      if (!authResult.prfOutput) {
        setError(
          "Failed to get encryption key from passkey. Please try again."
        );
        setSetupStep("ready_to_sign_in");
        setIsLoading(false);
        return;
      }

      // Derive master key from PRF output
      const masterKey = await deriveKeyFromPRF(
        authResult.prfOutput,
        registrationData.prfParams
      );

      // Cache the master key
      await storeMasterKey(userId, masterKey);

      // Save encryption params to database
      const saveResult = await savePasskeyParams({
        prf_salt: registrationData.prfParams.prfSalt,
        credential_id: registrationData.credentialId,
        version: registrationData.prfParams.version,
      });

      if (!saveResult.success) {
        setError(saveResult.error ?? "Failed to save passkey settings");
        setSetupStep("ready_to_sign_in");
        setIsLoading(false);
        return;
      }

      // Mark as complete before redirect
      setSetupStep("complete");

      // Success - redirect or callback
      if (onComplete) {
        onComplete();
      } else if (redirectUri) {
        window.location.href = redirectUri;
      } else {
        router.push("/");
      }
    } catch (err) {
      const message =
        err instanceof Error ? err.message : "An unexpected error occurred";
      setError(message);
      setSetupStep("ready_to_sign_in");
      setIsLoading(false);
    }
  };

  // Show loading while checking PRF support
  if (isCheckingSupport || contextLoading) {
    return (
      <div className="flex w-full max-w-md flex-col items-center">
        <AuthStepper flowType={flowType} currentStep="create_passkey" />
        <Card className="w-full">
          <CardContent className="flex items-center justify-center py-12">
            <Loader2 className="text-muted-foreground h-8 w-8 animate-spin" />
          </CardContent>
        </Card>
      </div>
    );
  }

  // Show unsupported message if PRF is not available
  if (prfSupported === false) {
    return (
      <div className="flex w-full max-w-md flex-col items-center">
        <AuthStepper flowType={flowType} currentStep="create_passkey" />
        <Card className="w-full">
          <CardHeader className="space-y-1">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              <CardTitle>Browser Not Supported</CardTitle>
            </div>
            <CardDescription>
              Your browser doesn&apos;t support passkey encryption with your
              phone.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="rounded-lg border border-amber-500/50 bg-amber-500/10 p-3">
              <p className="text-sm text-amber-500">
                {prfSupportInfo?.reason ??
                  "Phone passkey encryption is not supported"}
              </p>
            </div>
            <div className="text-muted-foreground text-sm">
              <p className="mb-2 font-medium">Supported browsers:</p>
              <ul className="list-inside list-disc space-y-1">
                <li>Chrome 128+ or Edge 128+ on desktop</li>
                <li>Safari 18+ on Mac</li>
              </ul>
              <p className="mt-3 mb-2 font-medium">Supported phones:</p>
              <ul className="list-inside list-disc space-y-1">
                <li>iPhone with iOS 18+</li>
                <li>Android 14+ with Chrome</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Show registering state - waiting for passkey creation
  if (setupStep === "registering") {
    return (
      <div className="flex w-full max-w-md flex-col items-center">
        <AuthStepper flowType={flowType} currentStep={currentAuthStep} />
        <Card className="w-full">
          <CardHeader className="space-y-1">
            <div className="flex items-center gap-2">
              <ShieldCheck className="text-primary h-5 w-5" />
              <CardTitle>Create Passkey</CardTitle>
            </div>
            <CardDescription>Save the passkey to your phone</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3 rounded-lg border p-4">
              <div className="flex items-center gap-3">
                <div className="bg-primary/10 flex h-10 w-10 items-center justify-center rounded-full">
                  <Loader2 className="text-primary h-5 w-5 animate-spin" />
                </div>
                <div>
                  <p className="font-medium">Scan QR Code</p>
                  <p className="text-muted-foreground text-sm">
                    Use your phone to scan the QR code
                  </p>
                </div>
              </div>

              <div className="border-t pt-2">
                <p className="text-muted-foreground text-sm">
                  Scan the QR code with your phone and save the passkey using
                  Face ID or fingerprint.
                </p>
              </div>
            </div>

            {error && <p className="text-destructive text-sm">{error}</p>}

            <div className="flex items-center justify-center py-2">
              <p className="text-muted-foreground text-sm">
                Waiting for your phone...
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Show ready_to_sign_in state - passkey created, waiting for user to click sign in
  if (setupStep === "ready_to_sign_in") {
    return (
      <div className="flex w-full max-w-md flex-col items-center">
        <AuthStepper flowType={flowType} currentStep={currentAuthStep} />
        <Card className="w-full">
          <CardHeader className="space-y-1">
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-green-500" />
              <CardTitle>Passkey Created</CardTitle>
            </div>
            <CardDescription>
              Now sign in with your passkey to complete setup
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="rounded-lg border border-green-500/50 bg-green-500/10 p-3">
              <p className="text-sm text-green-600 dark:text-green-400">
                Your passkey has been saved to your phone. Sign in once more to
                activate encryption.
              </p>
            </div>

            {error && <p className="text-destructive text-sm">{error}</p>}

            <Button
              onClick={handleSignIn}
              className="w-full"
              disabled={isLoading}
              size="lg"
            >
              <Smartphone className="mr-2 h-4 w-4" />
              Sign In with Phone
            </Button>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Show signing_in state - waiting for passkey authentication
  if (setupStep === "signing_in") {
    return (
      <div className="flex w-full max-w-md flex-col items-center">
        <AuthStepper flowType={flowType} currentStep={currentAuthStep} />
        <Card className="w-full">
          <CardHeader className="space-y-1">
            <div className="flex items-center gap-2">
              <ShieldCheck className="text-primary h-5 w-5" />
              <CardTitle>Sign In</CardTitle>
            </div>
            <CardDescription>
              Authenticate with your passkey to complete setup
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-3 rounded-lg border p-4">
              <div className="flex items-center gap-3">
                <div className="bg-primary/10 flex h-10 w-10 items-center justify-center rounded-full">
                  <Loader2 className="text-primary h-5 w-5 animate-spin" />
                </div>
                <div>
                  <p className="font-medium">Scan QR Code</p>
                  <p className="text-muted-foreground text-sm">
                    Use your phone to scan the QR code
                  </p>
                </div>
              </div>

              <div className="border-t pt-2">
                <p className="text-muted-foreground text-sm">
                  Scan the QR code with your phone and authenticate using Face
                  ID or fingerprint.
                </p>
              </div>
            </div>

            {error && <p className="text-destructive text-sm">{error}</p>}

            <div className="flex items-center justify-center py-2">
              <p className="text-muted-foreground text-sm">
                Waiting for your phone...
              </p>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  // Initial state - show setup introduction
  return (
    <div className="flex w-full max-w-md flex-col items-center">
      <AuthStepper flowType={flowType} currentStep="create_passkey" />
      <Card className="w-full">
        <CardHeader className="space-y-1">
          <div className="flex items-center gap-2">
            <ShieldCheck className="text-primary h-5 w-5" />
            <CardTitle>Set Up Encryption</CardTitle>
          </div>
          <CardDescription>
            Use your iPhone, iPad, or Android phone to secure your data with
            end-to-end encryption.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="rounded-lg border border-amber-500/50 bg-amber-500/10 p-3">
            <div className="flex gap-2">
              <AlertTriangle className="h-5 w-5 flex-shrink-0 text-amber-500" />
              <div className="text-sm text-amber-500">
                <p className="font-medium">Important</p>
                <p className="mt-1 text-amber-500/80">
                  Your passkey is the only way to decrypt your data. If you
                  remove the passkey from your phone, your data cannot be
                  recovered.
                </p>
              </div>
            </div>
          </div>

          <div className="space-y-3 rounded-lg border p-4">
            <div className="flex items-center gap-3">
              <div className="bg-primary/10 flex h-10 w-10 items-center justify-center rounded-full">
                <Fingerprint className="text-primary h-5 w-5" />
              </div>
              <div>
                <p className="font-medium">Phone Passkey</p>
                <p className="text-muted-foreground text-sm">
                  Secured with Face ID or fingerprint
                </p>
              </div>
            </div>
            <ul className="text-muted-foreground ml-13 space-y-1 text-sm">
              <li>• Scan QR code with your phone</li>
              <li>• Verify with Face ID or fingerprint</li>
              <li>• Your data stays encrypted</li>
            </ul>
          </div>

          {error && <p className="text-destructive text-sm">{error}</p>}

          <Button
            onClick={handleSetup}
            className="w-full"
            disabled={isLoading}
            size="lg"
          >
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Preparing...
              </>
            ) : (
              <>
                <Smartphone className="mr-2 h-4 w-4" />
                Set Up with Phone
              </>
            )}
          </Button>

          <p className="text-muted-foreground text-center text-xs">
            You&apos;ll scan two QR codes with your phone to complete setup.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
