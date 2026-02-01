"use client";

import { Check } from "lucide-react";

import { cn } from "@/lib/utils";

/** Type of authentication/encryption flow */
export type AuthFlowType = "new_user" | "returning_user";

/** Steps in the encryption flow */
export type AuthStep =
  | "email"
  | "create_passkey"
  | "verify_encryption"
  | "sign_in";

interface StepConfig {
  id: AuthStep;
  label: string;
}

/** Step configurations for each flow type */
const FLOW_STEPS: Record<AuthFlowType, StepConfig[]> = {
  new_user: [
    { id: "email", label: "Email" },
    { id: "create_passkey", label: "Setup Passkey" },
    { id: "verify_encryption", label: "Verify" },
  ],
  returning_user: [
    { id: "email", label: "Email" },
    { id: "sign_in", label: "Unlock" },
  ],
};

/**
 * Get the auth step based on setup step (used by encryption-setup)
 */
export function getSetupStep(
  setupStep:
    | "initial"
    | "registering"
    | "ready_to_sign_in"
    | "signing_in"
    | "complete"
): AuthStep {
  switch (setupStep) {
    case "initial":
    case "registering":
      return "create_passkey";
    case "ready_to_sign_in":
    case "signing_in":
    case "complete":
      return "verify_encryption";
  }
}

interface AuthStepperProps {
  flowType: AuthFlowType;
  currentStep: AuthStep;
  className?: string;
}

/**
 * Stepper component for the encryption setup/unlock flow.
 */
export function AuthStepper({
  flowType,
  currentStep,
  className,
}: AuthStepperProps) {
  const steps = FLOW_STEPS[flowType];
  const currentIndex = steps.findIndex((s) => s.id === currentStep);

  return (
    <div className={cn("mx-auto mb-6 w-full max-w-md", className)}>
      <div className="flex items-center justify-center">
        {steps.map((step, index) => {
          const isComplete = index < currentIndex;
          const isCurrent = index === currentIndex;
          const isLast = index === steps.length - 1;

          return (
            <div key={step.id} className="flex items-center">
              <div className="flex flex-col items-center">
                <div
                  className={cn(
                    "flex h-10 w-10 items-center justify-center rounded-full text-sm font-medium transition-colors",
                    isComplete && "bg-primary text-primary-foreground",
                    isCurrent &&
                      "bg-primary/20 text-primary border-primary border-2",
                    !isComplete &&
                      !isCurrent &&
                      "bg-muted text-muted-foreground"
                  )}
                >
                  {isComplete ? <Check className="h-5 w-5" /> : index + 1}
                </div>
                <span
                  className={cn(
                    "mt-2 text-xs whitespace-nowrap",
                    isCurrent
                      ? "text-primary font-medium"
                      : "text-muted-foreground"
                  )}
                >
                  {step.label}
                </span>
              </div>

              {!isLast && (
                <div
                  className={cn(
                    "mx-2 mb-6 h-0.5 w-12",
                    isComplete ? "bg-primary" : "bg-muted"
                  )}
                />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
