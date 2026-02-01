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

/**
 *
 */
interface StepConfig {
  id: AuthStep;
  label: string;
}

/** Step configurations for each flow type */
const FLOW_STEPS: Record<AuthFlowType, StepConfig[]> = {
  new_user: [
    { id: "email", label: "Email" },
    { id: "create_passkey", label: "Passkey Setup" },
    { id: "verify_encryption", label: "Passkey Sign In" },
  ],
  returning_user: [
    { id: "email", label: "Email" },
    { id: "sign_in", label: "Passkey Sign In" },
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

/**
 *
 */
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
      <div
        className="grid"
        style={{ gridTemplateColumns: `repeat(${steps.length}, 1fr)` }}
      >
        {steps.map((step, index) => {
          const isComplete = index < currentIndex;
          const isCurrent = index === currentIndex;
          const isLast = index === steps.length - 1;

          return (
            <div key={step.id} className="flex flex-col items-center">
              {/* Step circle with connector line */}
              <div className="relative flex w-full items-center justify-center">
                {/* Left connector - stops at circle edge */}
                {index > 0 && (
                  <div
                    className={cn(
                      "absolute left-0 h-0.5 w-[calc(50%-24px)]",
                      index <= currentIndex ? "bg-primary" : "bg-muted"
                    )}
                  />
                )}
                {/* Right connector - starts at circle edge */}
                {!isLast && (
                  <div
                    className={cn(
                      "absolute left-[calc(50%+24px)] h-0.5 w-[calc(50%-24px)]",
                      isComplete ? "bg-primary" : "bg-muted"
                    )}
                  />
                )}
                {/* Circle */}
                <div
                  className={cn(
                    "relative z-10 flex h-10 w-10 items-center justify-center rounded-full text-sm font-medium transition-colors",
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
              </div>
              {/* Label */}
              <span
                className={cn(
                  "mt-2 text-center text-xs",
                  isCurrent
                    ? "text-primary font-medium"
                    : "text-muted-foreground"
                )}
              >
                {step.label}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
