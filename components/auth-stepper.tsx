"use client";

import { Check } from "lucide-react";

import { cn } from "@/lib/utils";

/** Steps in the email + passkey authentication flow */
export type AuthStep = "email" | "verify" | "passkey";

/**
 *
 */
interface StepConfig {
  id: AuthStep;
  label: string;
}

/** Steps for new users: Email → Passkey Setup → Passkey Sign In */
const NEW_USER_STEPS: StepConfig[] = [
  { id: "email", label: "Email" },
  { id: "verify", label: "Passkey Setup" },
  { id: "passkey", label: "Passkey Sign In" },
];

/** Steps for returning users: Email → Passkey Sign In */
const RETURNING_USER_STEPS: StepConfig[] = [
  { id: "email", label: "Email" },
  { id: "passkey", label: "Passkey Sign In" },
];

/**
 *
 */
interface AuthStepperProps {
  /** The current step in the flow */
  currentStep: AuthStep;
  /** Whether this is a returning user (has passkey) - shows 2 steps instead of 3 */
  isReturningUser?: boolean;
  /** Optional className for the container */
  className?: string;
}

/**
 * Stepper component for the email + passkey authentication flow.
 * Shows progress through:
 * - New users: Email → Passkey Setup → Passkey Sign In
 * - Returning users: Email → Passkey Sign In (skip magic link, go straight to passkey)
 */
export function AuthStepper({
  currentStep,
  isReturningUser = false,
  className,
}: AuthStepperProps) {
  const steps = isReturningUser ? RETURNING_USER_STEPS : NEW_USER_STEPS;
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
