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

/** Steps for the email + passkey auth flow */
const STEPS: StepConfig[] = [
  { id: "email", label: "Enter Email" },
  { id: "verify", label: "Verify Email" },
  { id: "passkey", label: "Passkey" },
];

/**
 *
 */
interface AuthStepperProps {
  /** The current step in the flow */
  currentStep: AuthStep;
  /** Optional className for the container */
  className?: string;
}

/**
 * Stepper component for the email + passkey authentication flow.
 * Shows progress through: Enter Email -> Verify Email -> Passkey
 */
export function AuthStepper({ currentStep, className }: AuthStepperProps) {
  const currentIndex = STEPS.findIndex((s) => s.id === currentStep);

  return (
    <div className={cn("mx-auto mb-6 w-full max-w-md", className)}>
      <div className="flex items-center justify-center">
        {STEPS.map((step, index) => {
          const isComplete = index < currentIndex;
          const isCurrent = index === currentIndex;
          const isLast = index === STEPS.length - 1;

          return (
            <div key={step.id} className="flex items-center">
              {/* Step circle and label */}
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

              {/* Connector line */}
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
