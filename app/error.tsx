"use client";

import { AlertCircle, RefreshCw } from "lucide-react";
import Link from "next/link";
import { useEffect } from "react";

import { Button } from "@/components/ui/button";
import { logger } from "@/lib/logger";

/**
 *
 */
export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    // Log the error to an error reporting service
    logger.error("Application error:", error);
  }, [error]);

  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center px-4">
      <div className="flex flex-col items-center gap-6 text-center">
        <div className="bg-destructive/10 flex size-16 items-center justify-center rounded-full">
          <AlertCircle className="text-destructive size-8" />
        </div>

        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            Something went wrong
          </h1>
          <p className="text-muted-foreground max-w-md">
            An unexpected error occurred. Please try again, or contact support
            if the problem persists.
          </p>
          {error.digest && (
            <p className="text-muted-foreground/70 text-xs">
              Error ID: {error.digest}
            </p>
          )}
        </div>

        <div className="flex gap-3">
          <Button onClick={reset} variant="default">
            <RefreshCw className="size-4" data-icon="inline-start" />
            Try again
          </Button>
          <Button variant="outline" asChild>
            <Link href="/">Go home</Link>
          </Button>
        </div>
      </div>
    </div>
  );
}
