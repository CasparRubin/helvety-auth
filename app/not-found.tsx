import { FileQuestion, ArrowLeft } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/ui/button";

/**
 * Global 404 not found page for Next.js App Router
 *
 * Displays a user-friendly message when a page is not found.
 */
export default function NotFound() {
  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center px-4">
      <div className="flex flex-col items-center gap-6 text-center">
        <div className="bg-muted flex size-16 items-center justify-center rounded-full">
          <FileQuestion className="text-muted-foreground size-8" />
        </div>

        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">
            Page not found
          </h1>
          <p className="text-muted-foreground max-w-md">
            The page you&apos;re looking for doesn&apos;t exist or may have been
            moved.
          </p>
        </div>

        <Button asChild>
          <Link href="/">
            <ArrowLeft className="size-4" data-icon="inline-start" />
            Go home
          </Link>
        </Button>
      </div>
    </div>
  );
}
