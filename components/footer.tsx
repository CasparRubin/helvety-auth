import { cn } from "@/lib/utils";

const LEGAL_BASE = "https://helvety.com";

/** Site footer: contact email, legal links, and cookie info. */
export function Footer({ className }: { className?: string }) {
  return (
    <footer className={cn("border-border shrink-0 border-t", className)}>
      <div className="mx-auto w-full max-w-[2000px] px-4 py-3">
        <div className="text-muted-foreground flex flex-col items-center gap-1 text-center text-xs">
          <nav className="flex flex-wrap items-center justify-center gap-x-2 gap-y-1">
            <a
              href="mailto:contact@helvety.com"
              className="hover:text-foreground transition-colors"
            >
              contact@helvety.com
            </a>
            <span aria-hidden>·</span>
            <a
              href={`${LEGAL_BASE}/impressum`}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-foreground transition-colors"
            >
              Impressum
            </a>
            <span aria-hidden>·</span>
            <a
              href={`${LEGAL_BASE}/privacy`}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-foreground transition-colors"
            >
              Privacy
            </a>
            <span aria-hidden>·</span>
            <a
              href={`${LEGAL_BASE}/terms`}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-foreground transition-colors"
            >
              Terms
            </a>
          </nav>
          <p className="text-muted-foreground/60 text-[11px]">
            This site uses essential cookies for authentication and security.
          </p>
        </div>
      </div>
    </footer>
  );
}
