const LEGAL_BASE = "https://helvety.com";

/** Sticky site footer: contact email + Impressum, Privacy, Terms (links to helvety.com). */
export function Footer() {
  return (
    <footer className="border-border shrink-0 border-t">
      <div className="mx-auto w-full max-w-[2000px] px-4 py-3">
        <div className="text-muted-foreground flex flex-col items-center gap-1.5 text-center text-xs">
          <a
            href="mailto:contact@helvety.com"
            className="hover:text-foreground transition-colors"
          >
            contact@helvety.com
          </a>
          <nav className="flex flex-wrap items-center justify-center gap-x-2 gap-y-1">
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
        </div>
      </div>
    </footer>
  );
}
