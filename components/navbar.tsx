"use client";

import { Building2, Scale, FileText } from "lucide-react";
import Image from "next/image";

import { AppSwitcher } from "@/components/app-switcher";
import { ThemeSwitcher } from "@/components/theme-switcher";
import { Button } from "@/components/ui/button";
import { TooltipProvider } from "@/components/ui/tooltip";

export function Navbar() {
  const navLinks = [
    {
      href: "https://helvety.com/impressum",
      label: "Impressum",
      icon: Building2,
    },
    { href: "https://helvety.com/privacy", label: "Privacy", icon: Scale },
    { href: "https://helvety.com/terms", label: "Terms", icon: FileText },
  ];

  return (
    <TooltipProvider>
      <nav className="bg-background/95 supports-[backdrop-filter]:bg-background/60 sticky top-0 z-50 w-full border-b backdrop-blur">
        <div className="container mx-auto flex h-16 items-center justify-between gap-4 px-4">
          <div className="flex min-w-0 flex-1 items-center gap-3">
            <AppSwitcher currentApp="Auth" />
            <a
              href="https://helvety.com"
              target="_blank"
              rel="noopener noreferrer"
              className="flex shrink-0 items-center gap-3 transition-opacity hover:opacity-80"
              aria-label="Visit Helvety.com"
            >
              <Image
                src="/logo_whiteBg.svg"
                alt="Helvety"
                width={120}
                height={30}
                className="hidden h-8 w-auto sm:block"
                priority
              />
              <Image
                src="/Identifier_whiteBg.svg"
                alt="Helvety"
                width={30}
                height={30}
                className="h-8 w-auto sm:hidden"
                priority
              />
            </a>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            {/* Desktop navigation links */}
            <div className="hidden items-center gap-1 md:flex">
              {navLinks.map((link) => (
                <Button key={link.href} variant="ghost" size="sm" asChild>
                  <a href={link.href} target="_blank" rel="noopener noreferrer">
                    {link.label}
                  </a>
                </Button>
              ))}
            </div>

            <ThemeSwitcher />
          </div>
        </div>
      </nav>
    </TooltipProvider>
  );
}
