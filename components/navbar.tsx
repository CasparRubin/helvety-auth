"use client";

import {
  LogOut,
  User,
  Building2,
  Scale,
  FileText,
  Settings,
} from "lucide-react";
import Image from "next/image";
import { useEffect, useState } from "react";

import { AppSwitcher } from "@/components/app-switcher";
import { ThemeSwitcher } from "@/components/theme-switcher";
import { Button } from "@/components/ui/button";
import {
  Popover,
  PopoverContent,
  PopoverDescription,
  PopoverHeader,
  PopoverTitle,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Separator } from "@/components/ui/separator";
import { TooltipProvider } from "@/components/ui/tooltip";
import { createClient } from "@/lib/supabase/client";

import type { User as SupabaseUser } from "@supabase/supabase-js";

/**
 *
 */
export function Navbar() {
  const supabase = createClient();
  const [user, setUser] = useState<SupabaseUser | null>(null);
  const [profileOpen, setProfileOpen] = useState(false);

  useEffect(() => {
    const getUser = async () => {
      const {
        data: { user },
      } = await supabase.auth.getUser();
      setUser(user);
    };
    void getUser();

    // Listen for auth state changes
    const {
      data: { subscription },
    } = supabase.auth.onAuthStateChange((_event, session) => {
      setUser(session?.user ?? null);
    });

    return () => {
      subscription.unsubscribe();
    };
  }, [supabase.auth]);

  const handleLogout = () => {
    // Get current origin for redirect after logout
    const origin = typeof window !== "undefined" ? window.location.origin : "";
    window.location.href = `/logout?redirect_uri=${encodeURIComponent(origin)}`;
  };

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

            {/* Profile menu - only show when authenticated */}
            {user && (
              <Popover open={profileOpen} onOpenChange={setProfileOpen}>
                <PopoverTrigger asChild>
                  <Button variant="ghost" size="icon">
                    <User className="h-5 w-5" />
                  </Button>
                </PopoverTrigger>
                <PopoverContent align="end" className="w-80">
                  <PopoverHeader>
                    <div className="flex items-center gap-3">
                      <div className="bg-primary/10 flex h-10 w-10 items-center justify-center rounded-full">
                        <User className="text-primary h-5 w-5" />
                      </div>
                      <div className="min-w-0 flex-1">
                        <PopoverTitle>Account</PopoverTitle>
                        <PopoverDescription className="truncate">
                          {user.email ?? "Signed in"}
                        </PopoverDescription>
                      </div>
                    </div>
                  </PopoverHeader>
                  <Separator />
                  <div className="flex flex-col gap-2">
                    <Button
                      variant="outline"
                      className="w-full justify-start"
                      asChild
                    >
                      <a
                        href="https://store.helvety.com/account"
                        target="_blank"
                        rel="noopener noreferrer"
                      >
                        <Settings className="h-4 w-4" />
                        Account
                      </a>
                    </Button>
                    <Button
                      variant="destructive"
                      className="w-full justify-start"
                      onClick={() => {
                        setProfileOpen(false);
                        handleLogout();
                      }}
                    >
                      <LogOut className="h-4 w-4" />
                      Sign out
                    </Button>
                  </div>
                </PopoverContent>
              </Popover>
            )}
          </div>
        </div>
      </nav>
    </TooltipProvider>
  );
}
