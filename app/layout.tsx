import { Analytics } from "@vercel/analytics/next";
import localFont from "next/font/local";
import "./globals.css";

import { AuthTokenHandler } from "@/components/auth-token-handler";
import { Footer } from "@/components/footer";
import { GeoRestrictionDialog } from "@/components/geo-restriction-dialog";
import { Navbar } from "@/components/navbar";
import { ThemeProvider } from "@/components/theme-provider";
import { Toaster } from "@/components/ui/sonner";
import { TooltipProvider } from "@/components/ui/tooltip";
import { EncryptionProvider } from "@/lib/crypto/encryption-context";

import type { Metadata, Viewport } from "next";

// Local Public Sans variable font - no network fetch during build
const publicSans = localFont({
  src: [
    {
      path: "../node_modules/@fontsource-variable/public-sans/files/public-sans-latin-wght-normal.woff2",
      style: "normal",
    },
    {
      path: "../node_modules/@fontsource-variable/public-sans/files/public-sans-latin-wght-italic.woff2",
      style: "italic",
    },
  ],
  variable: "--font-sans",
  display: "swap",
});

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#000000" },
  ],
};

export const metadata: Metadata = {
  metadataBase: new URL("https://auth.helvety.com"),
  title: {
    default: "Sign In | Helvety",
    template: "%s | Helvety",
  },
  description: "Sign in to your Helvety account",
  keywords: ["Helvety", "sign in", "login", "authentication"],
  authors: [{ name: "Helvety" }],
  creator: "Helvety",
  publisher: "Helvety",
  openGraph: {
    type: "website",
    locale: "en_US",
    url: "https://auth.helvety.com",
    siteName: "Helvety Auth",
    title: "Sign In | Helvety",
    description: "Sign in to your Helvety account",
  },
  twitter: {
    card: "summary",
    title: "Sign In | Helvety",
    description: "Sign in to your Helvety account",
    images: [
      {
        url: "/helvety_Identifier_whiteBg.svg",
      },
    ],
  },
  icons: {
    icon: [{ url: "/helvety_Identifier_whiteBg.svg", type: "image/svg+xml" }],
    apple: [{ url: "/helvety_Identifier_whiteBg.svg", type: "image/svg+xml" }],
  },
  robots: {
    index: false,
    follow: false,
  },
};

/**
 * Root layout: sticky header (Navbar), scrollable main, sticky footer (contact + legal links).
 */
export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={publicSans.variable} suppressHydrationWarning>
      <body className="antialiased">
        <ThemeProvider
          attribute="class"
          defaultTheme="system"
          enableSystem
          disableTransitionOnChange
        >
          <GeoRestrictionDialog>
            <EncryptionProvider>
              <TooltipProvider>
                <AuthTokenHandler />
                <div className="flex min-h-screen flex-col">
                  <header className="shrink-0">
                    <Navbar />
                  </header>
                  <div className="min-h-0 flex-1 overflow-y-auto">
                    <div className="mx-auto w-full max-w-[2000px]">
                      {children}
                    </div>
                  </div>
                  <Footer />
                </div>
                <Toaster />
              </TooltipProvider>
            </EncryptionProvider>
          </GeoRestrictionDialog>
        </ThemeProvider>
        <Analytics />
      </body>
    </html>
  );
}
