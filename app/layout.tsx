import { Analytics } from "@vercel/analytics/react";
import { SpeedInsights } from "@vercel/speed-insights/next";
import localFont from "next/font/local";
import { Suspense } from "react";
import "./globals.css";

import { AuthTokenHandler } from "@/components/auth-token-handler";
import { Navbar } from "@/components/navbar";
import { ThemeProvider } from "@/components/theme-provider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";

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
        url: "/Identifier_whiteBg.png",
      },
    ],
  },
  icons: {
    icon: [
      { url: "/Identifier_whiteBg.png", type: "image/png" },
      { url: "/Identifier_whiteBg.svg", type: "image/svg+xml" },
    ],
    apple: "/Identifier_whiteBg.png",
  },
  robots: {
    index: false,
    follow: false,
  },
};

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
          <TooltipProvider>
            <Suspense>
              <AuthTokenHandler />
            </Suspense>
            <Navbar />
            <div className="mx-auto w-full max-w-[2000px]">{children}</div>
            <Toaster position="top-center" />
          </TooltipProvider>
        </ThemeProvider>
        <Analytics />
        <SpeedInsights />
      </body>
    </html>
  );
}
