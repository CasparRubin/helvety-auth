import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Enable compression
  compress: true,

  // Security headers
  async headers() {
    const isDevelopment = process.env.NODE_ENV === "development";

    // Build headers array
    const headers = [
      {
        key: "X-DNS-Prefetch-Control",
        value: "on",
      },
      {
        key: "X-Frame-Options",
        value: "SAMEORIGIN",
      },
      {
        key: "X-Content-Type-Options",
        value: "nosniff",
      },
      {
        key: "X-XSS-Protection",
        value: "1; mode=block",
      },
      {
        key: "Referrer-Policy",
        value: "strict-origin-when-cross-origin",
      },
      {
        key: "Permissions-Policy",
        value: "camera=(), microphone=(), geolocation=()",
      },
      {
        key: "Content-Security-Policy",
        // Note on 'unsafe-eval' and 'unsafe-inline':
        // - 'unsafe-eval': May be required by some third-party libraries and
        //   Next.js development mode. Could potentially be removed in production
        //   but requires thorough testing.
        // - 'unsafe-inline': Required for Next.js styled-jsx and some React patterns.
        // XSS is mitigated through:
        // - Strict React JSX escaping (no dangerouslySetInnerHTML)
        // - Input validation on all user data
        // - HTTPOnly cookies for authentication
        value: [
          "default-src 'self'",
          "script-src 'self' 'unsafe-eval' 'unsafe-inline'",
          "style-src 'self' 'unsafe-inline'",
          "img-src 'self' data: https: blob:",
          "font-src 'self' data:",
          "connect-src 'self' https://*.supabase.co https://*.supabase.in wss://*.supabase.co",
          "frame-src 'self'",
          "object-src 'none'",
          "base-uri 'self'",
          "form-action 'self'",
          "frame-ancestors 'self'",
          ...(isDevelopment ? [] : ["upgrade-insecure-requests"]),
        ].join("; "),
      },
    ];

    // Production-only security headers
    if (!isDevelopment) {
      headers.push({
        key: "Strict-Transport-Security",
        value: "max-age=63072000; includeSubDomains; preload",
      });
      headers.push({
        key: "Cross-Origin-Opener-Policy",
        value: "same-origin",
      });
      headers.push({
        key: "Cross-Origin-Embedder-Policy",
        value: "require-corp",
      });
    }

    return [
      {
        source: "/:path*",
        headers,
      },
    ];
  },

  // Experimental features for better performance
  experimental: {
    optimizePackageImports: ["lucide-react", "sonner"],
  },
};

export default nextConfig;
