import type { MetadataRoute } from "next";

/**
 * Robots configuration for helvety-auth
 * Auth service pages should not be indexed by search engines
 */
export default function robots(): MetadataRoute.Robots {
  return {
    rules: {
      userAgent: "*",
      disallow: "/",
    },
    sitemap: "https://auth.helvety.com/sitemap.xml",
  };
}
