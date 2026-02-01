import type { MetadataRoute } from "next";

/**
 * Sitemap for helvety-auth
 * Minimal sitemap for auth service - most pages should not be indexed
 */
export default function sitemap(): MetadataRoute.Sitemap {
  return [
    {
      url: "https://auth.helvety.com",
      lastModified: new Date(),
      changeFrequency: "monthly",
      priority: 0.1,
    },
  ];
}
