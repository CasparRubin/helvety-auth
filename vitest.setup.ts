import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// =============================================================================
// NEXT.JS MOCKS (all projects)
// =============================================================================
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
    refresh: vi.fn(),
  }),
  usePathname: () => "/",
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
}));

vi.mock("next-themes", () => ({
  useTheme: () => ({
    theme: "light",
    setTheme: vi.fn(),
    resolvedTheme: "light",
    themes: ["light", "dark", "system"],
  }),
  ThemeProvider: ({ children }: { children: React.ReactNode }) => children,
}));

// =============================================================================
// CRYPTO MOCKS (for projects using encryption)
// =============================================================================
if (typeof globalThis.crypto === "undefined") {
  Object.defineProperty(globalThis, "crypto", {
    value: {
      getRandomValues: <T extends ArrayBufferView | null>(array: T): T => {
        if (array) {
          const bytes = array as unknown as Uint8Array;
          for (let i = 0; i < bytes.length; i++) {
            bytes[i] = Math.floor(Math.random() * 256);
          }
        }
        return array;
      },
      subtle: {
        encrypt: vi.fn(),
        decrypt: vi.fn(),
        generateKey: vi.fn(),
        importKey: vi.fn(),
        deriveKey: vi.fn(),
      },
    },
    configurable: true,
  });
}

// Mock btoa and atob for Node.js
if (typeof globalThis.btoa === "undefined") {
  globalThis.btoa = (str: string) =>
    Buffer.from(str, "binary").toString("base64");
}

if (typeof globalThis.atob === "undefined") {
  globalThis.atob = (str: string) =>
    Buffer.from(str, "base64").toString("binary");
}

// =============================================================================
// WEBAUTHN MOCKS (for projects using passkeys)
// =============================================================================
// Only define browser-specific mocks when running in jsdom environment
if (typeof window !== "undefined") {
  const mockCredentialsContainer = {
    create: vi.fn(),
    get: vi.fn(),
  };

  Object.defineProperty(navigator, "credentials", {
    value: mockCredentialsContainer,
    writable: true,
    configurable: true,
  });

  Object.defineProperty(window, "PublicKeyCredential", {
    value: class MockPublicKeyCredential {
      static isUserVerifyingPlatformAuthenticatorAvailable = vi.fn(() =>
        Promise.resolve(true)
      );
      static isConditionalMediationAvailable = vi.fn(() =>
        Promise.resolve(true)
      );
    },
    writable: true,
    configurable: true,
  });
}
