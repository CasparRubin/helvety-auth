import "@testing-library/jest-dom/vitest";
import { vi } from "vitest";

// Mock Next.js navigation
vi.mock("next/navigation", () => ({
  useRouter: () => ({
    push: vi.fn(),
    replace: vi.fn(),
    prefetch: vi.fn(),
    back: vi.fn(),
    forward: vi.fn(),
  }),
  usePathname: () => "/",
  useSearchParams: () => new URLSearchParams(),
  useParams: () => ({}),
}));

// Mock next-themes
vi.mock("next-themes", () => ({
  useTheme: () => ({
    theme: "light",
    setTheme: vi.fn(),
    resolvedTheme: "light",
    themes: ["light", "dark", "system"],
  }),
  ThemeProvider: ({ children }: { children: React.ReactNode }) => children,
}));

// Mock WebAuthn browser API
const mockCredentialsContainer = {
  create: vi.fn(),
  get: vi.fn(),
};

Object.defineProperty(navigator, "credentials", {
  value: mockCredentialsContainer,
  writable: true,
  configurable: true,
});

// Mock PublicKeyCredential for WebAuthn support detection
Object.defineProperty(window, "PublicKeyCredential", {
  value: class MockPublicKeyCredential {
    static isUserVerifyingPlatformAuthenticatorAvailable = vi.fn(() =>
      Promise.resolve(true)
    );
    static isConditionalMediationAvailable = vi.fn(() => Promise.resolve(true));
  },
  writable: true,
  configurable: true,
});
