import { startAuthentication } from "@simplewebauthn/browser";
import { describe, it, expect, vi, beforeEach } from "vitest";

import {
  render,
  screen,
  waitFor,
  fireEvent,
} from "@/__tests__/utils/test-utils";
import {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
  savePasskeyParams,
  generatePasskeyAuthOptions,
  verifyPasskeyAuthentication,
} from "@/app/actions/passkey-auth-actions";
import { EncryptionSetup } from "@/components/encryption-setup";
import { registerPasskey } from "@/lib/crypto/passkey";

// Mock server actions
vi.mock("@/app/actions/passkey-auth-actions", () => ({
  generatePasskeyRegistrationOptions: vi.fn(),
  verifyPasskeyRegistration: vi.fn(),
  savePasskeyParams: vi.fn(),
  generatePasskeyAuthOptions: vi.fn(),
  verifyPasskeyAuthentication: vi.fn(),
}));

// Mock @simplewebauthn/browser
vi.mock("@simplewebauthn/browser", () => ({
  startAuthentication: vi.fn(),
}));

// Mock crypto passkey module
vi.mock("@/lib/crypto/passkey", () => ({
  registerPasskey: vi.fn(),
}));

// Mock crypto key storage
vi.mock("@/lib/crypto/key-storage", () => ({
  storeMasterKey: vi.fn().mockResolvedValue(undefined),
}));

// Mock PRF key derivation
vi.mock("@/lib/crypto/prf-key-derivation", () => ({
  deriveKeyFromPRF: vi.fn().mockResolvedValue({} as CryptoKey),
}));

// Mock logger
vi.mock("@/lib/logger", () => ({
  logger: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

// Mock encryption context
const mockCheckPRFSupport = vi.fn();
vi.mock("@/lib/crypto", () => ({
  useEncryptionContext: () => ({
    prfSupported: true,
    prfSupportInfo: null,
    checkPRFSupport: mockCheckPRFSupport,
  }),
  PRF_VERSION: 1,
}));

describe("EncryptionSetup", () => {
  const defaultProps = {
    userId: "test-user-id",
    userEmail: "test@example.com",
    redirectUri: "https://pdf.helvety.com",
  };

  beforeEach(() => {
    vi.clearAllMocks();
    mockCheckPRFSupport.mockResolvedValue(undefined);

    // Setup default mock implementations
    vi.mocked(generatePasskeyRegistrationOptions).mockResolvedValue({
      success: true,
      data: {
        challenge: "test-challenge",
        rp: { id: "helvety.com", name: "Helvety" },
        user: {
          id: "dGVzdC11c2VyLWlk",
          name: "test@example.com",
          displayName: "test@example.com",
        },
        pubKeyCredParams: [{ alg: -7, type: "public-key" }],
        timeout: 60000,
        attestation: "none",
        prfSalt: "dGVzdC1zYWx0", // base64 encoded "test-salt"
      },
    });

    vi.mocked(verifyPasskeyRegistration).mockResolvedValue({
      success: true,
      data: { credentialId: "test-credential-id" },
    });

    vi.mocked(savePasskeyParams).mockResolvedValue({
      success: true,
    });

    vi.mocked(generatePasskeyAuthOptions).mockResolvedValue({
      success: true,
      data: {
        challenge: "auth-challenge",
        rpId: "helvety.com",
        timeout: 60000,
        userVerification: "required",
        allowCredentials: [],
      },
    });

    vi.mocked(verifyPasskeyAuthentication).mockResolvedValue({
      success: true,
      data: {
        redirectUrl: "https://pdf.helvety.com",
        userId: "test-user-id",
      },
    });

    vi.mocked(registerPasskey).mockResolvedValue({
      response: {
        id: "test-credential-id",
        rawId: "test-credential-id",
        type: "public-key",
        response: {
          clientDataJSON: "eyJ0ZXN0IjoidmFsdWUifQ",
          attestationObject: "attestation-data",
        },
        clientExtensionResults: { prf: { enabled: true } } as never,
        authenticatorAttachment: "cross-platform",
      },
      credentialId: "test-credential-id",
      prfEnabled: true,
      prfOutput: undefined,
    });

    const mockPrfOutput = new ArrayBuffer(32);
    vi.mocked(startAuthentication).mockResolvedValue({
      id: "test-credential-id",
      rawId: "test-credential-id",
      type: "public-key",
      response: {
        clientDataJSON: "eyJ0ZXN0IjoidmFsdWUifQ",
        authenticatorData: "auth-data",
        signature: "signature-data",
      },
      clientExtensionResults: {
        prf: { results: { first: mockPrfOutput } },
      } as AuthenticationExtensionsClientOutputs,
      authenticatorAttachment: "cross-platform",
    });
  });

  describe("initial render", () => {
    it("should show loading state while checking PRF support", () => {
      // Make PRF check never resolve during this test
      mockCheckPRFSupport.mockImplementation(() => new Promise(() => {}));

      render(<EncryptionSetup {...defaultProps} />);

      // Should show loading spinner (Loader2 component)
      expect(document.querySelector(".animate-spin")).toBeInTheDocument();
    });

    it("should show setup introduction after PRF support check", async () => {
      render(<EncryptionSetup {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText("Set Up Encryption")).toBeInTheDocument();
      });

      expect(screen.getByText("Set Up with Phone")).toBeInTheDocument();
    });
  });

  describe("step 1: passkey registration", () => {
    it("should call generatePasskeyRegistrationOptions when setup button is clicked", async () => {
      render(<EncryptionSetup {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText("Set Up with Phone")).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText("Set Up with Phone"));

      await waitFor(() => {
        expect(generatePasskeyRegistrationOptions).toHaveBeenCalledWith(
          expect.any(String), // origin
          { isMobile: expect.any(Boolean) }
        );
      });
    });

    it("should return to initial state when registration options fail", async () => {
      vi.mocked(generatePasskeyRegistrationOptions).mockResolvedValue({
        success: false,
        error: "Failed to generate options",
      });

      render(<EncryptionSetup {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText("Set Up with Phone")).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText("Set Up with Phone"));

      // Should return to initial state (resetSetup is called)
      await waitFor(() => {
        expect(screen.getByText("Set Up Encryption")).toBeInTheDocument();
        expect(screen.getByText("Set Up with Phone")).toBeInTheDocument();
      });
    });

    it("should show ready_to_sign_in state after successful registration", async () => {
      render(<EncryptionSetup {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText("Set Up with Phone")).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText("Set Up with Phone"));

      await waitFor(() => {
        expect(screen.getByText("Passkey Created")).toBeInTheDocument();
        expect(screen.getByText("Sign In with Phone")).toBeInTheDocument();
      });
    });
  });

  describe("step 2: passkey sign-in with server verification", () => {
    // Helper to get to step 2
    const setupToStep2 = async () => {
      render(<EncryptionSetup {...defaultProps} />);

      await waitFor(() => {
        expect(screen.getByText("Set Up with Phone")).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText("Set Up with Phone"));

      await waitFor(() => {
        expect(screen.getByText("Sign In with Phone")).toBeInTheDocument();
      });
    };

    it("should call generatePasskeyAuthOptions with redirectUri", async () => {
      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(generatePasskeyAuthOptions).toHaveBeenCalledWith(
          expect.any(String), // origin
          "https://pdf.helvety.com", // redirectUri
          { isMobile: expect.any(Boolean) }
        );
      });
    });

    it("should call startAuthentication with PRF extension", async () => {
      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(startAuthentication).toHaveBeenCalledWith({
          optionsJSON: expect.objectContaining({
            challenge: "auth-challenge",
            extensions: expect.objectContaining({
              prf: expect.objectContaining({
                eval: expect.objectContaining({
                  first: expect.any(Uint8Array),
                }),
              }),
            }),
          }),
        });
      });
    });

    it("should call verifyPasskeyAuthentication after successful WebAuthn auth", async () => {
      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(verifyPasskeyAuthentication).toHaveBeenCalledWith(
          expect.objectContaining({
            id: "test-credential-id",
            type: "public-key",
          }),
          expect.any(String) // origin
        );
      });
    });

    it("should call savePasskeyParams before verifyPasskeyAuthentication", async () => {
      const callOrder: string[] = [];
      vi.mocked(savePasskeyParams).mockImplementation(async () => {
        callOrder.push("savePasskeyParams");
        return { success: true };
      });
      vi.mocked(verifyPasskeyAuthentication).mockImplementation(async () => {
        callOrder.push("verifyPasskeyAuthentication");
        return {
          success: true,
          data: {
            redirectUrl: "https://pdf.helvety.com",
            userId: "test-user-id",
          },
        };
      });

      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(callOrder).toEqual([
          "savePasskeyParams",
          "verifyPasskeyAuthentication",
        ]);
      });
    });

    it("should redirect using server-provided URL after successful verification", async () => {
      // Mock window.location.href setter
      const originalLocation = window.location;
      const mockHref = vi.fn();
      Object.defineProperty(window, "location", {
        value: { ...originalLocation, href: "" },
        writable: true,
        configurable: true,
      });
      Object.defineProperty(window.location, "href", {
        set: mockHref,
        configurable: true,
      });

      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(mockHref).toHaveBeenCalledWith("https://pdf.helvety.com");
      });

      // Restore
      Object.defineProperty(window, "location", {
        value: originalLocation,
        writable: true,
        configurable: true,
      });
    });

    it("should show error when generatePasskeyAuthOptions fails", async () => {
      vi.mocked(generatePasskeyAuthOptions).mockResolvedValue({
        success: false,
        error: "Failed to start authentication",
      });

      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(
          screen.getByText("Failed to start authentication")
        ).toBeInTheDocument();
      });
    });

    it("should show error when startAuthentication fails", async () => {
      const cancelError = new Error("User cancelled");
      cancelError.name = "NotAllowedError";
      vi.mocked(startAuthentication).mockRejectedValue(cancelError);

      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(
          screen.getByText("Sign in was cancelled. Please try again.")
        ).toBeInTheDocument();
      });
    });

    it("should show error when PRF output is missing", async () => {
      vi.mocked(startAuthentication).mockResolvedValue({
        id: "test-credential-id",
        rawId: "test-credential-id",
        type: "public-key",
        response: {
          clientDataJSON: "eyJ0ZXN0IjoidmFsdWUifQ",
          authenticatorData: "auth-data",
          signature: "signature-data",
        },
        clientExtensionResults: {}, // No PRF results
        authenticatorAttachment: "cross-platform",
      });

      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(
          screen.getByText(
            "Failed to get encryption key from passkey. Please try again."
          )
        ).toBeInTheDocument();
      });
    });

    it("should show error when savePasskeyParams fails", async () => {
      vi.mocked(savePasskeyParams).mockResolvedValue({
        success: false,
        error: "Database error",
      });

      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(screen.getByText("Database error")).toBeInTheDocument();
      });
    });

    it("should show error when verifyPasskeyAuthentication fails", async () => {
      vi.mocked(verifyPasskeyAuthentication).mockResolvedValue({
        success: false,
        error: "Session creation failed",
      });

      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(screen.getByText("Session creation failed")).toBeInTheDocument();
      });
    });

    it("should stay on ready_to_sign_in state when error occurs", async () => {
      vi.mocked(verifyPasskeyAuthentication).mockResolvedValue({
        success: false,
        error: "Session creation failed",
      });

      await setupToStep2();

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(screen.getByText("Session creation failed")).toBeInTheDocument();
      });

      // Should still show the Sign In button for retry
      expect(screen.getByText("Sign In with Phone")).toBeInTheDocument();
    });
  });

  describe("without redirectUri", () => {
    it("should pass undefined redirectUri to generatePasskeyAuthOptions", async () => {
      render(
        <EncryptionSetup userId="test-user-id" userEmail="test@example.com" />
      );

      await waitFor(() => {
        expect(screen.getByText("Set Up with Phone")).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText("Set Up with Phone"));

      await waitFor(() => {
        expect(screen.getByText("Sign In with Phone")).toBeInTheDocument();
      });

      fireEvent.click(screen.getByText("Sign In with Phone"));

      await waitFor(() => {
        expect(generatePasskeyAuthOptions).toHaveBeenCalledWith(
          expect.any(String), // origin
          undefined, // redirectUri
          { isMobile: expect.any(Boolean) }
        );
      });
    });
  });
});
