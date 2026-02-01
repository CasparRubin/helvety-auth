"use client";

import {
  createContext,
  useContext,
  useState,
  useCallback,
  type ReactNode,
} from "react";

import {
  storeMasterKey,
  getMasterKey,
  deleteMasterKey,
  clearAllKeys,
  isStorageAvailable,
} from "./key-storage";
import {
  isPasskeySupported,
  registerPasskeyWithEncryption,
  authenticatePasskeyWithEncryption,
} from "./passkey";
import {
  generatePRFParams,
  deriveKeyFromPRF,
  isPRFSupported,
  getPRFSupportInfo,
  type PRFKeyParams,
  type PRFSupportInfo,
} from "./prf-key-derivation";

/** Internal state for the encryption context */
interface EncryptionState {
  /** Whether encryption is unlocked (master key available) */
  isUnlocked: boolean;
  /** Whether we're currently loading/checking encryption state */
  isLoading: boolean;
  /** The master key (null if locked) */
  masterKey: CryptoKey | null;
  /** Error message if something went wrong */
  error: string | null;
  /** Whether passkey/PRF is supported on this device */
  prfSupported: boolean | null;
  /** Detailed PRF support info */
  prfSupportInfo: PRFSupportInfo | null;
}

/** Public API exposed by the encryption context */
interface EncryptionContextValue extends EncryptionState {
  /**
   * Initialize encryption with passkey (PRF-based)
   * Call this during onboarding to set up E2EE with passkey
   */
  initializePasskeyEncryption: (
    userId: string,
    userEmail: string
  ) => Promise<{ params: PRFKeyParams; credentialId: string } | null>;

  /**
   * Unlock encryption with passkey (PRF-based)
   * Call this on login to derive the master key
   */
  unlockWithPasskey: (
    userId: string,
    prfParams: PRFKeyParams,
    credentialIds?: string[]
  ) => Promise<boolean>;

  /**
   * Lock encryption (clear master key)
   * Call this on logout
   */
  lockEncryption: (userId: string) => Promise<void>;

  /**
   * Check if encryption is set up for a user
   */
  checkEncryptionState: (userId: string) => Promise<void>;

  /**
   * Check PRF/passkey support
   */
  checkPRFSupport: () => Promise<void>;
}

const EncryptionContext = createContext<EncryptionContextValue | null>(null);

/** Props for the EncryptionProvider component */
interface EncryptionProviderProps {
  children: ReactNode;
}

/**
 * Provider component for end-to-end encryption state management.
 * Handles passkey-based encryption initialization, unlocking, and key management.
 */
export function EncryptionProvider({ children }: EncryptionProviderProps) {
  const [state, setState] = useState<EncryptionState>({
    isUnlocked: false,
    isLoading: true,
    masterKey: null,
    error: null,
    prfSupported: null,
    prfSupportInfo: null,
  });

  /**
   * Check PRF/passkey support
   */
  const checkPRFSupport = useCallback(async () => {
    if (!isPasskeySupported()) {
      setState((prev) => ({
        ...prev,
        prfSupported: false,
        prfSupportInfo: { supported: false, reason: "WebAuthn not supported" },
      }));
      return;
    }

    const supported = await isPRFSupported();
    const info = await getPRFSupportInfo();

    setState((prev) => ({
      ...prev,
      prfSupported: supported,
      prfSupportInfo: info,
    }));
  }, []);

  /**
   * Check if we have a cached master key
   */
  const checkEncryptionState = useCallback(
    async (userId: string) => {
      if (!isStorageAvailable()) {
        setState((prev) => ({
          ...prev,
          isLoading: false,
          error:
            "IndexedDB not available - encryption requires a modern browser",
        }));
        return;
      }

      setState((prev) => ({ ...prev, isLoading: true, error: null }));

      try {
        // Also check PRF support while we're at it
        void checkPRFSupport();

        const cachedKey = await getMasterKey(userId);
        if (cachedKey) {
          setState((prev) => ({
            ...prev,
            isUnlocked: true,
            isLoading: false,
            masterKey: cachedKey,
            error: null,
          }));
        } else {
          setState((prev) => ({
            ...prev,
            isUnlocked: false,
            isLoading: false,
            masterKey: null,
            error: null,
          }));
        }
      } catch {
        setState((prev) => ({
          ...prev,
          isUnlocked: false,
          isLoading: false,
          masterKey: null,
          error: "Failed to check encryption state",
        }));
      }
    },
    [checkPRFSupport]
  );

  /**
   * Lock encryption (clear keys)
   */
  const lockEncryption = useCallback(async (userId: string) => {
    await deleteMasterKey(userId);
    await clearAllKeys();

    setState((prev) => ({
      ...prev,
      isUnlocked: false,
      isLoading: false,
      masterKey: null,
      error: null,
    }));
  }, []);

  /**
   * Initialize encryption with passkey (PRF-based)
   *
   * Flow:
   * 1. Register passkey (PRF only returns 'enabled' status, not output)
   * 2. Immediately authenticate with the new passkey to get PRF output
   * 3. Derive encryption key from PRF output
   */
  const initializePasskeyEncryption = useCallback(
    async (
      userId: string,
      userEmail: string
    ): Promise<{ params: PRFKeyParams; credentialId: string } | null> => {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));

      try {
        // Check PRF support first
        const supported = await isPRFSupported();
        if (!supported) {
          const info = await getPRFSupportInfo();
          setState((prev) => ({
            ...prev,
            isLoading: false,
            error: info.reason ?? "PRF extension not supported on this device",
            prfSupported: false,
            prfSupportInfo: info,
          }));
          return null;
        }

        // Generate PRF params
        const params = generatePRFParams();

        // Step 1: Register passkey with PRF extension
        const regResult = await registerPasskeyWithEncryption(
          userId,
          userEmail,
          params.prfSalt
        );

        if (!regResult.prfEnabled) {
          setState((prev) => ({
            ...prev,
            isLoading: false,
            error:
              "Your authenticator does not support encryption. Please try a different device or security key.",
          }));
          return null;
        }

        // Step 2: Immediately authenticate to get PRF output
        // PRF output is only available during authentication, not registration
        const authResult = await authenticatePasskeyWithEncryption(
          [regResult.credentialId], // Only allow the credential we just created
          params.prfSalt
        );

        if (!authResult.prfOutput) {
          setState((prev) => ({
            ...prev,
            isLoading: false,
            error:
              "Failed to get encryption key from passkey. Please try again.",
          }));
          return null;
        }

        // Step 3: Derive master key from PRF output
        const masterKey = await deriveKeyFromPRF(authResult.prfOutput, params);

        // Cache the master key
        await storeMasterKey(userId, masterKey);

        setState((prev) => ({
          ...prev,
          isUnlocked: true,
          isLoading: false,
          masterKey,
          error: null,
        }));

        return { params, credentialId: regResult.credentialId };
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : "Failed to initialize passkey encryption";
        setState((prev) => ({
          ...prev,
          isLoading: false,
          error: message,
        }));
        return null;
      }
    },
    []
  );

  /**
   * Unlock encryption with passkey (PRF-based)
   */
  const unlockWithPasskey = useCallback(
    async (
      userId: string,
      prfParams: PRFKeyParams,
      credentialIds?: string[]
    ): Promise<boolean> => {
      setState((prev) => ({ ...prev, isLoading: true, error: null }));

      try {
        // Authenticate with passkey and get PRF output
        const result = await authenticatePasskeyWithEncryption(
          credentialIds,
          prfParams.prfSalt
        );

        if (!result.prfEnabled || !result.prfOutput) {
          setState((prev) => ({
            ...prev,
            isLoading: false,
            error: "PRF output not received during authentication",
          }));
          return false;
        }

        // Derive master key from PRF output
        const masterKey = await deriveKeyFromPRF(result.prfOutput, prfParams);

        // Cache the master key
        await storeMasterKey(userId, masterKey);

        setState((prev) => ({
          ...prev,
          isUnlocked: true,
          isLoading: false,
          masterKey,
          error: null,
        }));

        return true;
      } catch (error) {
        const message =
          error instanceof Error
            ? error.message
            : "Failed to unlock with passkey";
        setState((prev) => ({
          ...prev,
          isLoading: false,
          error: message,
        }));
        return false;
      }
    },
    []
  );

  const value: EncryptionContextValue = {
    ...state,
    initializePasskeyEncryption,
    unlockWithPasskey,
    lockEncryption,
    checkEncryptionState,
    checkPRFSupport,
  };

  return (
    <EncryptionContext.Provider value={value}>
      {children}
    </EncryptionContext.Provider>
  );
}

/**
 * Hook to access encryption context
 */
export function useEncryptionContext(): EncryptionContextValue {
  const context = useContext(EncryptionContext);
  if (!context) {
    throw new Error(
      "useEncryptionContext must be used within an EncryptionProvider"
    );
  }
  return context;
}
