/**
 * Mock Factories
 *
 * Factory functions to create test data with sensible defaults.
 * Override any property as needed in your tests.
 */
import { vi } from "vitest";

// =============================================================================
// USER MOCKS
// =============================================================================

/**
 * Creates a mock user object
 */
export function createMockUser(overrides?: Partial<MockUser>): MockUser {
  return {
    id: "test-user-id",
    email: "test@example.com",
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

interface MockUser {
  id: string;
  email: string;
  created_at: string;
}

// =============================================================================
// SUPABASE MOCKS
// =============================================================================

/**
 * Creates a mock Supabase client for testing
 */
export function createMockSupabaseClient() {
  return {
    auth: {
      getUser: vi.fn().mockResolvedValue({ data: { user: null }, error: null }),
      getSession: vi.fn().mockResolvedValue({
        data: { session: null },
        error: null,
      }),
      signOut: vi.fn().mockResolvedValue({ error: null }),
    },
    from: vi.fn(() => ({
      select: vi.fn().mockReturnThis(),
      insert: vi.fn().mockReturnThis(),
      update: vi.fn().mockReturnThis(),
      delete: vi.fn().mockReturnThis(),
      eq: vi.fn().mockReturnThis(),
      single: vi.fn().mockResolvedValue({ data: null, error: null }),
      maybeSingle: vi.fn().mockResolvedValue({ data: null, error: null }),
    })),
  };
}

// =============================================================================
// RESPONSE MOCKS
// =============================================================================

/**
 * Creates a mock successful response
 */
export function createMockSuccessResponse<T>(data: T) {
  return { data, error: null };
}

/**
 * Creates a mock error response
 */
export function createMockErrorResponse(message: string, code?: string) {
  return {
    data: null,
    error: { message, code: code ?? "ERROR" },
  };
}

// =============================================================================
// AUTH MOCKS (project-specific)
// =============================================================================

/**
 * Creates a mock passkey credential
 */
export function createMockPasskeyCredential(
  overrides?: Partial<MockPasskeyCredential>
): MockPasskeyCredential {
  return {
    id: "test-credential-id",
    rawId: new ArrayBuffer(32),
    type: "public-key",
    response: {
      clientDataJSON: new ArrayBuffer(64),
      attestationObject: new ArrayBuffer(128),
    },
    ...overrides,
  };
}

interface MockPasskeyCredential {
  id: string;
  rawId: ArrayBuffer;
  type: string;
  response: {
    clientDataJSON: ArrayBuffer;
    attestationObject: ArrayBuffer;
  };
}
