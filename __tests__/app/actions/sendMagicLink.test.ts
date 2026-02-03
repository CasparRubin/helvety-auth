/**
 * sendMagicLink server action: magic link is sent only for new users or
 * existing users without a passkey; existing users with a passkey get
 * skipToPasskey and go straight to passkey sign-in.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

// Mock next/headers (headers() is async)
vi.mock("next/headers", () => ({
  headers: vi.fn(() =>
    Promise.resolve({
      get: (name: string) =>
        name === "x-forwarded-for"
          ? "192.168.1.1"
          : name === "x-real-ip"
            ? null
            : null,
    })
  ),
  cookies: vi.fn(() =>
    Promise.resolve({ get: vi.fn(), set: vi.fn(), delete: vi.fn() })
  ),
}));

// Mock rate limit to always allow
vi.mock("@/lib/rate-limit", () => ({
  checkRateLimit: vi.fn(() => ({ allowed: true, retryAfter: undefined })),
  RATE_LIMITS: { MAGIC_LINK: { maxRequests: 3, windowMs: 60000 } },
  resetRateLimit: vi.fn(),
}));

vi.mock("@/lib/auth-logger", () => ({
  logAuthEvent: vi.fn(),
}));

vi.mock("@/lib/logger", () => ({
  logger: { error: vi.fn(), info: vi.fn(), warn: vi.fn() },
}));

// Build a mock admin client that supports listUsers, createUser, signInWithOtp, and from().select().eq()
function createMockAdminClient(options: {
  listUsers: { users: { id: string; email: string }[]; error?: unknown };
  createUser?: { error?: unknown };
  signInWithOtp?: { error?: unknown };
  credentialCount?: number;
}) {
  const selectChain = {
    eq: vi.fn().mockResolvedValue({
      data: options.credentialCount ? [{ id: "c1" }] : [],
      error: null,
      count: options.credentialCount ?? 0,
    }),
  };
  const fromMock = vi.fn().mockReturnValue({
    select: vi.fn().mockReturnValue(selectChain),
  });

  return {
    auth: {
      admin: {
        listUsers: vi.fn().mockResolvedValue({
          data: { users: options.listUsers.users },
          error: options.listUsers.error ?? null,
        }),
        createUser: vi.fn().mockResolvedValue({
          error: options.createUser?.error ?? null,
        }),
      },
      signInWithOtp: vi.fn().mockResolvedValue({
        error: options.signInWithOtp?.error ?? null,
      }),
    },
    from: fromMock,
  };
}

vi.mock("@/lib/supabase/admin", () => ({
  createAdminClient: vi.fn(),
}));

import { sendMagicLink } from "@/app/actions/passkey-auth-actions";
import { createAdminClient } from "@/lib/supabase/admin";

describe("sendMagicLink", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns skipToPasskey when existing user has passkey", async () => {
    const mockClient = createMockAdminClient({
      listUsers: {
        users: [{ id: "user-1", email: "existing@example.com" }],
      },
      credentialCount: 1,
    });
    vi.mocked(createAdminClient).mockReturnValue(
      mockClient as unknown as ReturnType<typeof createAdminClient>
    );

    const result = await sendMagicLink("existing@example.com");

    expect(result.success).toBe(true);
    expect(result.data?.skipToPasskey).toBe(true);
    expect(result.data?.isNewUser).toBe(false);
    expect(mockClient.auth.signInWithOtp).not.toHaveBeenCalled();
  });

  it("sends magic link and returns email-sent when new user", async () => {
    const mockClient = createMockAdminClient({
      listUsers: { users: [] },
      credentialCount: 0,
    });
    vi.mocked(createAdminClient).mockReturnValue(
      mockClient as unknown as ReturnType<typeof createAdminClient>
    );

    const result = await sendMagicLink("newuser@example.com");

    expect(result.success).toBe(true);
    expect(result.data?.isNewUser).toBe(true);
    expect(result.data?.skipToPasskey).toBe(false);
    expect(mockClient.auth.admin.createUser).toHaveBeenCalled();
    expect(mockClient.auth.signInWithOtp).toHaveBeenCalled();
  });

  it("sends magic link when existing user has no passkey", async () => {
    const mockClient = createMockAdminClient({
      listUsers: {
        users: [{ id: "user-2", email: "nopasskey@example.com" }],
      },
      credentialCount: 0,
    });
    vi.mocked(createAdminClient).mockReturnValue(
      mockClient as unknown as ReturnType<typeof createAdminClient>
    );

    const result = await sendMagicLink("nopasskey@example.com");

    expect(result.success).toBe(true);
    expect(result.data?.isNewUser).toBe(false);
    expect(result.data?.skipToPasskey).toBe(false);
    expect(mockClient.auth.signInWithOtp).toHaveBeenCalled();
  });

  it("rejects invalid email", async () => {
    const mockClient = createMockAdminClient({
      listUsers: { users: [] },
    });
    vi.mocked(createAdminClient).mockReturnValue(
      mockClient as unknown as ReturnType<typeof createAdminClient>
    );

    const result = await sendMagicLink("not-an-email");

    expect(result.success).toBe(false);
    expect(result.error).toContain("valid email");
    expect(mockClient.auth.signInWithOtp).not.toHaveBeenCalled();
  });
});
