# Helvety Auth

![Next.js](https://img.shields.io/badge/Next.js-16.1.6-black?style=flat-square&logo=next.js)
![React](https://img.shields.io/badge/React-19.2.4-61DAFB?style=flat-square&logo=react)
![TypeScript](https://img.shields.io/badge/TypeScript-5-blue?style=flat-square&logo=typescript)
![License](https://img.shields.io/badge/License-All%20Rights%20Reserved-red?style=flat-square)

Centralized authentication service for the Helvety ecosystem, providing passwordless SSO across all Helvety applications.

## Overview

Helvety Auth (`auth.helvety.com`) handles all authentication for Helvety applications:

- **helvety.com** - Main website
- **store.helvety.com** - Store application
- **pdf.helvety.com** - PDF application
- **tasks.helvety.com** - Tasks application

## Features

- **Email + Passkey Authentication** - Magic links for new users (and existing without passkey); existing users with a passkey go straight to passkey sign-in
- **WebAuthn/FIDO2** - Device-aware passkey auth: on mobile, use this device (Face ID/fingerprint/PIN); on desktop, use phone via QR code + biometrics
- **Cross-Subdomain SSO** - Single sign-on across all `*.helvety.com` apps
- **Redirect URI Support** - Seamless cross-app authentication flows

## Tech Stack

- **Framework**: Next.js 16.1.6 (App Router)
- **Language**: TypeScript
- **Authentication**: Supabase Auth + SimpleWebAuthn
- **Styling**: Tailwind CSS 4 + shadcn/ui
- **Deployment**: Vercel

## Authentication Flows

New users receive a magic link to verify email, then complete passkey setup. Existing users with a passkey skip the email and sign in with passkey directly.

### New User Flow

**Device-aware:** On **mobile** (phone/tablet), the user creates and uses the passkey on the same device (Face ID, fingerprint, or device PIN). On **desktop**, they use their phone to scan a QR code and complete the passkey on the phone.

```mermaid
sequenceDiagram
    participant U as User
    participant P as Phone/Device
    participant A as Auth Service
    participant S as Supabase

    U->>A: Enter email address
    A->>S: Send magic link
    S-->>U: Email with magic link
    U->>A: Click magic link
    A->>S: Verify email
    S-->>A: Email verified
    A->>U: Show passkey setup
    alt Desktop
      U->>P: Scan QR code with phone
      P->>U: Verify biometrics on phone
    else Mobile
      U->>P: Use this device (Face ID / fingerprint / PIN)
    end
    P->>A: Passkey credential
    A->>S: Store passkey
    A->>U: Verify passkey
    U->>P: Authenticate (same device or phone)
    P->>A: Passkey response
    A-->>U: Redirect to app
```

### Returning User Flow

Existing users with a passkey do not receive a magic link. After entering their email, the passkey prompt appears automatically (no button click required).

Same device logic: **mobile** = sign in on this device; **desktop** = scan QR with phone and authenticate on phone.

```mermaid
sequenceDiagram
    participant U as User
    participant P as Phone/Device
    participant A as Auth Service
    participant S as Supabase

    U->>A: Enter email address
    A->>A: Check user has passkey (no email sent)
    A->>U: Show passkey sign-in
    alt Desktop
      U->>P: Scan QR code with phone
    else Mobile
      U->>P: Use this device
    end
    P->>U: Verify biometrics
    P->>A: Passkey response
    A->>S: Verify passkey + Create session
    S-->>A: Session created
    A-->>U: Redirect to app
```

Note: Passkey authentication creates the session directly server-side (via `verifyOtp`) without requiring the user to navigate through an additional callback URL. This ensures reliable session creation regardless of browser PKCE support.

### Key Points

- **Email required** - Users provide an email address for authentication and account recovery
- **Magic link only for new users** - New users (and existing users without a passkey) get a verification email; existing users with a passkey sign in directly with passkey
- **Passkey security** - Biometric verification (Face ID, fingerprint, or PIN) via WebAuthn

## API Routes

### GET `/auth/callback`

Handles authentication callbacks from email magic links (new users or existing users without a passkey) and OAuth flows. After successful email verification, redirects to the login page with the appropriate passkey step.

**Note:** This route is NOT used for passkey sign-in. Passkey authentication creates the session directly server-side and redirects the user to their destination without going through this callback.

**Query Parameters:**

- `code` - PKCE authorization code
- `token_hash` - Email OTP token hash
- `type` - OTP type (magiclink, signup, recovery, invite, email_change)
- `redirect_uri` - Where to redirect after authentication (validated against allowlist)

**Behavior:**

- Verifies the magic link token (via code exchange or OTP verification)
- Checks if user has a passkey and encryption configured
- Redirects based on user status:
  - New users or missing encryption: `/login?step=encryption-setup`
  - Returning users after email verification: `/login?step=passkey-signin`
- If no `redirect_uri` is provided, defaults to `https://helvety.com`
- **Always preserves `redirect_uri`** through the entire auth flow, including when handling hash fragment authentication (where tokens arrive as `#access_token=...` instead of query params)

### GET `/logout`

Signs out the user and redirects.

**Query Parameters:**

- `redirect_uri` - Where to redirect after logout (default: helvety.com)

**Example:** `/logout?redirect_uri=https://pdf.helvety.com`

## Session Management (proxy.ts)

The proxy (`proxy.ts`) handles session validation and refresh and cross-subdomain cookie management:

- **Session Validation & Refresh** - Uses `getClaims()` to validate the JWT locally (no Auth API call when the token is valid). The Supabase Auth API is only called when a token refresh is needed (e.g. near or past expiry). Refreshed tokens are written to cookies automatically.
- **Cross-Subdomain SSO** - Sets cookies with `.helvety.com` domain in production for session sharing across all Helvety apps
- **Server Component Support** - Ensures server components always have access to fresh session data

The proxy runs on all routes except static assets and handles the Supabase session lifecycle transparently.

## Cross-App Authentication

Other Helvety apps redirect to auth.helvety.com for authentication:

```typescript
// In store.helvety.com or pdf.helvety.com
// Each app has its own lib/auth-redirect.ts with helper functions

// Example redirect for unauthenticated users
const currentUrl = window.location.href;
const loginUrl = `https://auth.helvety.com/login?redirect_uri=${encodeURIComponent(currentUrl)}`;
window.location.href = loginUrl;
// → https://auth.helvety.com/login?redirect_uri=https://store.helvety.com/account
```

After authentication, users are redirected back to their original app with an active session (shared via `.helvety.com` cookie domain).

## Database Schema

The service uses two tables for storing WebAuthn credentials and encryption parameters:

### user_auth_credentials

Stores WebAuthn passkey credentials:

```sql
CREATE TABLE user_auth_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  counter BIGINT NOT NULL DEFAULT 0,
  transports TEXT[] DEFAULT '{}',
  device_type TEXT,
  backed_up BOOLEAN DEFAULT FALSE,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ DEFAULT NOW()
);
```

### user_passkey_params

Stores PRF extension parameters for encryption key derivation:

```sql
CREATE TABLE user_passkey_params (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL,
  prf_salt TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW(),
  UNIQUE(user_id, credential_id)
);
```

**Note:** The `prf_salt` is used during PRF evaluation to derive the encryption key. The actual encryption key is never stored—it's derived client-side during passkey authentication.

## Security Considerations

- **httpOnly Cookies** - Challenge storage uses secure httpOnly cookies
- **PKCE Flow** - Supabase uses PKCE for OAuth code exchange
- **Magic Link Expiry** - Links expire after 1 hour
- **Passkey Verification** - Strict origin and RP ID validation
- **Session Cookies** - Shared across subdomains via `.helvety.com` domain
- **Counter Tracking** - Prevents passkey replay attacks
- **Redirect URI Validation** - All redirect URIs are validated against a strict allowlist to prevent open redirect attacks

### Security Hardening

The auth service implements comprehensive security hardening:

- **Rate Limiting** - Protection against brute force attacks:
  - Magic link requests: 3 per 5 minutes per email, 9 per 5 minutes per IP
  - Passkey authentication: 10 per minute per IP
  - Rate limits reset on successful authentication
- **CSRF Protection** - Token-based protection with timing-safe comparison for all state-changing Server Actions
- **Server Layout Guards** - Authentication checks in Server Components (CVE-2025-29927 compliant - auth NOT in proxy)
- **Audit Logging** - Structured logging for all authentication events:
  - Login attempts (success/failure)
  - Magic link sent/failed
  - Passkey authentication (started/success/failed)
  - Rate limit exceeded events
- **Standardized Errors** - Consistent error codes and user-friendly messages that don't leak implementation details
- **Security Headers** - CSP, HSTS, X-Frame-Options, and other security headers

### Redirect URI Validation

The auth service validates all `redirect_uri` parameters to prevent open redirect vulnerabilities. Allowed destinations:

- `https://helvety.com` and any path
- `https://*.helvety.com` - Any subdomain (dynamically supports future apps)
- `http://localhost:*` - Any port (development only)
- `http://127.0.0.1:*` - Any port (development only)

Invalid redirect URIs are rejected, and the user is redirected to `helvety.com` by default.

### End-to-End Encryption Setup

After passkey authentication, new users are guided through a two-step encryption setup. The flow is **device-aware**:

**Step 1: Create Passkey (Registration)**

- **On mobile (phone/tablet):** User creates a passkey on this device using Face ID, fingerprint, or device PIN.
- **On desktop:** User scans a QR code with their phone and creates the passkey on the phone (Face ID or fingerprint).
- The passkey is registered with the WebAuthn PRF extension enabled. Server stores the credential and PRF salt parameters.

**Step 2: Sign In with Passkey (Verification + Session)**

- User authenticates with the newly created passkey (same device on mobile, or phone via QR on desktop).
- PRF extension derives a deterministic output from the passkey.
- Client-side HKDF derives the encryption key from PRF output.
- Server verifies the passkey response and creates a session.
- User is redirected to destination app with valid session cookies.

**Key Features:**

- **Encryption Passkey** - A passkey created using the WebAuthn PRF (Pseudo-Random Function) extension
- **Key Derivation** - Encryption keys are derived client-side from the PRF output using HKDF
- **Zero-Knowledge** - The server stores only PRF parameters (salt values); encryption keys are never transmitted
- **Cross-App Support** - Encryption passkeys work across all `*.helvety.com` apps (registered to `helvety.com` RP ID)

Browser requirements for encryption:

**Desktop:**

- Chrome 128+ or Edge 128+
- Safari 18+ on Mac
- Firefox 139+ (desktop only)

**Mobile:**

- iPhone with iOS 18+
- Android 14+ with Chrome

**Note:** Firefox for Android does not support the PRF extension.

**Legal Pages:** Privacy Policy, Terms of Service, and Impressum are hosted centrally on [helvety.com](https://helvety.com) and linked in the site footer.

## Developer

This application is developed and maintained by [Helvety](https://helvety.com), a Swiss company committed to transparency, strong security, and respect for user privacy and data protection.

Vercel Analytics is used across all Helvety apps for privacy-focused, anonymous page view statistics. Vercel Speed Insights is enabled only on [helvety.com](https://helvety.com). See our [Privacy Policy](https://helvety.com/privacy) for details.

For questions or inquiries, please contact us at [contact@helvety.com](mailto:contact@helvety.com).

## License & Usage

> **This is NOT open source software.**

This repository is public **for transparency purposes only** so users can verify the application's behavior and security.

**All Rights Reserved.** No license is granted for any use of this code. You may:

- View and inspect the code

You may NOT:

- Clone, copy, or download this code for any purpose
- Modify, adapt, or create derivative works
- Redistribute or share this code
- Use this code in your own projects
- Run this code locally or on your own servers

See [LICENSE](./LICENSE) for full legal terms.
