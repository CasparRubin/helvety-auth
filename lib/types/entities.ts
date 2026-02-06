/**
 * Entity type definitions shared across all Helvety apps
 * These types represent database entities and are synced via sync-shared.js
 */

// =============================================================================
// AUTHENTICATION TYPES
// =============================================================================

/**
 * User's WebAuthn authentication credential (stored in DB)
 * Used for passkey-based passwordless authentication
 */
export interface UserAuthCredential {
  id: string;
  user_id: string;
  /** Base64url-encoded credential ID from WebAuthn */
  credential_id: string;
  /** Base64url-encoded COSE public key for signature verification */
  public_key: string;
  /** Signature counter to detect cloned credentials */
  counter: number;
  /** Transport hints for credential (e.g., ['hybrid']) */
  transports: string[];
  /** Device type: 'singleDevice' (hardware key) or 'multiDevice' (synced passkey) */
  device_type: string | null;
  /** Whether the credential is cloud-synced */
  backed_up: boolean;
  created_at: string;
  last_used_at: string | null;
}

// =============================================================================
// ENCRYPTION KEY TYPES
// =============================================================================

/**
 * User's passkey encryption parameters (stored in DB, not secret)
 * Used for PRF-based key derivation from passkeys
 */
export interface UserPasskeyParams {
  user_id: string;
  /** Base64-encoded PRF salt for HKDF */
  prf_salt: string;
  /** Base64url-encoded credential ID */
  credential_id: string;
  /** PRF version for future compatibility */
  version: number;
  created_at: string;
}

// =============================================================================
// USER PROFILE TYPES
// =============================================================================

/**
 * User profile (central identity across all Helvety apps)
 */
export interface UserProfile {
  id: string;
  stripe_customer_id: string | null;
  /** Optional display name for personalization */
  display_name?: string | null;
  email: string;
  created_at: string;
  updated_at: string;
}

// =============================================================================
// SUBSCRIPTION TYPES
// =============================================================================

/**
 * Valid subscription statuses (matches Stripe subscription statuses)
 */
export type SubscriptionStatus =
  | "active"
  | "canceled"
  | "incomplete"
  | "incomplete_expired"
  | "past_due"
  | "trialing"
  | "unpaid"
  | "paused";

/**
 * User subscription record
 */
export interface Subscription {
  id: string;
  user_id: string;
  stripe_subscription_id: string | null;
  stripe_price_id: string;
  product_id: string;
  tier_id: string;
  status: SubscriptionStatus;
  current_period_start: string | null;
  current_period_end: string | null;
  cancel_at_period_end: boolean;
  canceled_at: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * One-time purchase record
 */
export interface Purchase {
  id: string;
  user_id: string;
  stripe_payment_intent_id: string | null;
  stripe_price_id: string;
  product_id: string;
  tier_id: string;
  amount_paid: number;
  currency: string;
  created_at: string;
}

/**
 * Subscription event types for audit log
 */
export type SubscriptionEventType =
  | "subscription.created"
  | "subscription.updated"
  | "subscription.canceled"
  | "subscription.renewed"
  | "subscription.payment_failed"
  | "purchase.completed"
  | "checkout.completed";

/**
 * Subscription event record (audit log).
 * subscription_id is set for subscription lifecycle events (created/updated/canceled/renewed/payment_failed)
 * and references subscriptions.id for JOINs; null for checkout.completed. purchase_id is for future
 * one-time purchase events (e.g. purchase.completed).
 */
export interface SubscriptionEvent {
  id: string;
  subscription_id: string | null;
  purchase_id: string | null;
  user_id: string;
  event_type: string;
  stripe_event_id: string | null;
  metadata: Record<string, unknown> | null;
  created_at: string;
}

/**
 * Subscription with related info for display
 */
export interface SubscriptionWithProduct extends Subscription {
  product_name?: string;
  tier_name?: string;
}

/**
 * User's subscription summary (for quick access checks)
 */
export interface UserSubscriptionSummary {
  userId: string;
  activeSubscriptions: {
    productId: string;
    tierId: string;
    status: SubscriptionStatus;
    currentPeriodEnd: string | null;
  }[];
  purchases: {
    productId: string;
    tierId: string;
    purchasedAt: string;
  }[];
}

// =============================================================================
// LICENSED TENANT TYPES
// =============================================================================

/**
 * Licensed tenant for product license validation
 * Maps a SharePoint tenant to a product subscription
 */
export interface LicensedTenant {
  id: string;
  subscription_id: string;
  user_id: string;
  /** Tenant identifier (e.g., "contoso" from contoso.sharepoint.com) */
  tenant_id: string;
  /** Full tenant domain (e.g., "contoso.sharepoint.com") */
  tenant_domain: string;
  /** Optional friendly name for display */
  display_name: string | null;
  created_at: string;
  updated_at: string;
}

/**
 * Licensed tenant with related subscription info
 */
export interface LicensedTenantWithSubscription extends LicensedTenant {
  subscription: Subscription;
}

/**
 * Request to register a new tenant
 */
export interface RegisterTenantRequest {
  /** Tenant identifier (e.g., "contoso") */
  tenantId: string;
  /** Optional friendly name */
  displayName?: string;
  /** Subscription ID to link the tenant to */
  subscriptionId: string;
}

/**
 * License validation response (returned by public API)
 */
export interface LicenseValidationResponse {
  valid: boolean;
  tier?: string;
  features?: string[];
  expiresAt?: string;
  gracePeriodDays?: number;
  reason?:
    | "tenant_not_registered"
    | "subscription_expired"
    | "subscription_canceled"
    | "subscription_inactive"
    | "missing_tenant_id"
    | "invalid_tenant_id"
    | "missing_product_id"
    | "invalid_product_id"
    | "rate_limit_exceeded"
    | "server_error";
}

// =============================================================================
// CHECKOUT TYPES
// =============================================================================

/**
 * Request to create a checkout session
 */
export interface CreateCheckoutRequest {
  tierId: string;
  successUrl?: string;
  cancelUrl?: string;
}

/**
 * Response from creating a checkout session
 */
export interface CreateCheckoutResponse {
  checkoutUrl: string;
  sessionId: string;
}

// =============================================================================
// SERVER ACTION TYPES
// =============================================================================

/**
 * Standard response type for server actions
 */
export type ActionResponse<T = void> = {
  success: boolean;
  data?: T;
  error?: string;
};
