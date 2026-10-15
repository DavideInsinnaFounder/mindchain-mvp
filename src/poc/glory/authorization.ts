/**
 * Bounded Glory CRM discount authorization for the simulated POC only.
 * Business Intent is a request; authority comes exclusively from the trusted
 * delegation authority supplied by the server-side composition root.
 */

export const GLORY_CRM_DISCOUNT_ACTION = "crm.discount.apply" as const;
export const GLORY_MAX_DISCOUNT_BPS = 10_000;

const BUSINESS_INTENT_KEYS = [
  "intent_id",
  "principal_id",
  "agent_id",
  "action",
  "target",
  "requested_discount_bps",
  "requested_at",
  "expires_at",
] as const;

export interface GloryBusinessIntent {
  intent_id: string;
  /** Caller claim/reference only; it never establishes authority. */
  principal_id: string;
  agent_id: string;
  action: typeof GLORY_CRM_DISCOUNT_ACTION;
  target: string;
  requested_discount_bps: number;
  requested_at: string;
  expires_at: string;
}

export interface GloryTrustedDelegationRecord {
  principal_id: string;
  agent_id: string;
  permitted_action: string;
  maximum_discount_bps: number;
  target_type: "opportunity";
  enabled: boolean;
  valid_from: string;
  valid_until: string;
}

export interface GloryTrustedDelegationAuthority {
  /** Resolution is agent-bound; the caller's principal claim is not a selector. */
  resolveByAgent(agentId: string): Readonly<GloryTrustedDelegationRecord> | null;
}

export type GloryInternalDecision = "ALLOW" | "DENY" | "UNRESOLVED" | "INVALID";
export type GloryExternalDecision = "ALLOW" | "STOP";

export interface GloryAuthorizationEvaluation {
  internal_decision: GloryInternalDecision;
  external_decision: GloryExternalDecision;
  reason: string;
  intent: Readonly<GloryBusinessIntent> | null;
  claimed_principal_id: string | null;
  resolved_principal_id: string | null;
  agent_id: string | null;
  requested_action: string | null;
  target: string | null;
  requested_discount_bps: number | null;
  delegated_limit_bps: number | null;
}

function invalidIntent(field: string): never {
  throw new Error(`glory_intent_invalid_${field}`);
}

function assertPlainDataObject(
  value: unknown,
  field: string,
  expectedKeys: readonly string[]
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    invalidIntent(field);
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  const descriptorKeys = Reflect.ownKeys(descriptors);
  if (
    descriptorKeys.some((key) => typeof key !== "string") ||
    descriptorKeys.length !== expectedKeys.length ||
    descriptorKeys.some((key) => !expectedKeys.includes(key as string))
  ) {
    invalidIntent(field);
  }
  const captured = Object.create(null) as Record<string, unknown>;
  for (const key of expectedKeys) {
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      "get" in descriptor ||
      "set" in descriptor
    ) {
      invalidIntent(key);
    }
    captured[key] = descriptor.value;
  }
  return captured;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    invalidIntent(field);
  }
  return value;
}

function isExactUtcTimestamp(value: unknown): value is string {
  if (typeof value !== "string") return false;
  const match = /^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d{1,3}))?Z$/.exec(value);
  if (match === null) return false;
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) return false;
  const canonicalInput = `${match[1]}.${(match[2] ?? "").padEnd(3, "0")}Z`;
  return new Date(milliseconds).toISOString() === canonicalInput;
}

function requiredTimestamp(value: unknown, field: string): string {
  if (!isExactUtcTimestamp(value)) invalidIntent(field);
  return value;
}

function requiredBasisPoints(value: unknown, field: string): number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0 ||
    value > GLORY_MAX_DISCOUNT_BPS
  ) {
    invalidIntent(field);
  }
  return value;
}

export function parseGloryBusinessIntent(value: unknown): Readonly<GloryBusinessIntent> {
  const captured = assertPlainDataObject(value, "shape", BUSINESS_INTENT_KEYS);
  const action = requiredString(captured.action, "action");
  if (action !== GLORY_CRM_DISCOUNT_ACTION) invalidIntent("action");
  return Object.freeze({
    intent_id: requiredString(captured.intent_id, "intent_id"),
    principal_id: requiredString(captured.principal_id, "principal_id"),
    agent_id: requiredString(captured.agent_id, "agent_id"),
    action,
    target: requiredString(captured.target, "target"),
    requested_discount_bps: requiredBasisPoints(
      captured.requested_discount_bps,
      "requested_discount_bps"
    ),
    requested_at: requiredTimestamp(captured.requested_at, "requested_at"),
    expires_at: requiredTimestamp(captured.expires_at, "expires_at"),
  });
}

function snapshotTrustedRecord(
  record: GloryTrustedDelegationRecord
): Readonly<GloryTrustedDelegationRecord> {
  if (
    record === null ||
    typeof record !== "object" ||
    Array.isArray(record) ||
    typeof record.principal_id !== "string" ||
    record.principal_id.trim().length === 0 ||
    typeof record.agent_id !== "string" ||
    record.agent_id.trim().length === 0 ||
    typeof record.permitted_action !== "string" ||
    record.permitted_action.trim().length === 0 ||
    !Number.isSafeInteger(record.maximum_discount_bps) ||
    record.maximum_discount_bps < 0 ||
    record.maximum_discount_bps > GLORY_MAX_DISCOUNT_BPS ||
    record.target_type !== "opportunity" ||
    typeof record.enabled !== "boolean" ||
    !isExactUtcTimestamp(record.valid_from) ||
    !isExactUtcTimestamp(record.valid_until) ||
    Date.parse(record.valid_from) >= Date.parse(record.valid_until)
  ) {
    throw new Error("glory_trusted_delegation_invalid");
  }
  return Object.freeze({ ...record });
}

export function createGloryTrustedDelegationAuthority(
  records: readonly GloryTrustedDelegationRecord[]
): GloryTrustedDelegationAuthority {
  const byAgent = new Map<string, Readonly<GloryTrustedDelegationRecord>>();
  for (const source of records) {
    const record = snapshotTrustedRecord(source);
    if (byAgent.has(record.agent_id)) {
      throw new Error("glory_trusted_delegation_ambiguous_agent");
    }
    byAgent.set(record.agent_id, record);
  }
  return Object.freeze({
    resolveByAgent(agentId: string) {
      const record = byAgent.get(agentId);
      return record === undefined ? null : Object.freeze({ ...record });
    },
  });
}

export function normalizeGloryDecision(decision: unknown): GloryExternalDecision {
  return decision === "ALLOW" ? "ALLOW" : "STOP";
}

function result(
  internalDecision: GloryInternalDecision,
  reason: string,
  intent: Readonly<GloryBusinessIntent> | null,
  trusted: Readonly<GloryTrustedDelegationRecord> | null,
  claimedPrincipalId: string | null = intent?.principal_id ?? null
): GloryAuthorizationEvaluation {
  return Object.freeze({
    internal_decision: internalDecision,
    external_decision: normalizeGloryDecision(internalDecision),
    reason,
    intent,
    claimed_principal_id: claimedPrincipalId,
    resolved_principal_id: trusted?.principal_id ?? null,
    agent_id: intent?.agent_id ?? null,
    requested_action: intent?.action ?? null,
    target: intent?.target ?? null,
    requested_discount_bps: intent?.requested_discount_bps ?? null,
    delegated_limit_bps: trusted?.maximum_discount_bps ?? null,
  });
}

function isOpportunityTarget(target: string): boolean {
  return /^Opportunity [A-Za-z0-9][A-Za-z0-9 ._-]{0,127}$/.test(target);
}

export function authorizeGloryDiscountIntent(
  rawIntent: unknown,
  authority: GloryTrustedDelegationAuthority,
  now: Date
): GloryAuthorizationEvaluation {
  let intent: Readonly<GloryBusinessIntent>;
  try {
    intent = parseGloryBusinessIntent(rawIntent);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("glory_intent_invalid_")) {
      return result("INVALID", "invalid_business_intent", null, null);
    }
    throw error;
  }

  const nowMs = now.getTime();
  if (!Number.isFinite(nowMs)) return result("INVALID", "invalid_clock", intent, null);

  const trusted = authority.resolveByAgent(intent.agent_id);
  if (trusted === null) {
    return result("UNRESOLVED", "trusted_delegation_unresolved", intent, null);
  }
  if (intent.principal_id !== trusted.principal_id) {
    return result("UNRESOLVED", "principal_mismatch", intent, trusted);
  }
  if (!trusted.enabled) {
    return result("UNRESOLVED", "delegation_disabled", intent, trusted);
  }
  if (nowMs < Date.parse(trusted.valid_from)) {
    return result("UNRESOLVED", "delegation_not_yet_valid", intent, trusted);
  }
  if (nowMs >= Date.parse(trusted.valid_until)) {
    return result("UNRESOLVED", "delegation_expired", intent, trusted);
  }
  if (Date.parse(intent.requested_at) >= Date.parse(intent.expires_at)) {
    return result("INVALID", "intent_validity_invalid", intent, trusted);
  }
  if (nowMs < Date.parse(intent.requested_at)) {
    return result("UNRESOLVED", "intent_not_yet_valid", intent, trusted);
  }
  if (nowMs >= Date.parse(intent.expires_at)) {
    return result("UNRESOLVED", "intent_expired", intent, trusted);
  }
  if (intent.action !== trusted.permitted_action) {
    return result("DENY", "action_not_permitted", intent, trusted);
  }
  if (trusted.target_type !== "opportunity" || !isOpportunityTarget(intent.target)) {
    return result("DENY", "target_outside_delegation", intent, trusted);
  }
  if (intent.requested_discount_bps > trusted.maximum_discount_bps) {
    return result("DENY", "delegated_limit_exceeded", intent, trusted);
  }
  return result("ALLOW", "within_delegated_limit", intent, trusted);
}
