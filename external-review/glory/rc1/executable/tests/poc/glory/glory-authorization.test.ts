import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GLORY_CRM_DISCOUNT_ACTION,
  GLORY_MAX_DISCOUNT_BPS,
  authorizeGloryDiscountIntent,
  createGloryTrustedDelegationAuthority,
  normalizeGloryDecision,
  parseGloryBusinessIntent,
  type GloryBusinessIntent,
  type GloryTrustedDelegationRecord,
} from "../../../src/poc/glory/authorization.js";

const NOW = new Date("2026-09-11T10:00:00.000Z");

const VALID_INTENT: GloryBusinessIntent = Object.freeze({
  intent_id: "intent-glory-001",
  principal_id: "principal-demo-001",
  agent_id: "agent-demo-001",
  action: GLORY_CRM_DISCOUNT_ACTION,
  target: "Opportunity A",
  requested_discount_bps: 700,
  requested_at: "2026-09-11T09:59:50.000Z",
  expires_at: "2026-09-11T10:00:20.000Z",
});

const TRUSTED_DELEGATION: GloryTrustedDelegationRecord = Object.freeze({
  principal_id: "principal-demo-001",
  agent_id: "agent-demo-001",
  permitted_action: GLORY_CRM_DISCOUNT_ACTION,
  maximum_discount_bps: 1_000,
  target_type: "opportunity",
  enabled: true,
  valid_from: "2026-09-11T00:00:00.000Z",
  valid_until: "2026-09-12T00:00:00.000Z",
});

function rawIntent(
  overrides: Record<string, unknown> = {}
): Record<string, unknown> {
  return { ...VALID_INTENT, ...overrides };
}

test("B1 parses only the exact adapter-local CRM discount intent", () => {
  const parsed = parseGloryBusinessIntent(rawIntent());
  assert.deepEqual(parsed, VALID_INTENT);
  assert.equal(parsed.requested_discount_bps, 700);

  const invalidCases: readonly Record<string, unknown>[] = [
    rawIntent({ intent_id: "" }),
    rawIntent({ principal_id: "" }),
    rawIntent({ agent_id: "" }),
    rawIntent({ action: "crm.discount.preview" }),
    rawIntent({ target: "" }),
    rawIntent({ requested_discount_bps: -1 }),
    rawIntent({ requested_discount_bps: 700.5 }),
    rawIntent({ requested_discount_bps: "700" }),
    rawIntent({ requested_discount_bps: "7%" }),
    rawIntent({ requested_discount_bps: GLORY_MAX_DISCOUNT_BPS + 1 }),
    rawIntent({ requested_discount_bps: Number.MAX_SAFE_INTEGER }),
    rawIntent({ requested_at: "11 September 2026" }),
    rawIntent({ expires_at: "2026-09-11T10:00:99.000Z" }),
    { ...rawIntent(), requested_discount_bps: undefined },
    { ...rawIntent(), extra_authority: "caller-supplied" },
  ];

  for (const invalid of invalidCases) {
    assert.throws(() => parseGloryBusinessIntent(invalid), /glory_intent_invalid/);
  }
});

test("B2 resolves authority from trusted agent binding and fails principal substitution closed", () => {
  const authority = createGloryTrustedDelegationAuthority([TRUSTED_DELEGATION]);

  const allowed = authorizeGloryDiscountIntent(rawIntent(), authority, NOW);
  assert.equal(allowed.internal_decision, "ALLOW");
  assert.equal(allowed.external_decision, "ALLOW");
  assert.equal(allowed.claimed_principal_id, "principal-demo-001");
  assert.equal(allowed.resolved_principal_id, "principal-demo-001");
  assert.equal(allowed.delegated_limit_bps, 1_000);

  const substituted = authorizeGloryDiscountIntent(
    rawIntent({ principal_id: "principal-attacker-999" }),
    authority,
    NOW
  );
  assert.equal(substituted.internal_decision, "UNRESOLVED");
  assert.equal(substituted.external_decision, "STOP");
  assert.equal(substituted.reason, "principal_mismatch");
  assert.equal(substituted.resolved_principal_id, "principal-demo-001");

  const unknownAgent = authorizeGloryDiscountIntent(
    rawIntent({ agent_id: "agent-unknown-999" }),
    authority,
    NOW
  );
  assert.equal(unknownAgent.internal_decision, "UNRESOLVED");
  assert.equal(unknownAgent.external_decision, "STOP");
  assert.equal(unknownAgent.reason, "trusted_delegation_unresolved");
});

test("B2 fails closed for disabled, invalid, or out-of-domain trusted delegation", () => {
  const cases: readonly [Partial<GloryTrustedDelegationRecord>, string][] = [
    [{ enabled: false }, "delegation_disabled"],
    [{ valid_from: "2026-09-11T10:00:01.000Z" }, "delegation_not_yet_valid"],
    [{ valid_until: "2026-09-11T10:00:00.000Z" }, "delegation_expired"],
    [{ permitted_action: "crm.discount.preview" }, "action_not_permitted"],
  ];

  for (const [override, expectedReason] of cases) {
    const authority = createGloryTrustedDelegationAuthority([
      { ...TRUSTED_DELEGATION, ...override },
    ]);
    const result = authorizeGloryDiscountIntent(rawIntent(), authority, NOW);
    assert.notEqual(result.external_decision, "ALLOW");
    assert.equal(result.reason, expectedReason);
  }

  const authority = createGloryTrustedDelegationAuthority([TRUSTED_DELEGATION]);
  const wrongDomain = authorizeGloryDiscountIntent(
    rawIntent({ target: "Contact A" }),
    authority,
    NOW
  );
  assert.equal(wrongDomain.external_decision, "STOP");
  assert.equal(wrongDomain.reason, "target_outside_delegation");
});

test("B3 evaluates the trusted maximum inclusively and never treats malformed bps as a decision", () => {
  const authority = createGloryTrustedDelegationAuthority([TRUSTED_DELEGATION]);
  const cases = [
    [0, "ALLOW"],
    [700, "ALLOW"],
    [1_000, "ALLOW"],
    [1_001, "DENY"],
    [1_500, "DENY"],
  ] as const;

  for (const [requestedBps, expected] of cases) {
    const result = authorizeGloryDiscountIntent(
      rawIntent({ requested_discount_bps: requestedBps }),
      authority,
      NOW
    );
    assert.equal(result.internal_decision, expected);
    assert.equal(result.external_decision, expected === "ALLOW" ? "ALLOW" : "STOP");
  }

  for (const malformed of [-1, 700.5, "700", undefined, Number.MAX_SAFE_INTEGER]) {
    const result = authorizeGloryDiscountIntent(
      rawIntent({ requested_discount_bps: malformed }),
      authority,
      NOW
    );
    assert.equal(result.internal_decision, "INVALID");
    assert.equal(result.external_decision, "STOP");
  }
});

test("B3 preserves internal decisions while only explicit ALLOW crosses the boundary", () => {
  assert.equal(normalizeGloryDecision("ALLOW"), "ALLOW");
  for (const decision of [
    "DENY",
    "REVIEW",
    "UNDECIDED",
    "UNKNOWN",
    "unresolved",
    "ambiguous",
    "invalid",
    null,
    undefined,
    new Error("evaluator failure"),
  ]) {
    assert.equal(normalizeGloryDecision(decision), "STOP");
  }
});
