import assert from "node:assert/strict";
import { test } from "node:test";
import {
  createGloryDemoIntent,
  createGloryPocRuntime,
} from "../../../src/poc/glory/poc.js";
import {
  createEphemeralGloryPocSigner,
  type GloryProofSigner,
} from "../../../src/poc/glory/runtime_proof_issuer.js";

const NOW = new Date("2026-09-11T10:00:00.000Z");

test("POC-01 700 <= 1000 allows, signs, guards, and causes exactly one CRM effect", async () => {
  const runtime = createGloryPocRuntime();
  const result = await runtime.run(createGloryDemoIntent(700));

  assert.equal(result.authorization_evidence.internal_decision, "ALLOW");
  assert.equal(result.authorization_evidence.normalized_external_decision, "ALLOW");
  assert.equal(result.authorization_evidence.proof_issuance_result, "ISSUED");
  assert.equal(result.authorization_evidence.guard_result, "PASS");
  assert.equal(result.proof_verification?.verification, "verified_locally");
  assert.equal(result.execution_evidence?.execution_status, "APPLIED");
  assert.equal(result.execution_evidence?.actual_discount_bps, 700);
  assert.equal(runtime.getEffectCount(), 1);
  assert.notStrictEqual(result.authorization_evidence, result.execution_evidence);

  const decisionId = result.authorization_evidence.authorization_decision_id!;
  const firstSnapshot = runtime.getAuthorizedActionRecord(decisionId)!;
  assert.equal(Object.isFrozen(firstSnapshot), true);
  assert.throws(() => {
    (firstSnapshot as { target: string }).target = "Opportunity B";
  }, TypeError);
  assert.equal(runtime.getAuthorizedActionRecord(decisionId)?.target, "Opportunity A");
});

test("POC-02 1500 > 1000 denies with no proof and no effect", async () => {
  const runtime = createGloryPocRuntime();
  const result = await runtime.run(createGloryDemoIntent(1_500));

  assert.equal(result.authorization_evidence.internal_decision, "DENY");
  assert.equal(result.authorization_evidence.normalized_external_decision, "STOP");
  assert.equal(result.authorization_evidence.proof_issuance_result, "NOT_ELIGIBLE");
  assert.equal(result.proof, null);
  assert.equal(result.execution_evidence, null);
  assert.equal(runtime.getEffectCount(), 0);
});

test("POC-03 principal substitution fails closed", async () => {
  const runtime = createGloryPocRuntime();
  const intent = {
    ...createGloryDemoIntent(700),
    principal_id: "principal-attacker-999",
  };
  const result = await runtime.run(intent);

  assert.equal(result.authorization_evidence.internal_decision, "UNRESOLVED");
  assert.equal(result.authorization_evidence.authorization_reason, "principal_mismatch");
  assert.equal(result.authorization_evidence.resolved_principal_id, "principal-demo-001");
  assert.equal(result.proof, null);
  assert.equal(runtime.getEffectCount(), 0);
});

test("POC-04 any non-ALLOW or unresolved decision produces no proof and no execution", async () => {
  const runtime = createGloryPocRuntime();
  const result = await runtime.run({
    ...createGloryDemoIntent(700),
    agent_id: "agent-unresolved-999",
  });

  assert.notEqual(result.authorization_evidence.internal_decision, "ALLOW");
  assert.equal(result.authorization_evidence.normalized_external_decision, "STOP");
  assert.equal(result.proof, null);
  assert.equal(result.authorization_evidence.guard_result, "NOT_REACHED");
  assert.equal(runtime.getRequestCount(), 0);
});

test("POC-05 signing failure returns no proof and cannot execute", async () => {
  const validSigner = createEphemeralGloryPocSigner("glory-failing-key-001");
  const failingSigner: GloryProofSigner = Object.freeze({
    ...validSigner,
    signMessage: () => {
      throw new Error("simulated signing failure");
    },
  });
  const runtime = createGloryPocRuntime({ signer: failingSigner });
  const result = await runtime.run(createGloryDemoIntent(700));

  assert.equal(result.authorization_evidence.internal_decision, "ALLOW");
  assert.equal(result.authorization_evidence.proof_issuance_result, "NOT_ISSUED");
  assert.equal(result.authorization_evidence.proof_issuance_reason, "signing_failed");
  assert.equal(result.proof, null);
  assert.equal(runtime.getEffectCount(), 0);
});

test("POC-06 missing proof is blocked before downstream", async () => {
  const runtime = createGloryPocRuntime();
  const attempt = runtime.authorize(createGloryDemoIntent(700));
  const result = await runtime.execute(attempt.authorization_attempt_id, {
    proof: null,
  });

  assert.equal(result.authorization_evidence.guard_result, "BLOCK");
  assert.equal(result.execution_evidence, null);
  assert.equal(runtime.getRequestCount(), 0);
});

test("POC-07 altered signature is blocked before downstream", async () => {
  const runtime = createGloryPocRuntime();
  const attempt = runtime.authorize(createGloryDemoIntent(700));
  const tampered = structuredClone(attempt.proof!);
  tampered.signature = `${tampered.signature[0] === "A" ? "B" : "A"}${tampered.signature.slice(1)}`;
  const result = await runtime.execute(attempt.authorization_attempt_id, {
    proof: tampered,
  });

  assert.equal(result.authorization_evidence.guard_result, "BLOCK");
  assert.equal(result.authorization_evidence.guard_reason, "proof_verification_failed");
  assert.equal(runtime.getRequestCount(), 0);
});

test("POC-08 expired proof is blocked before downstream", async () => {
  let now = new Date(NOW);
  const runtime = createGloryPocRuntime({
    clock: { now: () => new Date(now) },
  });
  const attempt = runtime.authorize(createGloryDemoIntent(700));
  now = new Date("2026-09-11T10:00:21.000Z");
  const result = await runtime.execute(attempt.authorization_attempt_id);

  assert.equal(result.authorization_evidence.guard_result, "BLOCK");
  assert.equal(result.authorization_evidence.guard_reason, "proof_expired");
  assert.equal(runtime.getRequestCount(), 0);
});

test("POC-09 Opportunity A authorization cannot execute against Opportunity B", async () => {
  const runtime = createGloryPocRuntime();
  const attempt = runtime.authorize(createGloryDemoIntent(700));
  const result = await runtime.execute(attempt.authorization_attempt_id, {
    executionOverrides: { target: "Opportunity B" },
  });

  assert.equal(result.authorization_evidence.guard_result, "BLOCK");
  assert.equal(result.authorization_evidence.guard_reason, "target_mismatch");
  assert.equal(runtime.getEffectCount(), 0);
});

test("POC-10 700 bps authorization cannot execute 900 bps", async () => {
  const runtime = createGloryPocRuntime();
  const attempt = runtime.authorize(createGloryDemoIntent(700));
  const result = await runtime.execute(attempt.authorization_attempt_id, {
    executionOverrides: { requested_discount_bps: 900 },
  });

  assert.equal(result.authorization_evidence.guard_result, "BLOCK");
  assert.equal(result.authorization_evidence.guard_reason, "discount_mismatch");
  assert.equal(runtime.getEffectCount(), 0);
});

test("POC-11 action substitution is blocked", async () => {
  const runtime = createGloryPocRuntime();
  const attempt = runtime.authorize(createGloryDemoIntent(700));
  const result = await runtime.execute(attempt.authorization_attempt_id, {
    executionOverrides: { action: "crm.discount.preview" },
  });

  assert.equal(result.authorization_evidence.guard_result, "BLOCK");
  assert.equal(result.authorization_evidence.guard_reason, "action_mismatch");
  assert.equal(runtime.getEffectCount(), 0);
});

test("POC-12 replay produces one first effect and blocks the second execution", async () => {
  const runtime = createGloryPocRuntime();
  const attempt = runtime.authorize(createGloryDemoIntent(700));

  const first = await runtime.execute(attempt.authorization_attempt_id);
  const second = await runtime.execute(attempt.authorization_attempt_id);

  assert.equal(first.authorization_evidence.guard_result, "PASS");
  assert.equal(second.authorization_evidence.guard_result, "BLOCK");
  assert.equal(second.authorization_evidence.guard_reason, "authorization_replay");
  assert.equal(runtime.getRequestCount(), 1);
  assert.equal(runtime.getEffectCount(), 1);
});

test("POC-13 indeterminate downstream outcome requires determination and is not retried", async () => {
  const runtime = createGloryPocRuntime({
    downstreamMode: "timeout_after_effect",
  });
  const attempt = runtime.authorize(createGloryDemoIntent(700));

  const first = await runtime.execute(attempt.authorization_attempt_id);
  const second = await runtime.execute(attempt.authorization_attempt_id);

  assert.equal(first.authorization_evidence.guard_result, "PASS");
  assert.equal(first.authorization_evidence.downstream_outcome, "INDETERMINATE");
  assert.equal(first.determination, "REQUIRES_DETERMINATION");
  assert.equal(first.execution_evidence, null);
  assert.equal(second.authorization_evidence.guard_result, "BLOCK");
  assert.equal(runtime.getRequestCount(), 1);
  assert.equal(runtime.getEffectCount(), 1);
});

test("POC-14 adapter success claim is non-authoritative and CRM evidence remains truth", async () => {
  const runtime = createGloryPocRuntime({ downstreamMode: "reject" });
  const attempt = runtime.authorize(createGloryDemoIntent(700));
  const result = await runtime.execute(attempt.authorization_attempt_id, {
    adapterClaimedDownstreamStatus: "SUCCEEDED",
  });

  assert.equal(result.untrusted_adapter_claimed_downstream_status, "SUCCEEDED");
  assert.equal(result.authorization_evidence.downstream_outcome, "REJECTED");
  assert.equal(result.execution_evidence?.execution_status, "REJECTED");
  assert.equal(result.execution_evidence?.actual_discount_bps, 0);
  assert.equal(runtime.getEffectCount(), 0);
  assert.equal(
    Object.prototype.hasOwnProperty.call(result.execution_evidence, "authorized"),
    false
  );
});
