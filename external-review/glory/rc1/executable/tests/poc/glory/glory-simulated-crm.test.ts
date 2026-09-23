import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GLORY_CRM_DISCOUNT_ACTION,
  createGloryTrustedDelegationAuthority,
  type GloryBusinessIntent,
} from "../../../src/poc/glory/authorization.js";
import { createGloryAuthorizationRecordAuthority } from "../../../src/poc/glory/authorization_records.js";
import {
  createGloryExecutionGuard,
  type GloryExecutionRequest,
} from "../../../src/poc/glory/execution_guard.js";
import {
  createEphemeralGloryPocSigner,
  createGloryRuntimeProofIssuer,
} from "../../../src/poc/glory/runtime_proof_issuer.js";
import { createSimulatedGloryCrm } from "../../../src/poc/glory/simulated_crm.js";

const NOW = new Date("2026-09-11T10:00:00.000Z");
const EXECUTED_AT = new Date("2026-09-11T10:00:01.000Z");

const INTENT: GloryBusinessIntent = Object.freeze({
  intent_id: "intent-glory-simulator-001",
  principal_id: "principal-demo-001",
  agent_id: "agent-demo-001",
  action: GLORY_CRM_DISCOUNT_ACTION,
  target: "Opportunity A",
  requested_discount_bps: 700,
  requested_at: "2026-09-11T09:59:50.000Z",
  expires_at: "2026-09-11T10:00:20.000Z",
});

function setup(timeoutAfterEffect = false) {
  const records = createGloryAuthorizationRecordAuthority({
    delegations: createGloryTrustedDelegationAuthority([
      {
        principal_id: "principal-demo-001",
        agent_id: "agent-demo-001",
        permitted_action: GLORY_CRM_DISCOUNT_ACTION,
        maximum_discount_bps: 1_000,
        target_type: "opportunity",
        enabled: true,
        valid_from: "2026-09-11T00:00:00.000Z",
        valid_until: "2026-09-12T00:00:00.000Z",
      },
    ]),
    decisionIdSource: () => "decision-glory-simulator-001",
  });
  const recording = records.authorizeAndRecord(INTENT, NOW);
  const issuer = createGloryRuntimeProofIssuer({
    records,
    signer: createEphemeralGloryPocSigner("glory-simulator-key-001"),
    clock: { now: () => new Date(NOW) },
  });
  const issuance = issuer.issueForDecision(
    recording.authorization_record!.authorization_decision_id
  );
  assert.equal(issuance.issuance, "issued");
  const simulator = createSimulatedGloryCrm({
    opportunities: [{ opportunity_id: "Opportunity A", approved_discount_bps: 0 }],
    clock: { now: () => new Date(EXECUTED_AT) },
    timeoutAfterEffect,
  });
  const guard = createGloryExecutionGuard({
    records,
    trustedVerification: issuer.getTrustedVerificationContext(),
    downstream: simulator,
    clock: { now: () => new Date(NOW) },
  });
  const request: GloryExecutionRequest = {
    authorization_proof: issuance.proof,
    principal_id: INTENT.principal_id,
    agent_id: INTENT.agent_id,
    action: INTENT.action,
    target: INTENT.target,
    requested_discount_bps: INTENT.requested_discount_bps,
  };
  return { guard, request, simulator };
}

test("B6 applies an authorized discount and emits separate downstream execution evidence", async () => {
  const { guard, request, simulator } = setup();
  assert.deepEqual(simulator.getOpportunity("Opportunity A"), {
    opportunity_id: "Opportunity A",
    approved_discount_bps: 0,
    execution_id: null,
    authorization_correlation_id: null,
    execution_status: "NOT_EXECUTED",
    executed_at: null,
  });

  const result = await guard.execute(request);
  assert.equal(result.guard_result, "PASS");
  assert.equal(result.downstream_outcome, "SUCCEEDED");
  assert.equal(simulator.getEffectCount(), 1);
  assert.equal(simulator.getRequestCount(), 1);
  assert.deepEqual(simulator.getOpportunity("Opportunity A"), {
    opportunity_id: "Opportunity A",
    approved_discount_bps: 700,
    execution_id: "glory-execution:decision-glory-simulator-001",
    authorization_correlation_id: "decision-glory-simulator-001",
    execution_status: "APPLIED",
    executed_at: EXECUTED_AT.toISOString(),
  });
  assert.deepEqual(
    result.execution_evidence,
    simulator.getExecutionEvidence(
      "glory-execution:decision-glory-simulator-001"
    )
  );
  assert.equal(
    Object.prototype.hasOwnProperty.call(result.execution_evidence, "authorized"),
    false
  );
});

test("B6 receives no downstream request and changes no CRM state when the guard blocks", async () => {
  const { guard, request, simulator } = setup();
  const result = await guard.execute({ ...request, target: "Opportunity B" });
  assert.equal(result.guard_result, "BLOCK");
  assert.equal(simulator.getRequestCount(), 0);
  assert.equal(simulator.getEffectCount(), 0);
  assert.equal(
    simulator.getOpportunity("Opportunity A")?.approved_discount_bps,
    0
  );
});

test("B6 timeout after a possible effect is indeterminate and never blindly retried", async () => {
  const { guard, request, simulator } = setup(true);

  const first = await guard.execute(request);
  assert.equal(first.guard_result, "PASS");
  assert.equal(first.downstream_outcome, "INDETERMINATE");
  assert.equal(first.determination, "REQUIRES_DETERMINATION");
  assert.equal(first.execution_evidence, null);
  assert.equal(simulator.getRequestCount(), 1);
  assert.equal(simulator.getEffectCount(), 1);
  assert.equal(
    simulator.getOpportunity("Opportunity A")?.approved_discount_bps,
    700
  );

  const second = await guard.execute(request);
  assert.equal(second.guard_result, "BLOCK");
  assert.equal(second.reason, "authorization_replay");
  assert.equal(simulator.getRequestCount(), 1);
  assert.equal(simulator.getEffectCount(), 1);
});
