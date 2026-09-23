import assert from "node:assert/strict";
import { test } from "node:test";
import {
  GLORY_CRM_DISCOUNT_ACTION,
  createGloryTrustedDelegationAuthority,
  type GloryBusinessIntent,
  type GloryTrustedDelegationRecord,
} from "../../../src/poc/glory/authorization.js";
import { createGloryAuthorizationRecordAuthority } from "../../../src/poc/glory/authorization_records.js";
import {
  createGloryExecutionGuard,
  type GloryCrmExecutionCommand,
  type GloryCrmExecutionPort,
  type GloryExecutionRequest,
} from "../../../src/poc/glory/execution_guard.js";
import {
  createEphemeralGloryPocSigner,
  createGloryRuntimeProofIssuer,
} from "../../../src/poc/glory/runtime_proof_issuer.js";

const NOW = new Date("2026-09-11T10:00:00.000Z");

const INTENT: GloryBusinessIntent = Object.freeze({
  intent_id: "intent-glory-guard-001",
  principal_id: "principal-demo-001",
  agent_id: "agent-demo-001",
  action: GLORY_CRM_DISCOUNT_ACTION,
  target: "Opportunity A",
  requested_discount_bps: 700,
  requested_at: "2026-09-11T09:59:50.000Z",
  expires_at: "2026-09-11T10:00:20.000Z",
});

const DELEGATION: GloryTrustedDelegationRecord = Object.freeze({
  principal_id: "principal-demo-001",
  agent_id: "agent-demo-001",
  permitted_action: GLORY_CRM_DISCOUNT_ACTION,
  maximum_discount_bps: 1_000,
  target_type: "opportunity",
  enabled: true,
  valid_from: "2026-09-11T00:00:00.000Z",
  valid_until: "2026-09-12T00:00:00.000Z",
});

class CapturingCrmPort implements GloryCrmExecutionPort {
  readonly commands: GloryCrmExecutionCommand[] = [];

  async applyDiscount(command: Readonly<GloryCrmExecutionCommand>) {
    this.commands.push({ ...command });
    return {
      outcome: "SUCCEEDED" as const,
      execution_evidence: {
        execution_id: command.execution_id,
        opportunity_id: command.opportunity_id,
        actual_discount_bps: command.discount_bps,
        execution_status: "APPLIED" as const,
        executed_at: "2026-09-11T10:00:01.000Z",
        authorization_correlation_id: command.authorization_correlation_id,
      },
    };
  }
}

function setup(guardNow = NOW) {
  const records = createGloryAuthorizationRecordAuthority({
    delegations: createGloryTrustedDelegationAuthority([DELEGATION]),
    decisionIdSource: () => "decision-glory-guard-001",
  });
  const recording = records.authorizeAndRecord(INTENT, NOW);
  const issuer = createGloryRuntimeProofIssuer({
    records,
    signer: createEphemeralGloryPocSigner("glory-guard-key-001"),
    clock: { now: () => new Date(NOW) },
  });
  const issuance = issuer.issueForDecision(
    recording.authorization_record!.authorization_decision_id
  );
  assert.equal(issuance.issuance, "issued");
  const downstream = new CapturingCrmPort();
  const guard = createGloryExecutionGuard({
    records,
    trustedVerification: issuer.getTrustedVerificationContext(),
    downstream,
    clock: { now: () => new Date(guardNow) },
  });
  const request: GloryExecutionRequest = {
    authorization_proof: issuance.proof,
    principal_id: INTENT.principal_id,
    agent_id: INTENT.agent_id,
    action: INTENT.action,
    target: INTENT.target,
    requested_discount_bps: INTENT.requested_discount_bps,
  };
  return { guard, downstream, request };
}

test("B5 passes the exact authorized action once and blocks replay before dispatch", async () => {
  const { guard, downstream, request } = setup();

  const first = await guard.execute(request);
  assert.equal(first.guard_result, "PASS");
  assert.equal(first.downstream_outcome, "SUCCEEDED");
  assert.equal(downstream.commands.length, 1);

  const replay = await guard.execute(request);
  assert.equal(replay.guard_result, "BLOCK");
  assert.equal(replay.reason, "authorization_replay");
  assert.equal(downstream.commands.length, 1);
});

test("B5 blocks every principal, agent, action, target, or bps substitution", async () => {
  const cases: readonly [string, Partial<GloryExecutionRequest>, string][] = [
    ["principal", { principal_id: "principal-attacker-999" }, "principal_mismatch"],
    ["agent", { agent_id: "agent-attacker-999" }, "agent_mismatch"],
    ["action", { action: "crm.discount.preview" }, "action_mismatch"],
    ["target", { target: "Opportunity B" }, "target_mismatch"],
    ["bps", { requested_discount_bps: 900 }, "discount_mismatch"],
  ];

  for (const [label, override, expectedReason] of cases) {
    const { guard, downstream, request } = setup();
    const result = await guard.execute({ ...request, ...override });
    assert.equal(result.guard_result, "BLOCK", label);
    assert.equal(result.reason, expectedReason, label);
    assert.equal(downstream.commands.length, 0, label);
  }
});

test("B5 blocks missing target or bps as malformed execution requests", async () => {
  for (const missing of ["target", "requested_discount_bps"] as const) {
    const { guard, downstream, request } = setup();
    const malformed = { ...request } as Record<string, unknown>;
    delete malformed[missing];
    const result = await guard.execute(malformed);
    assert.equal(result.guard_result, "BLOCK");
    assert.equal(result.reason, "invalid_execution_request");
    assert.equal(downstream.commands.length, 0);
  }
});

test("B5 blocks missing proof, invalid signature, and expired proof before dispatch", async () => {
  {
    const { guard, downstream, request } = setup();
    const missingProof = { ...request } as Record<string, unknown>;
    delete missingProof.authorization_proof;
    const result = await guard.execute(missingProof);
    assert.equal(result.guard_result, "BLOCK");
    assert.equal(downstream.commands.length, 0);
  }
  {
    const { guard, downstream, request } = setup();
    const tampered = structuredClone(request);
    const signature = tampered.authorization_proof.signature;
    tampered.authorization_proof.signature = `${signature[0] === "A" ? "B" : "A"}${signature.slice(1)}`;
    const result = await guard.execute(tampered);
    assert.equal(result.guard_result, "BLOCK");
    assert.equal(result.reason, "proof_verification_failed");
    assert.equal(downstream.commands.length, 0);
  }
  {
    const { guard, downstream, request } = setup(
      new Date("2026-09-11T10:00:21.000Z")
    );
    const result = await guard.execute(request);
    assert.equal(result.guard_result, "BLOCK");
    assert.equal(result.reason, "proof_expired");
    assert.equal(downstream.commands.length, 0);
  }
});
