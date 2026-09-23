import assert from "node:assert/strict";
import { test } from "node:test";
import { deriveAuthorizationProofId } from "../../../src/core/authorization_proof.js";
import { verifyAuthorizationProofLocally } from "../../../src/core/authorization_proof_verification.js";
import {
  GLORY_CRM_DISCOUNT_ACTION,
  createGloryTrustedDelegationAuthority,
  type GloryBusinessIntent,
  type GloryTrustedDelegationRecord,
} from "../../../src/poc/glory/authorization.js";
import {
  createGloryAuthorizationRecordAuthority,
} from "../../../src/poc/glory/authorization_records.js";
import {
  createEphemeralGloryPocSigner,
  createGloryRuntimeProofIssuer,
  type GloryProofSigner,
} from "../../../src/poc/glory/runtime_proof_issuer.js";

const NOW = new Date("2026-09-11T10:00:00.000Z");

const INTENT: GloryBusinessIntent = Object.freeze({
  intent_id: "intent-glory-001",
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

function setup(requestedDiscountBps = 700) {
  const delegations = createGloryTrustedDelegationAuthority([DELEGATION]);
  const records = createGloryAuthorizationRecordAuthority({
    delegations,
    decisionIdSource: () => "decision-glory-001",
  });
  const recording = records.authorizeAndRecord(
    { ...INTENT, requested_discount_bps: requestedDiscountBps },
    NOW
  );
  const signer = createEphemeralGloryPocSigner("glory-poc-key-001");
  const issuer = createGloryRuntimeProofIssuer({
    records,
    signer,
    clock: { now: () => new Date(NOW) },
  });
  return { records, recording, signer, issuer };
}

test("B4 issues a locally verifiable proof only from an explicit recorded ALLOW", () => {
  const { records, recording, issuer } = setup();
  assert.equal(recording.evaluation.internal_decision, "ALLOW");
  assert.equal(recording.evaluation.external_decision, "ALLOW");
  assert.notEqual(recording.authorization_record, null);

  const record = recording.authorization_record!;
  assert.deepEqual(
    {
      principal: record.principal_id,
      agent: record.agent_id,
      action: record.action,
      target: record.target,
      bps: record.requested_discount_bps,
    },
    {
      principal: "principal-demo-001",
      agent: "agent-demo-001",
      action: "crm.discount.apply",
      target: "Opportunity A",
      bps: 700,
    }
  );
  assert.equal(records.resolveByDecisionId(record.authorization_decision_id)?.target, "Opportunity A");

  const issuance = issuer.issueForDecision(record.authorization_decision_id);
  assert.equal(issuance.issuance, "issued");
  assert.equal(issuance.proof.payload.authorization_request_id, INTENT.intent_id);
  assert.equal(
    issuance.proof.payload.authorization_decision_id,
    record.authorization_decision_id
  );
  assert.equal(issuance.proof.payload.economic_scope.mode, "none");
  assert.deepEqual(
    verifyAuthorizationProofLocally({
      proof: issuance.proof,
      verification_material: issuer.getTrustedVerificationContext().verification_material,
    }),
    { verification: "verified_locally", proof_id: issuance.proof.proof_id }
  );
});

test("P0 proves the trusted authorization decision anchor is inside signed material", () => {
  const { recording, issuer } = setup();
  const issuance = issuer.issueForDecision(
    recording.authorization_record!.authorization_decision_id
  );
  assert.equal(issuance.issuance, "issued");

  const tampered = structuredClone(issuance.proof);
  tampered.payload.authorization_decision_id = "decision-attacker-999";
  tampered.proof_id = deriveAuthorizationProofId(tampered.payload);

  assert.deepEqual(
    verifyAuthorizationProofLocally({
      proof: tampered,
      verification_material: issuer.getTrustedVerificationContext().verification_material,
    }),
    { verification: "not_verified", reason: "invalid_signature" }
  );
});

test("B4 creates no trusted authorization record and no proof for DENY or unresolved", () => {
  const denied = setup(1_500);
  assert.equal(denied.recording.evaluation.internal_decision, "DENY");
  assert.equal(denied.recording.authorization_record, null);
  assert.deepEqual(denied.issuer.issueForDecision("decision-glory-001"), {
    issuance: "not_issued",
    reason: "authorization_record_not_found",
  });

  const unresolvedRecords = createGloryAuthorizationRecordAuthority({
    delegations: createGloryTrustedDelegationAuthority([DELEGATION]),
    decisionIdSource: () => "decision-glory-002",
  });
  const unresolved = unresolvedRecords.authorizeAndRecord(
    { ...INTENT, principal_id: "principal-attacker-999" },
    NOW
  );
  assert.equal(unresolved.evaluation.internal_decision, "UNRESOLVED");
  assert.equal(unresolved.authorization_record, null);
});

test("B4 fails closed when runtime signing or proof self-verification fails", () => {
  const { records, recording, signer } = setup();
  const failingSigner: GloryProofSigner = Object.freeze({
    algorithm_id: signer.algorithm_id,
    issuer_key_id: signer.issuer_key_id,
    public_key_spki_der_base64url: signer.public_key_spki_der_base64url,
    signMessage: () => {
      throw new Error("simulated signing failure");
    },
  });
  const issuer = createGloryRuntimeProofIssuer({
    records,
    signer: failingSigner,
    clock: { now: () => new Date(NOW) },
  });

  assert.deepEqual(
    issuer.issueForDecision(recording.authorization_record!.authorization_decision_id),
    { issuance: "not_issued", reason: "signing_failed" }
  );
});

test("B4 exposes no proof issuance path from a caller-supplied Business Intent", () => {
  const { issuer } = setup();
  assert.deepEqual(issuer.issueForDecision(INTENT as unknown as string), {
    issuance: "not_issued",
    reason: "authorization_record_not_found",
  });
});
