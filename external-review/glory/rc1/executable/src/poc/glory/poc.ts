/** Executable composition root for the bounded Glory CRM discount POC. */

import type { AuthorizationProof } from "../../core/contracts.js";
import { verifyAuthorizationProofLocally } from "../../core/authorization_proof_verification.js";
import {
  GLORY_CRM_DISCOUNT_ACTION,
  createGloryTrustedDelegationAuthority,
  type GloryAuthorizationEvaluation,
  type GloryBusinessIntent,
} from "./authorization.js";
import {
  createGloryAuthorizationRecordAuthority,
  type GloryAuthorizationRecordAuthority,
  type GloryAuthorizedActionRecord,
} from "./authorization_records.js";
import {
  createGloryExecutionGuard,
  type GloryExecutionEvidence,
  type GloryExecutionGuardResult,
  type GloryExecutionRequest,
} from "./execution_guard.js";
import {
  createEphemeralGloryPocSigner,
  createGloryRuntimeProofIssuer,
  type GloryProofIssuanceResult,
  type GloryProofSigner,
  type GloryRuntimeProofIssuer,
  type GloryTrustedProofVerificationContext,
} from "./runtime_proof_issuer.js";
import {
  createSimulatedGloryCrm,
  type SimulatedGloryCrm,
  type SimulatedGloryOpportunityState,
} from "./simulated_crm.js";

export const GLORY_POC_FIXED_NOW = "2026-09-11T10:00:00.000Z";

export interface GloryAuthorizationEvidence {
  intent_id: string | null;
  claimed_principal_id: string | null;
  resolved_principal_id: string | null;
  agent_id: string | null;
  requested_action: string | null;
  target: string | null;
  requested_discount_bps: number | null;
  delegated_limit_bps: number | null;
  internal_decision: GloryAuthorizationEvaluation["internal_decision"];
  normalized_external_decision: GloryAuthorizationEvaluation["external_decision"];
  authorization_reason: string;
  authorization_request_id: string | null;
  authorization_decision_id: string | null;
  proof_issuance_result: "ISSUED" | "NOT_ISSUED" | "NOT_ELIGIBLE";
  proof_issuance_reason: string | null;
  proof_id: string | null;
  guard_result: "NOT_REACHED" | "PASS" | "BLOCK";
  guard_reason: string | null;
  downstream_outcome: "NOT_SENT" | "SUCCEEDED" | "REJECTED" | "INDETERMINATE";
}

export interface GloryPocAuthorizationAttempt {
  authorization_attempt_id: string;
  proof: AuthorizationProof | null;
  authorization_evidence: GloryAuthorizationEvidence;
}

export interface GloryPocExecutionOptions {
  /** Explicit null simulates a missing proof; omitted uses the issued proof. */
  proof?: AuthorizationProof | null;
  executionOverrides?: Partial<
    Pick<
      GloryExecutionRequest,
      | "principal_id"
      | "agent_id"
      | "action"
      | "target"
      | "requested_discount_bps"
    >
  >;
  /** Recorded as untrusted diagnostic input and never used as CRM evidence. */
  adapterClaimedDownstreamStatus?: string;
}

export interface GloryPocResult {
  authorization_attempt_id: string;
  proof: AuthorizationProof | null;
  proof_verification: ReturnType<typeof verifyAuthorizationProofLocally> | null;
  authorization_evidence: GloryAuthorizationEvidence;
  execution_evidence: GloryExecutionEvidence | null;
  determination: "REQUIRES_DETERMINATION" | null;
  untrusted_adapter_claimed_downstream_status: string | null;
  simulated_opportunity: SimulatedGloryOpportunityState | null;
}

export interface CreateGloryPocRuntimeInput {
  clock?: { now(): Date };
  signer?: GloryProofSigner;
  downstreamMode?: "success" | "reject" | "timeout_after_effect";
}

export interface GloryPocRuntime {
  authorize(rawIntent: unknown): GloryPocAuthorizationAttempt;
  execute(
    authorizationAttemptId: string,
    options?: GloryPocExecutionOptions
  ): Promise<GloryPocResult>;
  run(rawIntent: unknown, options?: GloryPocExecutionOptions): Promise<GloryPocResult>;
  getAuthorizedActionRecord(
    authorizationDecisionId: string
  ): Readonly<GloryAuthorizedActionRecord> | null;
  getOpportunity(opportunityId: string): SimulatedGloryOpportunityState | null;
  getTrustedVerificationContext(): Readonly<GloryTrustedProofVerificationContext>;
  verifyProof(
    proof: AuthorizationProof
  ): ReturnType<typeof verifyAuthorizationProofLocally>;
  getRequestCount(): number;
  getEffectCount(): number;
}

interface StoredAttempt {
  evaluation: GloryAuthorizationEvaluation;
  proof: AuthorizationProof | null;
  evidence: GloryAuthorizationEvidence;
}

function snapshotProof(proof: AuthorizationProof | null): AuthorizationProof | null {
  return proof === null ? null : structuredClone(proof);
}

function snapshotAuthorizationEvidence(
  evidence: GloryAuthorizationEvidence
): GloryAuthorizationEvidence {
  return Object.freeze({ ...evidence });
}

function snapshotAttempt(
  attemptId: string,
  stored: StoredAttempt
): GloryPocAuthorizationAttempt {
  return Object.freeze({
    authorization_attempt_id: attemptId,
    proof: snapshotProof(stored.proof),
    authorization_evidence: snapshotAuthorizationEvidence(stored.evidence),
  });
}

function issuanceFields(
  issuance: GloryProofIssuanceResult | null
): Pick<
  GloryAuthorizationEvidence,
  "proof_issuance_result" | "proof_issuance_reason" | "proof_id"
> {
  if (issuance === null) {
    return {
      proof_issuance_result: "NOT_ELIGIBLE",
      proof_issuance_reason: null,
      proof_id: null,
    };
  }
  return issuance.issuance === "issued"
    ? {
        proof_issuance_result: "ISSUED",
        proof_issuance_reason: null,
        proof_id: issuance.proof.proof_id,
      }
    : {
        proof_issuance_result: "NOT_ISSUED",
        proof_issuance_reason: issuance.reason,
        proof_id: null,
      };
}

function buildInitialEvidence(
  evaluation: GloryAuthorizationEvaluation,
  record: Readonly<GloryAuthorizedActionRecord> | null,
  issuance: GloryProofIssuanceResult | null
): GloryAuthorizationEvidence {
  return snapshotAuthorizationEvidence({
    intent_id: evaluation.intent?.intent_id ?? null,
    claimed_principal_id: evaluation.claimed_principal_id,
    resolved_principal_id: evaluation.resolved_principal_id,
    agent_id: evaluation.agent_id,
    requested_action: evaluation.requested_action,
    target: evaluation.target,
    requested_discount_bps: evaluation.requested_discount_bps,
    delegated_limit_bps: evaluation.delegated_limit_bps,
    internal_decision: evaluation.internal_decision,
    normalized_external_decision: evaluation.external_decision,
    authorization_reason: evaluation.reason,
    authorization_request_id: record?.authorization_request_id ?? null,
    authorization_decision_id: record?.authorization_decision_id ?? null,
    ...issuanceFields(issuance),
    guard_result: "NOT_REACHED",
    guard_reason: null,
    downstream_outcome: "NOT_SENT",
  });
}

function withGuardEvidence(
  evidence: GloryAuthorizationEvidence,
  guard: GloryExecutionGuardResult
): GloryAuthorizationEvidence {
  return snapshotAuthorizationEvidence({
    ...evidence,
    guard_result: guard.guard_result,
    guard_reason: guard.guard_result === "BLOCK" ? guard.reason : null,
    downstream_outcome: guard.downstream_outcome,
  });
}

function defaultClock(): { now(): Date } {
  return Object.freeze({
    now: () => new Date(GLORY_POC_FIXED_NOW),
  });
}

export function createGloryDemoIntent(
  requestedDiscountBps: number
): GloryBusinessIntent {
  return Object.freeze({
    intent_id: `intent-glory-demo-${requestedDiscountBps}`,
    principal_id: "principal-demo-001",
    agent_id: "agent-demo-001",
    action: GLORY_CRM_DISCOUNT_ACTION,
    target: "Opportunity A",
    requested_discount_bps: requestedDiscountBps,
    requested_at: "2026-09-11T09:59:50.000Z",
    expires_at: "2026-09-11T10:00:20.000Z",
  });
}

export function createGloryPocRuntime(
  options: CreateGloryPocRuntimeInput = {}
): GloryPocRuntime {
  const clock = options.clock ?? defaultClock();
  let decisionSequence = 0;
  let attemptSequence = 0;
  const records: GloryAuthorizationRecordAuthority =
    createGloryAuthorizationRecordAuthority({
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
      decisionIdSource: () =>
        `decision-glory-${String(++decisionSequence).padStart(4, "0")}`,
    });
  const issuer: GloryRuntimeProofIssuer = createGloryRuntimeProofIssuer({
    records,
    signer: options.signer ?? createEphemeralGloryPocSigner(),
    clock,
  });
  const simulator: SimulatedGloryCrm = createSimulatedGloryCrm({
    opportunities: [
      { opportunity_id: "Opportunity A", approved_discount_bps: 0 },
    ],
    clock,
    rejectBeforeEffect: options.downstreamMode === "reject",
    timeoutAfterEffect: options.downstreamMode === "timeout_after_effect",
  });
  const guard = createGloryExecutionGuard({
    records,
    trustedVerification: issuer.getTrustedVerificationContext(),
    downstream: simulator,
    clock,
  });
  const attempts = new Map<string, StoredAttempt>();

  function authorize(rawIntent: unknown): GloryPocAuthorizationAttempt {
    const recording = records.authorizeAndRecord(rawIntent, clock.now());
    const record = recording.authorization_record;
    const issuance = record === null
      ? null
      : issuer.issueForDecision(record.authorization_decision_id);
    const proof = issuance?.issuance === "issued" ? issuance.proof : null;
    const evidence = buildInitialEvidence(
      recording.evaluation,
      record,
      issuance
    );
    const attemptId = `glory-authorization-attempt-${String(
      ++attemptSequence
    ).padStart(4, "0")}`;
    const stored: StoredAttempt = {
      evaluation: recording.evaluation,
      proof: snapshotProof(proof),
      evidence,
    };
    attempts.set(attemptId, stored);
    return snapshotAttempt(attemptId, stored);
  }

  async function execute(
    authorizationAttemptId: string,
    executionOptions: GloryPocExecutionOptions = {}
  ): Promise<GloryPocResult> {
    const stored = attempts.get(authorizationAttemptId);
    if (stored === undefined) throw new Error("glory_authorization_attempt_not_found");
    const issuedProof = snapshotProof(stored.proof);
    const proofVerification = issuedProof === null
      ? null
      : verifyAuthorizationProofLocally({
          proof: issuedProof,
          verification_material:
            issuer.getTrustedVerificationContext().verification_material,
        });
    const adapterClaim =
      executionOptions.adapterClaimedDownstreamStatus ?? null;

    if (stored.proof === null || stored.evaluation.intent === null) {
      return Object.freeze({
        authorization_attempt_id: authorizationAttemptId,
        proof: issuedProof,
        proof_verification: proofVerification,
        authorization_evidence: snapshotAuthorizationEvidence(stored.evidence),
        execution_evidence: null,
        determination: null,
        untrusted_adapter_claimed_downstream_status: adapterClaim,
        simulated_opportunity: simulator.getOpportunity("Opportunity A"),
      });
    }

    const hasProofOverride = Object.prototype.hasOwnProperty.call(
      executionOptions,
      "proof"
    );
    const submittedProof = hasProofOverride
      ? executionOptions.proof ?? null
      : snapshotProof(stored.proof);
    const intent = stored.evaluation.intent;
    const rawExecutionRequest: Record<string, unknown> = {
      authorization_proof: submittedProof,
      principal_id: intent.principal_id,
      agent_id: intent.agent_id,
      action: intent.action,
      target: intent.target,
      requested_discount_bps: intent.requested_discount_bps,
      ...executionOptions.executionOverrides,
    };
    if (submittedProof === null) delete rawExecutionRequest.authorization_proof;

    const guardResult = await guard.execute(rawExecutionRequest);
    return Object.freeze({
      authorization_attempt_id: authorizationAttemptId,
      proof: issuedProof,
      proof_verification: proofVerification,
      authorization_evidence: withGuardEvidence(stored.evidence, guardResult),
      execution_evidence:
        guardResult.guard_result === "PASS"
          ? guardResult.execution_evidence
          : null,
      determination:
        guardResult.guard_result === "PASS" ? guardResult.determination : null,
      untrusted_adapter_claimed_downstream_status: adapterClaim,
      simulated_opportunity: simulator.getOpportunity("Opportunity A"),
    });
  }

  return Object.freeze({
    authorize,
    execute,
    async run(rawIntent: unknown, executionOptions?: GloryPocExecutionOptions) {
      const attempt = authorize(rawIntent);
      return execute(attempt.authorization_attempt_id, executionOptions);
    },
    getAuthorizedActionRecord(authorizationDecisionId: string) {
      return records.resolveByDecisionId(authorizationDecisionId);
    },
    getOpportunity(opportunityId: string) {
      return simulator.getOpportunity(opportunityId);
    },
    getTrustedVerificationContext() {
      return issuer.getTrustedVerificationContext();
    },
    verifyProof(proof: AuthorizationProof) {
      return verifyAuthorizationProofLocally({
        proof,
        verification_material:
          issuer.getTrustedVerificationContext().verification_material,
      });
    },
    getRequestCount() {
      return simulator.getRequestCount();
    },
    getEffectCount() {
      return simulator.getEffectCount();
    },
  });
}
