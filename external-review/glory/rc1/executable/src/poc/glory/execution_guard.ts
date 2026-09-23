/** Exact-action execution guard for the bounded simulated Glory CRM POC. */

import type { AuthorizationProof } from "../../core/contracts.js";
import {
  createAtomicAdmissionAuthority,
  type AtomicAdmissionAuthority,
} from "../../core/atomic_admission.js";
import { snapshotAuthorizationProof } from "../../core/authorization_proof.js";
import { verifyAuthorizationProofLocally } from "../../core/authorization_proof_verification.js";
import { GLORY_MAX_DISCOUNT_BPS } from "./authorization.js";
import type { GloryAuthorizationRecordAuthority } from "./authorization_records.js";
import type { GloryTrustedProofVerificationContext } from "./runtime_proof_issuer.js";

const EXECUTION_REQUEST_KEYS = [
  "authorization_proof",
  "principal_id",
  "agent_id",
  "action",
  "target",
  "requested_discount_bps",
] as const;

export interface GloryExecutionRequest {
  authorization_proof: AuthorizationProof;
  principal_id: string;
  agent_id: string;
  action: string;
  target: string;
  requested_discount_bps: number;
}

export interface GloryCrmExecutionCommand {
  execution_id: string;
  opportunity_id: string;
  discount_bps: number;
  authorization_correlation_id: string;
}

export interface GloryExecutionEvidence {
  execution_id: string;
  opportunity_id: string;
  actual_discount_bps: number;
  execution_status: "APPLIED" | "REJECTED";
  executed_at: string;
  authorization_correlation_id: string;
}

export type GloryCrmDispatchResult =
  | {
      outcome: "SUCCEEDED" | "REJECTED";
      execution_evidence: GloryExecutionEvidence;
    }
  | {
      outcome: "INDETERMINATE";
      execution_evidence: null;
      determination: "REQUIRES_DETERMINATION";
    };

export interface GloryCrmExecutionPort {
  applyDiscount(
    command: Readonly<GloryCrmExecutionCommand>
  ): Promise<GloryCrmDispatchResult>;
}

export type GloryGuardBlockReason =
  | "invalid_execution_request"
  | "proof_verification_failed"
  | "proof_untrusted"
  | "invalid_clock"
  | "proof_not_yet_valid"
  | "proof_expired"
  | "proof_validity_invalid"
  | "authorization_record_not_found"
  | "authorization_record_expired"
  | "proof_record_mismatch"
  | "principal_mismatch"
  | "agent_mismatch"
  | "action_mismatch"
  | "target_mismatch"
  | "discount_mismatch"
  | "authorization_replay"
  | "admission_rejected";

export type GloryExecutionGuardResult =
  | {
      guard_result: "BLOCK";
      reason: GloryGuardBlockReason;
      downstream_dispatched: false;
      downstream_outcome: "NOT_SENT";
      execution_evidence: null;
    }
  | {
      guard_result: "PASS";
      proof_id: string;
      authorization_decision_id: string;
      downstream_dispatched: true;
      downstream_outcome: "SUCCEEDED" | "REJECTED" | "INDETERMINATE";
      execution_evidence: GloryExecutionEvidence | null;
      determination: "REQUIRES_DETERMINATION" | null;
    };

export interface GloryExecutionGuard {
  execute(rawRequest: unknown): Promise<GloryExecutionGuardResult>;
}

export interface CreateGloryExecutionGuardInput {
  records: GloryAuthorizationRecordAuthority;
  trustedVerification: Readonly<GloryTrustedProofVerificationContext>;
  downstream: GloryCrmExecutionPort;
  clock: { now(): Date };
  admissionAuthority?: AtomicAdmissionAuthority;
}

class InvalidGloryExecutionRequest extends Error {}

function invalidExecutionRequest(): never {
  throw new InvalidGloryExecutionRequest("glory_execution_request_invalid");
}

function snapshotExecutionRequest(raw: unknown): GloryExecutionRequest {
  if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
    invalidExecutionRequest();
  }
  const descriptors = Object.getOwnPropertyDescriptors(raw);
  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.some((key) => typeof key !== "string") ||
    keys.length !== EXECUTION_REQUEST_KEYS.length ||
    keys.some((key) => !EXECUTION_REQUEST_KEYS.includes(key as never))
  ) {
    invalidExecutionRequest();
  }
  const captured = Object.create(null) as Record<string, unknown>;
  for (const key of EXECUTION_REQUEST_KEYS) {
    const descriptor = descriptors[key];
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      "get" in descriptor ||
      "set" in descriptor
    ) {
      invalidExecutionRequest();
    }
    captured[key] = descriptor.value;
  }

  for (const key of ["principal_id", "agent_id", "action", "target"] as const) {
    const value = captured[key];
    if (typeof value !== "string" || value.trim().length === 0) {
      invalidExecutionRequest();
    }
  }
  const requestedDiscountBps = captured.requested_discount_bps;
  if (
    typeof requestedDiscountBps !== "number" ||
    !Number.isSafeInteger(requestedDiscountBps) ||
    requestedDiscountBps < 0 ||
    requestedDiscountBps > GLORY_MAX_DISCOUNT_BPS
  ) {
    invalidExecutionRequest();
  }

  let proof: AuthorizationProof;
  try {
    proof = snapshotAuthorizationProof(
      captured.authorization_proof as AuthorizationProof
    );
  } catch (error) {
    if (error instanceof Error && error.message.startsWith("authorization_proof_")) {
      invalidExecutionRequest();
    }
    throw error;
  }
  return {
    authorization_proof: proof,
    principal_id: captured.principal_id as string,
    agent_id: captured.agent_id as string,
    action: captured.action as string,
    target: captured.target as string,
    requested_discount_bps: requestedDiscountBps,
  };
}

function block(reason: GloryGuardBlockReason): GloryExecutionGuardResult {
  return Object.freeze({
    guard_result: "BLOCK",
    reason,
    downstream_dispatched: false,
    downstream_outcome: "NOT_SENT",
    execution_evidence: null,
  });
}

function proofMatchesTrustedContext(
  proof: AuthorizationProof,
  trusted: Readonly<GloryTrustedProofVerificationContext>
): boolean {
  const payload = proof.payload;
  return trusted.key_status === "active" &&
    payload.issuer_id === trusted.issuer_id &&
    payload.issuer_key_id === trusted.verification_material.issuer_key_id &&
    payload.algorithm_id === trusted.verification_material.algorithm_id &&
    payload.audience === trusted.audience &&
    payload.runtime_id === trusted.runtime_id &&
    payload.provider_scope.mode === "exact" &&
    payload.provider_scope.provider_id === trusted.provider_id &&
    payload.service_scope.service_id === trusted.service_id &&
    payload.execution_scope.mode === "exact" &&
    payload.execution_scope.operation_type === trusted.operation_type &&
    payload.policy_digest === trusted.policy_digest &&
    payload.policy_epoch === trusted.policy_epoch &&
    payload.revocation_epoch === trusted.revocation_epoch &&
    payload.usage.mode === "single_use" &&
    payload.usage.maximum_usage_count === 1 &&
    payload.economic_scope.mode === "none" &&
    payload.delegation_constraints.delegation_mode === "delegated" &&
    payload.delegator_id === payload.principal_id;
}

function snapshotEvidence(
  evidence: GloryExecutionEvidence
): GloryExecutionEvidence {
  return Object.freeze({ ...evidence });
}

function validExecutedAt(value: unknown): value is string {
  return typeof value === "string" &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/.test(value) &&
    Number.isFinite(Date.parse(value));
}

function validDownstreamResult(
  value: GloryCrmDispatchResult,
  command: GloryCrmExecutionCommand
): value is Extract<GloryCrmDispatchResult, { outcome: "SUCCEEDED" | "REJECTED" }> {
  if (value.outcome !== "SUCCEEDED" && value.outcome !== "REJECTED") return false;
  const evidence = value.execution_evidence;
  if (
    evidence === null ||
    typeof evidence !== "object" ||
    evidence.execution_id !== command.execution_id ||
    evidence.opportunity_id !== command.opportunity_id ||
    evidence.authorization_correlation_id !== command.authorization_correlation_id ||
    !Number.isSafeInteger(evidence.actual_discount_bps) ||
    evidence.actual_discount_bps < 0 ||
    evidence.actual_discount_bps > GLORY_MAX_DISCOUNT_BPS ||
    !validExecutedAt(evidence.executed_at)
  ) {
    return false;
  }
  return value.outcome === "SUCCEEDED"
    ? evidence.execution_status === "APPLIED" &&
        evidence.actual_discount_bps === command.discount_bps
    : evidence.execution_status === "REJECTED";
}

function indeterminatePass(
  proof: AuthorizationProof
): GloryExecutionGuardResult {
  return Object.freeze({
    guard_result: "PASS",
    proof_id: proof.proof_id,
    authorization_decision_id: proof.payload.authorization_decision_id,
    downstream_dispatched: true,
    downstream_outcome: "INDETERMINATE",
    execution_evidence: null,
    determination: "REQUIRES_DETERMINATION",
  });
}

export function createGloryExecutionGuard(
  input: CreateGloryExecutionGuardInput
): GloryExecutionGuard {
  const admissionAuthority =
    input.admissionAuthority ?? createAtomicAdmissionAuthority();
  const trusted = Object.freeze({
    ...input.trustedVerification,
    verification_material: Object.freeze({
      ...input.trustedVerification.verification_material,
    }),
  });

  return Object.freeze({
    async execute(rawRequest: unknown): Promise<GloryExecutionGuardResult> {
      let request: GloryExecutionRequest;
      try {
        request = snapshotExecutionRequest(rawRequest);
      } catch (error) {
        if (
          error instanceof InvalidGloryExecutionRequest ||
          (error instanceof Error && error.message.startsWith("authorization_proof_"))
        ) {
          return block("invalid_execution_request");
        }
        return block("invalid_execution_request");
      }

      const proof = request.authorization_proof;
      let localVerification;
      try {
        localVerification = verifyAuthorizationProofLocally({
          proof,
          verification_material: trusted.verification_material,
        });
      } catch {
        return block("proof_verification_failed");
      }
      if (localVerification.verification !== "verified_locally") {
        return block("proof_verification_failed");
      }
      if (!proofMatchesTrustedContext(proof, trusted)) {
        return block("proof_untrusted");
      }

      let nowMs: number;
      try {
        nowMs = input.clock.now().getTime();
      } catch {
        return block("invalid_clock");
      }
      if (!Number.isFinite(nowMs)) return block("invalid_clock");
      const validFromMs = Date.parse(proof.payload.valid_from);
      const expiresAtMs = Date.parse(proof.payload.expires_at);
      if (expiresAtMs - validFromMs > trusted.maximum_validity_ms) {
        return block("proof_validity_invalid");
      }
      if (nowMs < validFromMs) return block("proof_not_yet_valid");
      if (nowMs >= expiresAtMs) return block("proof_expired");

      const record = input.records.resolveByDecisionId(
        proof.payload.authorization_decision_id
      );
      if (record === null || record.internal_decision !== "ALLOW") {
        return block("authorization_record_not_found");
      }
      if (nowMs >= Date.parse(record.intent_expires_at)) {
        return block("authorization_record_expired");
      }
      if (
        proof.payload.authorization_request_id !== record.authorization_request_id ||
        proof.payload.authorization_decision_id !== record.authorization_decision_id ||
        proof.payload.principal_id !== record.principal_id ||
        proof.payload.subject_agent_id !== record.agent_id ||
        proof.payload.execution_scope.mode !== "exact" ||
        proof.payload.execution_scope.execution_id !== record.execution_id ||
        proof.payload.execution_scope.operation_type !== record.action ||
        Date.parse(proof.payload.issued_at) < Date.parse(record.decided_at) ||
        expiresAtMs > Date.parse(record.intent_expires_at)
      ) {
        return block("proof_record_mismatch");
      }

      if (request.principal_id !== record.principal_id) {
        return block("principal_mismatch");
      }
      if (request.agent_id !== record.agent_id) return block("agent_mismatch");
      if (request.action !== record.action) return block("action_mismatch");
      if (request.target !== record.target) return block("target_mismatch");
      if (request.requested_discount_bps !== record.requested_discount_bps) {
        return block("discount_mismatch");
      }

      const admission = admissionAuthority.commitAuthorizationAdmission({
        admission_id: `glory-admission:${record.authorization_decision_id}`,
        proof,
        local_verification: localVerification,
        requested_usage_index: 1,
        execution_request: {
          mode: "exact",
          execution_attempt_id: record.execution_id,
          operation_type: record.action,
        },
        economic_request: { mode: "none" },
      });
      if (admission.admission === "admission_replayed") {
        return block("authorization_replay");
      }
      if (admission.admission === "admission_rejected") {
        return admission.failure.reason === "proof_usage_rejected"
          ? block("authorization_replay")
          : block("admission_rejected");
      }

      const command: GloryCrmExecutionCommand = Object.freeze({
        execution_id: record.execution_id,
        opportunity_id: record.target,
        discount_bps: record.requested_discount_bps,
        authorization_correlation_id: record.authorization_decision_id,
      });
      let downstreamResult: GloryCrmDispatchResult;
      try {
        downstreamResult = await input.downstream.applyDiscount(command);
      } catch {
        return indeterminatePass(proof);
      }
      if (!validDownstreamResult(downstreamResult, command)) {
        return indeterminatePass(proof);
      }
      return Object.freeze({
        guard_result: "PASS",
        proof_id: proof.proof_id,
        authorization_decision_id: record.authorization_decision_id,
        downstream_dispatched: true,
        downstream_outcome: downstreamResult.outcome,
        execution_evidence: snapshotEvidence(
          downstreamResult.execution_evidence
        ),
        determination: null,
      });
    },
  });
}
