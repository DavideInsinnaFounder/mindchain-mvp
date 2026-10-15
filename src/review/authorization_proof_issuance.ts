import type { AuthorizationProof, AuthorizationProofPayload, UUID, } from "./contracts.js";

import { deriveAuthorizationProofId, snapshotAuthorizationProof, snapshotAuthorizationProofPayload, validateAuthorizationProof, } from "./authorization_proof.js";

export interface AuthorizationDecisionProvenanceAssertion {
    authorization_request_id: UUID;
    authorization_decision_id: UUID;
    policy_digest: string;
    policy_epoch: number;
}

export interface CreateAuthorizationProofEnvelopeInput {
    payload: AuthorizationProofPayload;
    decision_provenance: AuthorizationDecisionProvenanceAssertion;
    signature: string;
}

function fail(field: string, reason: string): never {
    throw new Error(`authorization_proof_issuance_${field}_${reason}`);
}

function assertObject(value: unknown, field: string): asserts value is Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        fail(field, "invalid");
    }
}

function captureExactDataProperties(value: Record<string, unknown>, keys: readonly string[], field: string): Record<string, unknown> {
    const descriptors = Object.getOwnPropertyDescriptors(value);
    for (const key of Reflect.ownKeys(descriptors)) {
        if (typeof key !== "string")
            fail(field, "symbol_unsupported");
        if (!keys.includes(key))
            fail(`${field}.${key}`, "unsupported");
    }
    const captured = Object.create(null) as Record<string, unknown>;
    for (const key of keys) {
        if (!Object.prototype.hasOwnProperty.call(descriptors, key)) {
            fail(`${field}.${key}`, "required");
        }
        const descriptor = descriptors[key];
        if (!Object.prototype.hasOwnProperty.call(descriptor, "value") ||
            Object.prototype.hasOwnProperty.call(descriptor, "get") ||
            Object.prototype.hasOwnProperty.call(descriptor, "set")) {
            fail(`${field}.${key}`, "accessor_unsupported");
        }
        captured[key] = descriptor.value;
    }
    return captured;
}

function assertNonEmptyString(value: unknown, field: string): asserts value is string {
    if (typeof value !== "string" || value.trim().length === 0) {
        fail(field, "invalid");
    }
}

function assertPolicyEpoch(value: unknown): asserts value is number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
        fail("decision_provenance.policy_epoch", "invalid");
    }
}

function snapshotDecisionProvenance(value: unknown): AuthorizationDecisionProvenanceAssertion {
    assertObject(value, "decision_provenance");
    const captured = captureExactDataProperties(value, [
        "authorization_request_id",
        "authorization_decision_id",
        "policy_digest",
        "policy_epoch",
    ], "decision_provenance");
    const snapshot: AuthorizationDecisionProvenanceAssertion = {
        authorization_request_id: captured.authorization_request_id as UUID,
        authorization_decision_id: captured.authorization_decision_id as UUID,
        policy_digest: captured.policy_digest as string,
        policy_epoch: captured.policy_epoch as number,
    };
    assertNonEmptyString(snapshot.authorization_request_id, "decision_provenance.authorization_request_id");
    assertNonEmptyString(snapshot.authorization_decision_id, "decision_provenance.authorization_decision_id");
    assertNonEmptyString(snapshot.policy_digest, "decision_provenance.policy_digest");
    assertPolicyEpoch(snapshot.policy_epoch);
    return snapshot;
}

function assertProvenanceMatches(payload: AuthorizationProofPayload, assertion: AuthorizationDecisionProvenanceAssertion): void {
    if (assertion.authorization_request_id !== payload.authorization_request_id ||
        assertion.authorization_decision_id !== payload.authorization_decision_id ||
        assertion.policy_digest !== payload.policy_digest ||
        assertion.policy_epoch !== payload.policy_epoch) {
        fail("decision_provenance", "mismatch");
    }
}

export function createAuthorizationProofEnvelope(input: CreateAuthorizationProofEnvelopeInput): AuthorizationProof {
    assertObject(input, "input");
    const captured = captureExactDataProperties(input, ["payload", "decision_provenance", "signature"], "input");
    const payload = snapshotAuthorizationProofPayload(captured.payload as AuthorizationProofPayload);
    const decisionProvenance = snapshotDecisionProvenance(captured.decision_provenance);
    assertProvenanceMatches(payload, decisionProvenance);
    const signature = captured.signature;
    assertNonEmptyString(signature, "signature");
    const proof: AuthorizationProof = {
        proof_id: deriveAuthorizationProofId(payload),
        payload,
        signature,
    };
    validateAuthorizationProof(proof);
    return snapshotAuthorizationProof(proof);
}
