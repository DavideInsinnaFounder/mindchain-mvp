import { createPublicKey, verify as verifyEd25519 } from "node:crypto";

import type { AuthorizationProof, AuthorizationProofPayload, DelegationConstraints, EconomicScope, ExecutionScope, ProviderScope, ServiceScope, UsageLimit, UUID, } from "./contracts.js";

import { deriveAuthorizationProofId, encodeAuthorizationProofIdentity, snapshotAuthorizationProof, snapshotAuthorizationProofPayload, } from "./authorization_proof.js";

export const LOCAL_AUTHORIZATION_PROOF_ALGORITHM_ID = "ed25519";

export const AUTHORIZATION_PROOF_SIGNATURE_MESSAGE_DOMAIN = "authorization-proof:signature:v1:";

const MAX_ED25519_SPKI_BASE64URL_LENGTH = 128;

const MAX_ED25519_SIGNATURE_BASE64URL_LENGTH = 128;

const ED25519_SIGNATURE_BYTE_LENGTH = 64;

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]+$/;

export interface SuppliedLocalAuthorizationProofVerificationMaterial {
    algorithm_id: string;
    issuer_key_id: string;
    public_key_spki_der_base64url: string;
}

export interface VerifyAuthorizationProofLocallyInput {
    proof: AuthorizationProof;
    verification_material: SuppliedLocalAuthorizationProofVerificationMaterial;
}

export type LocalAuthorizationProofVerificationFailureReason = "structural_invalid" | "proof_id_mismatch" | "unsupported_algorithm" | "verification_material_mismatch" | "invalid_verification_material" | "invalid_signature";

export type LocalAuthorizationProofVerificationResult = {
    verification: "verified_locally";
    proof_id: UUID;
} | {
    verification: "not_verified";
    reason: LocalAuthorizationProofVerificationFailureReason;
};

class StructuralInputError extends Error {
}

function fail(field: string, reason: string): never {
    throw new StructuralInputError(`authorization_proof_verification_${field}_${reason}`);
}

function assertObject(value: unknown, field: string): asserts value is Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value)) {
        fail(field, "invalid");
    }
}

function own(value: object, key: PropertyKey): boolean {
    return Object.prototype.hasOwnProperty.call(value, key);
}

function captureFromDescriptors(descriptors: PropertyDescriptorMap, requiredKeys: readonly string[], optionalKeys: readonly string[], field: string): Record<string, unknown> {
    const supportedKeys = [...requiredKeys, ...optionalKeys];
    for (const key of Reflect.ownKeys(descriptors)) {
        if (typeof key !== "string")
            fail(field, "symbol_unsupported");
        if (!supportedKeys.includes(key))
            fail(`${field}.${key}`, "unsupported");
    }
    const captured = Object.create(null) as Record<string, unknown>;
    for (const key of supportedKeys) {
        if (!own(descriptors, key)) {
            if (requiredKeys.includes(key))
                fail(`${field}.${key}`, "required");
            continue;
        }
        const descriptor = descriptors[key];
        if (!own(descriptor, "value") ||
            own(descriptor, "get") ||
            own(descriptor, "set")) {
            fail(`${field}.${key}`, "accessor_unsupported");
        }
        captured[key] = descriptor.value;
    }
    return captured;
}

function captureExactDataProperties(value: unknown, requiredKeys: readonly string[], field: string, optionalKeys: readonly string[] = []): Record<string, unknown> {
    assertObject(value, field);
    return captureFromDescriptors(Object.getOwnPropertyDescriptors(value), requiredKeys, optionalKeys, field);
}

function captureDiscriminatedDataProperties(value: unknown, shapes: Readonly<Record<string, readonly string[]>>, field: string): Record<string, unknown> {
    assertObject(value, field);
    const descriptors = Object.getOwnPropertyDescriptors(value);
    if (!own(descriptors, "mode"))
        fail(`${field}.mode`, "required");
    const modeDescriptor = descriptors.mode;
    if (!own(modeDescriptor, "value") ||
        own(modeDescriptor, "get") ||
        own(modeDescriptor, "set")) {
        fail(`${field}.mode`, "accessor_unsupported");
    }
    const mode = modeDescriptor.value;
    if (typeof mode !== "string" || !own(shapes, mode)) {
        fail(`${field}.mode`, "invalid");
    }
    return captureFromDescriptors(descriptors, shapes[mode], [], field);
}

function snapshotPassiveProviderScope(v: unknown): ProviderScope { const c=captureDiscriminatedDataProperties(v,{exact:["mode","provider_id"]},"proof.payload.provider_scope"); return {mode:"exact",provider_id:c.provider_id as string}; }

function snapshotPassiveServiceScope(value: unknown): ServiceScope {
    const captured = captureExactDataProperties(value, ["service_id"], "proof.payload.service_scope");
    return { service_id: captured.service_id as UUID };
}

function snapshotPassiveExecutionScope(v: unknown): ExecutionScope { const c=captureDiscriminatedDataProperties(v,{exact:["mode","execution_id","operation_type"]},"proof.payload.execution_scope"); return {mode:"exact",execution_id:c.execution_id as string,operation_type:c.operation_type as string}; }

function snapshotPassiveUsage(v: unknown): UsageLimit { const c=captureDiscriminatedDataProperties(v,{single_use:["mode","maximum_usage_count"]},"proof.payload.usage"); return {mode:"single_use",maximum_usage_count:c.maximum_usage_count as 1}; }

function snapshotPassiveEconomicScope(v: unknown): EconomicScope { captureDiscriminatedDataProperties(v,{none:["mode"]},"proof.payload.economic_scope"); return {mode:"none"}; }

function snapshotPassiveDelegationConstraints(value: unknown): DelegationConstraints {
    const captured = captureExactDataProperties(value, ["delegation_mode"], "proof.payload.delegation_constraints");
    return {
        delegation_mode: captured.delegation_mode as "direct" | "delegated",
    };
}

function snapshotPassivePayload(value: unknown): AuthorizationProofPayload {
    const captured = captureExactDataProperties(value, [
        "protocol_version",
        "canonicalization_version",
        "issuer_id",
        "issuer_key_id",
        "principal_id",
        "subject_agent_id",
        "audience",
        "runtime_id",
        "provider_scope",
        "service_scope",
        "execution_scope",
        "authorization_request_id",
        "authorization_decision_id",
        "policy_digest",
        "policy_epoch",
        "issued_at",
        "valid_from",
        "expires_at",
        "revocation_epoch",
        "usage",
        "economic_scope",
        "delegation_constraints",
        "algorithm_id",
    ], "proof.payload", ["delegator_id"]);
    const payload: AuthorizationProofPayload = {
        protocol_version: captured.protocol_version as string,
        canonicalization_version: captured.canonicalization_version as string,
        issuer_id: captured.issuer_id as UUID,
        issuer_key_id: captured.issuer_key_id as string,
        principal_id: captured.principal_id as UUID,
        subject_agent_id: captured.subject_agent_id as UUID,
        audience: captured.audience as string,
        runtime_id: captured.runtime_id as UUID,
        provider_scope: snapshotPassiveProviderScope(captured.provider_scope),
        service_scope: snapshotPassiveServiceScope(captured.service_scope),
        execution_scope: snapshotPassiveExecutionScope(captured.execution_scope),
        authorization_request_id: captured.authorization_request_id as UUID,
        authorization_decision_id: captured.authorization_decision_id as UUID,
        policy_digest: captured.policy_digest as string,
        policy_epoch: captured.policy_epoch as number,
        issued_at: captured.issued_at as string,
        valid_from: captured.valid_from as string,
        expires_at: captured.expires_at as string,
        revocation_epoch: captured.revocation_epoch as number,
        usage: snapshotPassiveUsage(captured.usage),
        economic_scope: snapshotPassiveEconomicScope(captured.economic_scope),
        delegation_constraints: snapshotPassiveDelegationConstraints(captured.delegation_constraints),
        algorithm_id: captured.algorithm_id as string,
    };
    if (own(captured, "delegator_id")) {
        payload.delegator_id = captured.delegator_id as UUID;
    }
    return snapshotAuthorizationProofPayload(payload);
}

function snapshotPassiveProof(value: unknown): AuthorizationProof {
    const captured = captureExactDataProperties(value, ["proof_id", "payload", "signature"], "proof");
    const payload = snapshotPassivePayload(captured.payload);
    return snapshotAuthorizationProof({
        proof_id: captured.proof_id as UUID,
        payload,
        signature: captured.signature as string,
    });
}

function snapshotPassiveVerificationMaterial(value: unknown): SuppliedLocalAuthorizationProofVerificationMaterial {
    const captured = captureExactDataProperties(value, ["algorithm_id", "issuer_key_id", "public_key_spki_der_base64url"], "verification_material");
    for (const key of [
        "algorithm_id",
        "issuer_key_id",
        "public_key_spki_der_base64url",
    ] as const) {
        const fieldValue = captured[key];
        if (typeof fieldValue !== "string" || fieldValue.trim().length === 0) {
            fail(`verification_material.${key}`, "invalid");
        }
    }
    return {
        algorithm_id: captured.algorithm_id as string,
        issuer_key_id: captured.issuer_key_id as string,
        public_key_spki_der_base64url: captured.public_key_spki_der_base64url as string,
    };
}

function decodeCanonicalBase64Url(value: string, maximumEncodedLength: number): Buffer | undefined {
    if (value.length === 0 ||
        value.length > maximumEncodedLength ||
        !BASE64URL_PATTERN.test(value)) {
        return undefined;
    }
    const decoded = Buffer.from(value, "base64url");
    return decoded.toString("base64url") === value ? decoded : undefined;
}

function parseCanonicalEd25519PublicKey(value: string) {
    const der = decodeCanonicalBase64Url(value, MAX_ED25519_SPKI_BASE64URL_LENGTH);
    if (der === undefined)
        return undefined;
    try {
        const key = createPublicKey({ key: der, format: "der", type: "spki" });
        if (key.asymmetricKeyType !== "ed25519")
            return undefined;
        const canonicalDer = key.export({ format: "der", type: "spki" });
        if (!Buffer.isBuffer(canonicalDer) || !canonicalDer.equals(der)) {
            return undefined;
        }
        return key;
    }
    catch {
        return undefined;
    }
}

function createSignatureMessage(payload: AuthorizationProofPayload): Buffer {
    return Buffer.concat([
        Buffer.from(AUTHORIZATION_PROOF_SIGNATURE_MESSAGE_DOMAIN, "utf8"),
        Buffer.from(encodeAuthorizationProofIdentity(payload)),
    ]);
}

function deriveOwnedProofId(payload: AuthorizationProofPayload): string | undefined {
    try {
        return deriveAuthorizationProofId(payload);
    }
    catch (error) {
        if (error instanceof Error &&
            error.message.startsWith("authorization_proof_")) {
            return undefined;
        }
        throw error;
    }
}

function structuralFailure(operation: () => {
    proof: AuthorizationProof;
    material: SuppliedLocalAuthorizationProofVerificationMaterial;
}): {
    proof: AuthorizationProof;
    material: SuppliedLocalAuthorizationProofVerificationMaterial;
} | undefined {
    try {
        return operation();
    }
    catch (error) {
        if (error instanceof StructuralInputError ||
            (error instanceof Error &&
                error.message.startsWith("authorization_proof_"))) {
            return undefined;
        }
        throw error;
    }
}

export function verifyAuthorizationProofLocally(input: VerifyAuthorizationProofLocallyInput): LocalAuthorizationProofVerificationResult {
    const owned = structuralFailure(() => {
        const capturedInput = captureExactDataProperties(input, ["proof", "verification_material"], "input");
        const proof = snapshotPassiveProof(capturedInput.proof);
        const material = snapshotPassiveVerificationMaterial(capturedInput.verification_material);
        return { proof, material };
    });
    if (owned === undefined) {
        return { verification: "not_verified", reason: "structural_invalid" };
    }
    const expectedProofId = deriveOwnedProofId(owned.proof.payload);
    if (expectedProofId === undefined) {
        return { verification: "not_verified", reason: "structural_invalid" };
    }
    if (expectedProofId !== owned.proof.proof_id) {
        return { verification: "not_verified", reason: "proof_id_mismatch" };
    }
    if (owned.proof.payload.algorithm_id !== LOCAL_AUTHORIZATION_PROOF_ALGORITHM_ID) {
        return { verification: "not_verified", reason: "unsupported_algorithm" };
    }
    if (owned.material.algorithm_id !== owned.proof.payload.algorithm_id ||
        owned.material.issuer_key_id !== owned.proof.payload.issuer_key_id) {
        return {
            verification: "not_verified",
            reason: "verification_material_mismatch",
        };
    }
    const key = parseCanonicalEd25519PublicKey(owned.material.public_key_spki_der_base64url);
    if (key === undefined) {
        return {
            verification: "not_verified",
            reason: "invalid_verification_material",
        };
    }
    const signature = decodeCanonicalBase64Url(owned.proof.signature, MAX_ED25519_SIGNATURE_BASE64URL_LENGTH);
    if (signature === undefined ||
        signature.byteLength !== ED25519_SIGNATURE_BYTE_LENGTH) {
        return { verification: "not_verified", reason: "invalid_signature" };
    }
    const signatureValid = verifyEd25519(null, createSignatureMessage(owned.proof.payload), key, signature);
    return signatureValid
        ? { verification: "verified_locally", proof_id: owned.proof.proof_id }
        : { verification: "not_verified", reason: "invalid_signature" };
}
