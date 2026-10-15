import type { AuthorizationProof, AuthorizationProofIdentityPreimage, AuthorizationProofPayload, DelegationConstraints, EconomicScope, ExecutionScope, ProviderScope, ServiceScope, UsageLimit, } from "./contracts.js";

import { isISODateTime } from "./contracts.js";

import { createHash } from "node:crypto";

export const AUTHORIZATION_PROOF_PROTOCOL_VERSION = "v1";

export const AUTHORIZATION_PROOF_CANONICALIZATION_VERSION = "v1";

export const AUTHORIZATION_PROOF_IDENTITY_DOMAIN = "authorization-proof";

const AUTHORIZATION_PROOF_KEYS = ["proof_id", "payload", "signature"] as const;

const AUTHORIZATION_PROOF_PAYLOAD_REQUIRED_KEYS = [
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
] as const satisfies readonly (keyof AuthorizationProofPayload)[];

const AUTHORIZATION_PROOF_PAYLOAD_OPTIONAL_KEYS = [
    "delegator_id",
] as const satisfies readonly (keyof AuthorizationProofPayload)[];

const AUTHORIZATION_PROOF_PAYLOAD_KEYS = [
    ...AUTHORIZATION_PROOF_PAYLOAD_REQUIRED_KEYS,
    ...AUTHORIZATION_PROOF_PAYLOAD_OPTIONAL_KEYS,
] as const;

const EXACT_PROVIDER_SCOPE_KEYS = ["mode", "provider_id"] as const;

const PROVIDER_SCOPE_SHAPES = { exact: EXACT_PROVIDER_SCOPE_KEYS } as const;

const SERVICE_SCOPE_KEYS = ["service_id"] as const;

const EXACT_EXECUTION_SCOPE_KEYS = [
    "mode",
    "execution_id",
    "operation_type",
] as const;

const EXECUTION_SCOPE_SHAPES = { exact: EXACT_EXECUTION_SCOPE_KEYS } as const;

const SINGLE_USE_LIMIT_KEYS = ["mode", "maximum_usage_count"] as const;

const USAGE_LIMIT_SHAPES = { single_use: SINGLE_USE_LIMIT_KEYS } as const;

const NO_ECONOMIC_SCOPE_KEYS = ["mode"] as const;

const ECONOMIC_SCOPE_SHAPES = { none: NO_ECONOMIC_SCOPE_KEYS } as const;

const DELEGATION_CONSTRAINT_KEYS = ["delegation_mode"] as const;

function fail(field: string, reason: string): never {
    throw new Error(`authorization_proof_${field}_${reason}`);
}

function own(value: object, key: PropertyKey): boolean {
    return Object.prototype.hasOwnProperty.call(value, key);
}

function defineOwnDataProperty(target: object, key: string, value: unknown): void {
    const descriptor = Object.create(null) as PropertyDescriptor;
    descriptor.value = value;
    descriptor.enumerable = true;
    descriptor.writable = true;
    descriptor.configurable = true;
    Object.defineProperty(target, key, descriptor);
}

function assertObject(value: unknown, field: string): asserts value is Record<string, unknown> {
    if (value === null || typeof value !== "object" || Array.isArray(value))
        fail(field, "invalid");
}

function assertKeys(value: Record<string, unknown>, keys: readonly string[], field: string): void {
    const allowed = new Set(keys);
    for (const key of Object.keys(value))
        if (!allowed.has(key))
            fail(`${field}.${key}`, "unsupported");
}

function assertRequiredOwnKeys(value: Record<string, unknown>, keys: readonly string[], field: string): void {
    for (const key of keys) {
        if (!own(value, key))
            fail(field.length === 0 ? key : `${field}.${key}`, "required");
    }
}

function readRequiredOwn<Value extends object, Key extends keyof Value>(value: Value, key: Key, field: string): Value[Key] {
    if (!own(value, key))
        fail(field, "required");
    return value[key];
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
        defineOwnDataProperty(captured, key, descriptor.value);
    }
    return captured;
}

function captureExactPassiveData(value: unknown, requiredKeys: readonly string[], field: string, optionalKeys: readonly string[] = []): Record<string, unknown> {
    assertObject(value, field);
    return captureFromDescriptors(Object.getOwnPropertyDescriptors(value), requiredKeys, optionalKeys, field);
}

function captureDiscriminatedPassiveData(value: unknown, shapes: Readonly<Record<string, readonly string[]>>, field: string): Record<string, unknown> {
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

function captureProviderScopePassiveData(value: unknown): ProviderScope {
 const c = captureDiscriminatedPassiveData(value, PROVIDER_SCOPE_SHAPES, "payload.provider_scope");
 return { mode: "exact", provider_id: c.provider_id as string };
 }

function captureServiceScopePassiveData(value: unknown): ServiceScope {
    const captured = captureExactPassiveData(value, SERVICE_SCOPE_KEYS, "payload.service_scope");
    return { service_id: captured.service_id as ServiceScope["service_id"] };
}

function captureExecutionScopePassiveData(value: unknown): ExecutionScope {
 const c = captureDiscriminatedPassiveData(value, EXECUTION_SCOPE_SHAPES, "payload.execution_scope");
 return { mode: "exact", execution_id: c.execution_id as string, operation_type: c.operation_type as string };
 }

function captureUsagePassiveData(value: unknown): UsageLimit {
 const c = captureDiscriminatedPassiveData(value, USAGE_LIMIT_SHAPES, "payload.usage");
 return { mode: "single_use", maximum_usage_count: c.maximum_usage_count as 1 };
 }

function captureEconomicScopePassiveData(value: unknown): EconomicScope {
 captureDiscriminatedPassiveData(value, ECONOMIC_SCOPE_SHAPES, "payload.economic_scope");
 return { mode: "none" };
 }

function captureDelegationConstraintsPassiveData(value: unknown): DelegationConstraints {
    const captured = captureExactPassiveData(value, DELEGATION_CONSTRAINT_KEYS, "payload.delegation_constraints");
    return {
        delegation_mode: captured.delegation_mode as DelegationConstraints["delegation_mode"],
    };
}

function captureAuthorizationProofPayloadPassiveData(value: unknown): AuthorizationProofPayload {
    const captured = captureExactPassiveData(value, AUTHORIZATION_PROOF_PAYLOAD_REQUIRED_KEYS, "payload", AUTHORIZATION_PROOF_PAYLOAD_OPTIONAL_KEYS);
    const payload: AuthorizationProofPayload = {
        protocol_version: captured.protocol_version as string,
        canonicalization_version: captured.canonicalization_version as string,
        issuer_id: captured.issuer_id as AuthorizationProofPayload["issuer_id"],
        issuer_key_id: captured.issuer_key_id as string,
        principal_id: captured.principal_id as AuthorizationProofPayload["principal_id"],
        subject_agent_id: captured.subject_agent_id as AuthorizationProofPayload["subject_agent_id"],
        audience: captured.audience as string,
        runtime_id: captured.runtime_id as AuthorizationProofPayload["runtime_id"],
        provider_scope: captureProviderScopePassiveData(captured.provider_scope),
        service_scope: captureServiceScopePassiveData(captured.service_scope),
        execution_scope: captureExecutionScopePassiveData(captured.execution_scope),
        authorization_request_id: captured.authorization_request_id as AuthorizationProofPayload["authorization_request_id"],
        authorization_decision_id: captured.authorization_decision_id as AuthorizationProofPayload["authorization_decision_id"],
        policy_digest: captured.policy_digest as string,
        policy_epoch: captured.policy_epoch as number,
        issued_at: captured.issued_at as AuthorizationProofPayload["issued_at"],
        valid_from: captured.valid_from as AuthorizationProofPayload["valid_from"],
        expires_at: captured.expires_at as AuthorizationProofPayload["expires_at"],
        revocation_epoch: captured.revocation_epoch as number,
        usage: captureUsagePassiveData(captured.usage),
        economic_scope: captureEconomicScopePassiveData(captured.economic_scope),
        delegation_constraints: captureDelegationConstraintsPassiveData(captured.delegation_constraints),
        algorithm_id: captured.algorithm_id as string,
    };
    if (own(captured, "delegator_id")) {
        defineOwnDataProperty(payload, "delegator_id", captured.delegator_id);
    }
    return payload;
}

function captureAuthorizationProofPassiveData(value: unknown): AuthorizationProof {
    const captured = captureExactPassiveData(value, AUTHORIZATION_PROOF_KEYS, "proof");
    return {
        proof_id: captured.proof_id as AuthorizationProof["proof_id"],
        payload: captureAuthorizationProofPayloadPassiveData(captured.payload),
        signature: captured.signature as string,
    };
}

function assertUuid(value: unknown, field: string): asserts value is string {
    assertNonEmpty(value, field);
}

function assertNonEmpty(value: unknown, field: string): asserts value is string {
    if (typeof value !== "string" || value.trim().length === 0)
        fail(field, "required");
}

function assertWellFormedUnicodeString(value: string, field: string): void {
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        if (code >= 0xd800 && code <= 0xdbff) {
            const next = value.charCodeAt(index + 1);
            if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff)
                fail(field, "unicode_invalid");
            index += 1;
        }
        else if (code >= 0xdc00 && code <= 0xdfff) {
            fail(field, "unicode_invalid");
        }
    }
}

function assertIdentityUnicode(p: AuthorizationProofIdentityPreimage): void {
 const values = [p.protocol_version,p.canonicalization_version,p.issuer_id,p.issuer_key_id,p.principal_id,p.subject_agent_id,p.audience,p.runtime_id,p.provider_scope.provider_id,p.service_scope.service_id,p.execution_scope.execution_id,p.execution_scope.operation_type,p.authorization_request_id,p.authorization_decision_id,p.policy_digest,p.issued_at,p.valid_from,p.expires_at,p.algorithm_id];
 if (own(p,"delegator_id")) values.push(p.delegator_id as string);
 for (const value of values) assertWellFormedUnicodeString(value,"identity");
 }

function assertInteger(value: unknown, field: string, minimum: number): asserts value is number {
    if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum)
        fail(field, "invalid");
}

function assertTimestamp(value: unknown, field: string): asserts value is string {
    if (typeof value !== "string" || !isISODateTime(value))
        fail(field, "invalid");
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(value);
    if (!match)
        fail(field, "invalid");
    const year = decimalDigits(match[1]);
    const month = decimalDigits(match[2]);
    const day = decimalDigits(match[3]);
    const hour = decimalDigits(match[4]);
    const minute = decimalDigits(match[5]);
    const second = decimalDigits(match[6]);
    const daysInMonth = [31, (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
    if (!daysInMonth || day < 1 || day > daysInMonth || hour > 23 || minute > 59 || second > 59)
        fail(field, "invalid");
}

function decimalDigits(value: string): number {
    let result = 0;
    for (const character of value)
        result = result * 10 + character.charCodeAt(0) - 48;
    return result;
}

function timestampValue(value: string): number {
    const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(value);
    if (!match)
        fail("timestamp", "invalid");
    return (((((decimalDigits(match[1]) * 13 + decimalDigits(match[2])) * 32 + decimalDigits(match[3])) * 24 + decimalDigits(match[4])) * 60 + decimalDigits(match[5])) * 60 + decimalDigits(match[6])) * 1000 + decimalDigits((match[7] ?? "").padEnd(3, "0"));
}

function canonicalTimestamp(value: string): string {
    if (!isISODateTime(value))
        fail("timestamp", "invalid");
    return new Date(value).toISOString();
}

type AuthorizationProofCanonicalTuple = [
    string,
    string,
    string,
    string,
    string,
    string,
    string | null,
    string,
    string,
    unknown[],
    unknown[],
    unknown[],
    string,
    string,
    string,
    number,
    string,
    string,
    string,
    number,
    unknown[],
    unknown[],
    unknown[],
    string
];

function canonicalTuple(payload: AuthorizationProofPayload): AuthorizationProofCanonicalTuple {
 const p = createAuthorizationProofIdentityPreimage(payload); assertIdentityUnicode(p);
 return [p.protocol_version,p.canonicalization_version,p.issuer_id,p.issuer_key_id,p.principal_id,p.subject_agent_id,own(p,"delegator_id") ? p.delegator_id as string : null,p.audience,p.runtime_id,["exact",p.provider_scope.provider_id],["service_id",p.service_scope.service_id],["exact",p.execution_scope.execution_id,p.execution_scope.operation_type],p.authorization_request_id,p.authorization_decision_id,p.policy_digest,p.policy_epoch,canonicalTimestamp(p.issued_at),canonicalTimestamp(p.valid_from),canonicalTimestamp(p.expires_at),p.revocation_epoch,["single_use",1],["none"],[p.delegation_constraints.delegation_mode],p.algorithm_id];
 }

export function canonicalizeAuthorizationProofIdentity(payload: AuthorizationProofPayload): string {
    const serialized = JSON.stringify(canonicalTuple(payload));
    if (typeof serialized !== "string")
        fail("canonicalization", "failed");
    return serialized;
}

export function encodeAuthorizationProofIdentity(payload: AuthorizationProofPayload): Uint8Array {
    return new Uint8Array(Buffer.from(canonicalizeAuthorizationProofIdentity(payload), "utf8"));
}

export function deriveAuthorizationProofId(payload: AuthorizationProofPayload): string {
    const domain = `${AUTHORIZATION_PROOF_IDENTITY_DOMAIN}:`;
    const input = Buffer.concat([Buffer.from(domain, "utf8"), Buffer.from(encodeAuthorizationProofIdentity(payload))]);
    const digest = createHash("sha256").update(input).digest("base64url");
    return `${domain}${digest}`;
}

function validateProviderScope(v: ProviderScope): void {
 assertObject(v,"provider_scope"); assertKeys(v,EXACT_PROVIDER_SCOPE_KEYS,"provider_scope"); assertRequiredOwnKeys(v,EXACT_PROVIDER_SCOPE_KEYS,"provider_scope");
 if(v.mode!=="exact") fail("provider_scope.mode","invalid"); assertUuid(v.provider_id,"provider_scope.provider_id");
 }

function validateServiceScope(value: ServiceScope): void {
    assertObject(value, "service_scope");
    assertKeys(value, SERVICE_SCOPE_KEYS, "service_scope");
    assertRequiredOwnKeys(value, SERVICE_SCOPE_KEYS, "service_scope");
    assertUuid(readRequiredOwn(value, "service_id", "service_scope.service_id"), "service_scope.service_id");
}

function validateExecutionScope(v: ExecutionScope): void {
 assertObject(v,"execution_scope"); assertKeys(v,EXACT_EXECUTION_SCOPE_KEYS,"execution_scope"); assertRequiredOwnKeys(v,EXACT_EXECUTION_SCOPE_KEYS,"execution_scope");
 if(v.mode!=="exact") fail("execution_scope.mode","invalid"); assertUuid(v.execution_id,"execution_scope.execution_id"); assertNonEmpty(v.operation_type,"execution_scope.operation_type");
 }

function validateUsage(v: UsageLimit): void {
 assertObject(v,"usage"); assertKeys(v,SINGLE_USE_LIMIT_KEYS,"usage"); assertRequiredOwnKeys(v,SINGLE_USE_LIMIT_KEYS,"usage");
 if(v.mode!=="single_use"||v.maximum_usage_count!==1) fail("usage","invalid");
 }

function validateEconomicScope(v: EconomicScope): void {
 assertObject(v,"economic_scope"); assertKeys(v,NO_ECONOMIC_SCOPE_KEYS,"economic_scope"); assertRequiredOwnKeys(v,NO_ECONOMIC_SCOPE_KEYS,"economic_scope");
 if(v.mode!=="none") fail("economic_scope.mode","invalid");
 }

function validateDelegation(value: DelegationConstraints, hasDelegator: boolean, delegatorId: unknown): void {
    assertObject(value, "delegation_constraints");
    assertKeys(value, DELEGATION_CONSTRAINT_KEYS, "delegation_constraints");
    assertRequiredOwnKeys(value, DELEGATION_CONSTRAINT_KEYS, "delegation_constraints");
    const mode = readRequiredOwn(value, "delegation_mode", "delegation_constraints.delegation_mode");
    if (mode === "direct") {
        if (hasDelegator)
            fail("delegator_id", "unsupported_for_direct");
        return;
    }
    if (mode === "delegated") {
        assertUuid(delegatorId, "delegator_id");
        return;
    }
    fail("delegation_constraints.delegation_mode", "invalid");
}

function validateOwnedAuthorizationProofPayload(payload: AuthorizationProofPayload): void {
    assertObject(payload, "payload");
    assertKeys(payload, AUTHORIZATION_PROOF_PAYLOAD_KEYS, "payload");
    assertRequiredOwnKeys(payload, AUTHORIZATION_PROOF_PAYLOAD_REQUIRED_KEYS, "");
    const protocolVersion = readRequiredOwn(payload, "protocol_version", "protocol_version");
    const canonicalizationVersion = readRequiredOwn(payload, "canonicalization_version", "canonicalization_version");
    const issuerId = readRequiredOwn(payload, "issuer_id", "issuer_id");
    const issuerKeyId = readRequiredOwn(payload, "issuer_key_id", "issuer_key_id");
    const principalId = readRequiredOwn(payload, "principal_id", "principal_id");
    const subjectAgentId = readRequiredOwn(payload, "subject_agent_id", "subject_agent_id");
    const audience = readRequiredOwn(payload, "audience", "audience");
    const runtimeId = readRequiredOwn(payload, "runtime_id", "runtime_id");
    const providerScope = readRequiredOwn(payload, "provider_scope", "provider_scope");
    const serviceScope = readRequiredOwn(payload, "service_scope", "service_scope");
    const executionScope = readRequiredOwn(payload, "execution_scope", "execution_scope");
    const authorizationRequestId = readRequiredOwn(payload, "authorization_request_id", "authorization_request_id");
    const authorizationDecisionId = readRequiredOwn(payload, "authorization_decision_id", "authorization_decision_id");
    const policyDigest = readRequiredOwn(payload, "policy_digest", "policy_digest");
    const policyEpoch = readRequiredOwn(payload, "policy_epoch", "policy_epoch");
    const issuedAt = readRequiredOwn(payload, "issued_at", "issued_at");
    const validFrom = readRequiredOwn(payload, "valid_from", "valid_from");
    const expiresAt = readRequiredOwn(payload, "expires_at", "expires_at");
    const revocationEpoch = readRequiredOwn(payload, "revocation_epoch", "revocation_epoch");
    const usage = readRequiredOwn(payload, "usage", "usage");
    const economicScope = readRequiredOwn(payload, "economic_scope", "economic_scope");
    const delegationConstraints = readRequiredOwn(payload, "delegation_constraints", "delegation_constraints");
    const algorithmId = readRequiredOwn(payload, "algorithm_id", "algorithm_id");
    if (protocolVersion !== AUTHORIZATION_PROOF_PROTOCOL_VERSION)
        fail("protocol_version", "unsupported");
    if (canonicalizationVersion !== AUTHORIZATION_PROOF_CANONICALIZATION_VERSION)
        fail("canonicalization_version", "unsupported");
    assertUuid(issuerId, "issuer_id");
    assertNonEmpty(issuerKeyId, "issuer_key_id");
    assertUuid(principalId, "principal_id");
    assertUuid(subjectAgentId, "subject_agent_id");
    const hasDelegator = own(payload, "delegator_id");
    const delegatorId = hasDelegator ? payload.delegator_id : undefined;
    if (hasDelegator && delegatorId !== undefined)
        assertUuid(delegatorId, "delegator_id");
    assertNonEmpty(audience, "audience");
    assertUuid(runtimeId, "runtime_id");
    validateProviderScope(providerScope);
    validateServiceScope(serviceScope);
    validateExecutionScope(executionScope);
    assertUuid(authorizationRequestId, "authorization_request_id");
    assertUuid(authorizationDecisionId, "authorization_decision_id");
    assertNonEmpty(policyDigest, "policy_digest");
    assertInteger(policyEpoch, "policy_epoch", 0);
    assertTimestamp(issuedAt, "issued_at");
    assertTimestamp(validFrom, "valid_from");
    assertTimestamp(expiresAt, "expires_at");
    if (timestampValue(issuedAt) > timestampValue(validFrom))
        fail("validity", "ordering");
    if (timestampValue(validFrom) >= timestampValue(expiresAt))
        fail("validity", "ordering");
    assertInteger(revocationEpoch, "revocation_epoch", 0);
    validateUsage(usage);
    validateEconomicScope(economicScope);
    validateDelegation(delegationConstraints, hasDelegator, delegatorId);
    assertNonEmpty(algorithmId, "algorithm_id");
}

function captureAndValidateAuthorizationProofPayload(payload: AuthorizationProofPayload): AuthorizationProofPayload {
    const owned = captureAuthorizationProofPayloadPassiveData(payload);
    validateOwnedAuthorizationProofPayload(owned);
    return owned;
}

export function validateAuthorizationProofPayload(payload: AuthorizationProofPayload): void {
    captureAndValidateAuthorizationProofPayload(payload);
}

function snapshotProviderScope(v: ProviderScope): ProviderScope { return { mode: "exact", provider_id: v.provider_id }; }

function snapshotExecutionScope(v: ExecutionScope): ExecutionScope { return { mode: "exact", execution_id: v.execution_id, operation_type: v.operation_type }; }

function snapshotUsage(v: UsageLimit): UsageLimit { return { mode: "single_use", maximum_usage_count: v.maximum_usage_count }; }

function snapshotEconomicScope(v: EconomicScope): EconomicScope { return { mode: "none" }; }

export function snapshotAuthorizationProofPayload(payload: AuthorizationProofPayload): AuthorizationProofPayload {
    return captureAndValidateAuthorizationProofPayload(payload);
}

export function createAuthorizationProofIdentityPreimage(payload: AuthorizationProofPayload): AuthorizationProofIdentityPreimage {
    const snapshot = snapshotAuthorizationProofPayload(payload);
    const preimage: AuthorizationProofIdentityPreimage = {
        protocol_version: snapshot.protocol_version,
        canonicalization_version: snapshot.canonicalization_version,
        issuer_id: snapshot.issuer_id,
        issuer_key_id: snapshot.issuer_key_id,
        principal_id: snapshot.principal_id,
        subject_agent_id: snapshot.subject_agent_id,
        audience: snapshot.audience,
        runtime_id: snapshot.runtime_id,
        provider_scope: snapshotProviderScope(snapshot.provider_scope),
        service_scope: { service_id: snapshot.service_scope.service_id },
        execution_scope: snapshotExecutionScope(snapshot.execution_scope),
        authorization_request_id: snapshot.authorization_request_id,
        authorization_decision_id: snapshot.authorization_decision_id,
        policy_digest: snapshot.policy_digest,
        policy_epoch: snapshot.policy_epoch,
        issued_at: snapshot.issued_at,
        valid_from: snapshot.valid_from,
        expires_at: snapshot.expires_at,
        revocation_epoch: snapshot.revocation_epoch,
        usage: snapshotUsage(snapshot.usage),
        economic_scope: snapshotEconomicScope(snapshot.economic_scope),
        delegation_constraints: { delegation_mode: snapshot.delegation_constraints.delegation_mode },
        algorithm_id: snapshot.algorithm_id,
    };
    if (own(snapshot, "delegator_id")) {
        defineOwnDataProperty(preimage, "delegator_id", snapshot.delegator_id);
    }
    return preimage;
}

function validateOwnedAuthorizationProof(proof: AuthorizationProof): void {
    assertUuid(proof.proof_id, "proof_id");
    assertNonEmpty(proof.signature, "signature");
    validateOwnedAuthorizationProofPayload(proof.payload);
}

function captureAndValidateAuthorizationProof(proof: AuthorizationProof): AuthorizationProof {
    const owned = captureAuthorizationProofPassiveData(proof);
    validateOwnedAuthorizationProof(owned);
    return owned;
}

export function validateAuthorizationProof(proof: AuthorizationProof): void {
    captureAndValidateAuthorizationProof(proof);
}

export function snapshotAuthorizationProof(proof: AuthorizationProof): AuthorizationProof {
    return captureAndValidateAuthorizationProof(proof);
}
