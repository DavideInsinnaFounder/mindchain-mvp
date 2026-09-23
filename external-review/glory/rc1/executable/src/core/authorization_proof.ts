import type {
  AuthorizationProof,
  AuthorizationProofIdentityPreimage,
  AuthorizationProofPayload,
  DelegationConstraints,
  EconomicScope,
  ExecutionScope,
  ProviderScope,
  ServiceScope,
  UsageLimit,
} from "./contracts.js";
import { isISODateTime } from "./contracts.js";
import { createHash } from "node:crypto";

/**
 * Day 67 is a structural contract boundary only. These validators perform no
 * provider, policy, revocation, issuer-trust, cryptographic, storage, or
 * runtime-admission work. Canonical bytes and identity derivation are Day 68.
 */
export const AUTHORIZATION_PROOF_PROTOCOL_VERSION = "v1";
export const AUTHORIZATION_PROOF_CANONICALIZATION_VERSION = "v1";
// Authorization semantic changes require protocol-version review; representation,
// field-order, hash, or output-format changes require canonicalization-version review.
// algorithm_id identifies future signatures and never selects proof-ID hashing.
export const AUTHORIZATION_PROOF_IDENTITY_DOMAIN = "authorization-proof";

const AMOUNT_PATTERN = /^[1-9][0-9]*$/;

type ExactKeyInventory<
  Value,
  Inventory extends readonly PropertyKey[],
> = Exclude<keyof Value, Inventory[number]> extends never
  ? Exclude<Inventory[number], keyof Value> extends never
    ? true
    : never
  : never;

type OptionalKeys<Value> = {
  [Key in keyof Value]-?: object extends Pick<Value, Key> ? Key : never;
}[keyof Value];

type AssociationIsValid<Association> = [Association] extends [never]
  ? false
  : [Association] extends [true]
    ? true
    : false;

type KeyedDiscriminantShapeAssociations<
  Union,
  Discriminant extends keyof Union,
  Shapes extends {
    readonly [Mode in Union[Discriminant] & PropertyKey]: readonly PropertyKey[];
  },
> = {
  readonly [Mode in Union[Discriminant] & PropertyKey]: AssociationIsValid<
    ExactKeyInventory<
      Extract<Union, Record<Discriminant, Mode>>,
      Shapes[Mode]
    >
  >;
};

type AssertAllAssociationsTrue<
  Associations extends {
    readonly [Mode in keyof Associations]: true;
  },
> = Associations;

type AssertAllTrue<Checks extends readonly true[]> = Checks;

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

type AnyProviderScope = Extract<ProviderScope, { mode: "any_authorized" }>;
type ExactProviderScope = Extract<ProviderScope, { mode: "exact" }>;
const ANY_PROVIDER_SCOPE_KEYS = ["mode"] as const;
const EXACT_PROVIDER_SCOPE_KEYS = ["mode", "provider_id"] as const;
const PROVIDER_SCOPE_SHAPES = {
  any_authorized: ANY_PROVIDER_SCOPE_KEYS,
  exact: EXACT_PROVIDER_SCOPE_KEYS,
} as const satisfies Record<ProviderScope["mode"], readonly string[]>;
type ProviderScopeShapeAssociationsChecked = AssertAllAssociationsTrue<
  KeyedDiscriminantShapeAssociations<
    ProviderScope,
    "mode",
    typeof PROVIDER_SCOPE_SHAPES
  >
>;

const SERVICE_SCOPE_KEYS = ["service_id"] as const;

type ExactExecutionScope = Extract<ExecutionScope, { mode: "exact" }>;
type BoundedExecutionScope = Extract<ExecutionScope, { mode: "bounded" }>;
const EXACT_EXECUTION_SCOPE_KEYS = [
  "mode",
  "execution_id",
  "operation_type",
] as const;
const BOUNDED_EXECUTION_SCOPE_KEYS = [
  "mode",
  "operation_type",
  "capability_id",
  "maximum_operations",
] as const;
const EXECUTION_SCOPE_SHAPES = {
  exact: EXACT_EXECUTION_SCOPE_KEYS,
  bounded: BOUNDED_EXECUTION_SCOPE_KEYS,
} as const satisfies Record<ExecutionScope["mode"], readonly string[]>;
type ExecutionScopeShapeAssociationsChecked = AssertAllAssociationsTrue<
  KeyedDiscriminantShapeAssociations<
    ExecutionScope,
    "mode",
    typeof EXECUTION_SCOPE_SHAPES
  >
>;

type SingleUseLimit = Extract<UsageLimit, { mode: "single_use" }>;
type BoundedUsageLimit = Extract<UsageLimit, { mode: "bounded" }>;
const SINGLE_USE_LIMIT_KEYS = ["mode", "maximum_usage_count"] as const;
const BOUNDED_USAGE_LIMIT_KEYS = [
  "mode",
  "maximum_usage_count",
  "sequence_mode",
] as const;
const USAGE_LIMIT_SHAPES = {
  single_use: SINGLE_USE_LIMIT_KEYS,
  bounded: BOUNDED_USAGE_LIMIT_KEYS,
} as const satisfies Record<UsageLimit["mode"], readonly string[]>;
type UsageLimitShapeAssociationsChecked = AssertAllAssociationsTrue<
  KeyedDiscriminantShapeAssociations<
    UsageLimit,
    "mode",
    typeof USAGE_LIMIT_SHAPES
  >
>;

type NoEconomicScope = Extract<EconomicScope, { mode: "none" }>;
type BoundedEconomicScope = Extract<EconomicScope, { mode: "bounded" }>;
const NO_ECONOMIC_SCOPE_KEYS = ["mode"] as const;
const BOUNDED_ECONOMIC_SCOPE_KEYS = [
  "mode",
  "asset_id",
  "maximum_amount",
  "spending_envelope_id",
  "wallet_or_economic_epoch",
] as const;
const ECONOMIC_SCOPE_SHAPES = {
  none: NO_ECONOMIC_SCOPE_KEYS,
  bounded: BOUNDED_ECONOMIC_SCOPE_KEYS,
} as const satisfies Record<EconomicScope["mode"], readonly string[]>;
type EconomicScopeShapeAssociationsChecked = AssertAllAssociationsTrue<
  KeyedDiscriminantShapeAssociations<
    EconomicScope,
    "mode",
    typeof ECONOMIC_SCOPE_SHAPES
  >
>;

const DELEGATION_CONSTRAINT_KEYS = ["delegation_mode"] as const;
type AuthorizationProofInventoryChecks = AssertAllTrue<[
  AssociationIsValid<
    ExactKeyInventory<AuthorizationProof, typeof AUTHORIZATION_PROOF_KEYS>
  >,
  AssociationIsValid<
    ExactKeyInventory<
      Omit<AuthorizationProofPayload, OptionalKeys<AuthorizationProofPayload>>,
      typeof AUTHORIZATION_PROOF_PAYLOAD_REQUIRED_KEYS
    >
  >,
  AssociationIsValid<
    ExactKeyInventory<
      Pick<AuthorizationProofPayload, OptionalKeys<AuthorizationProofPayload>>,
      typeof AUTHORIZATION_PROOF_PAYLOAD_OPTIONAL_KEYS
    >
  >,
  AssociationIsValid<
    ExactKeyInventory<AnyProviderScope, typeof ANY_PROVIDER_SCOPE_KEYS>
  >,
  AssociationIsValid<
    ExactKeyInventory<ExactProviderScope, typeof EXACT_PROVIDER_SCOPE_KEYS>
  >,
  AssociationIsValid<
    ExactKeyInventory<ServiceScope, typeof SERVICE_SCOPE_KEYS>
  >,
  AssociationIsValid<
    ExactKeyInventory<ExactExecutionScope, typeof EXACT_EXECUTION_SCOPE_KEYS>
  >,
  AssociationIsValid<
    ExactKeyInventory<
      BoundedExecutionScope,
      typeof BOUNDED_EXECUTION_SCOPE_KEYS
    >
  >,
  AssociationIsValid<
    ExactKeyInventory<SingleUseLimit, typeof SINGLE_USE_LIMIT_KEYS>
  >,
  AssociationIsValid<
    ExactKeyInventory<BoundedUsageLimit, typeof BOUNDED_USAGE_LIMIT_KEYS>
  >,
  AssociationIsValid<
    ExactKeyInventory<NoEconomicScope, typeof NO_ECONOMIC_SCOPE_KEYS>
  >,
  AssociationIsValid<
    ExactKeyInventory<
      BoundedEconomicScope,
      typeof BOUNDED_ECONOMIC_SCOPE_KEYS
    >
  >,
  AssociationIsValid<
    ExactKeyInventory<
      DelegationConstraints,
      typeof DELEGATION_CONSTRAINT_KEYS
    >
  >,
]>;

function fail(field: string, reason: string): never {
  throw new Error(`authorization_proof_${field}_${reason}`);
}

function own(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function defineOwnDataProperty(
  target: object,
  key: string,
  value: unknown
): void {
  const descriptor = Object.create(null) as PropertyDescriptor;
  descriptor.value = value;
  descriptor.enumerable = true;
  descriptor.writable = true;
  descriptor.configurable = true;
  Object.defineProperty(target, key, descriptor);
}

function assertObject(value: unknown, field: string): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) fail(field, "invalid");
}

function assertKeys(value: Record<string, unknown>, keys: readonly string[], field: string): void {
  const allowed = new Set(keys);
  for (const key of Object.keys(value)) if (!allowed.has(key)) fail(`${field}.${key}`, "unsupported");
}

function assertRequiredOwnKeys(
  value: Record<string, unknown>,
  keys: readonly string[],
  field: string
): void {
  for (const key of keys) {
    if (!own(value, key)) fail(field.length === 0 ? key : `${field}.${key}`, "required");
  }
}

function readRequiredOwn<Value extends object, Key extends keyof Value>(
  value: Value,
  key: Key,
  field: string
): Value[Key] {
  if (!own(value, key)) fail(field, "required");
  return value[key];
}

function captureFromDescriptors(
  descriptors: PropertyDescriptorMap,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  field: string
): Record<string, unknown> {
  const supportedKeys = [...requiredKeys, ...optionalKeys];
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") fail(field, "symbol_unsupported");
    if (!supportedKeys.includes(key)) fail(`${field}.${key}`, "unsupported");
  }

  const captured = Object.create(null) as Record<string, unknown>;
  for (const key of supportedKeys) {
    if (!own(descriptors, key)) {
      if (requiredKeys.includes(key)) fail(`${field}.${key}`, "required");
      continue;
    }
    const descriptor = descriptors[key];
    if (
      !own(descriptor, "value") ||
      own(descriptor, "get") ||
      own(descriptor, "set")
    ) {
      fail(`${field}.${key}`, "accessor_unsupported");
    }
    defineOwnDataProperty(captured, key, descriptor.value);
  }
  return captured;
}

function captureExactPassiveData(
  value: unknown,
  requiredKeys: readonly string[],
  field: string,
  optionalKeys: readonly string[] = []
): Record<string, unknown> {
  assertObject(value, field);
  return captureFromDescriptors(
    Object.getOwnPropertyDescriptors(value),
    requiredKeys,
    optionalKeys,
    field
  );
}

function captureDiscriminatedPassiveData(
  value: unknown,
  shapes: Readonly<Record<string, readonly string[]>>,
  field: string
): Record<string, unknown> {
  assertObject(value, field);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (!own(descriptors, "mode")) fail(`${field}.mode`, "required");
  const modeDescriptor = descriptors.mode;
  if (
    !own(modeDescriptor, "value") ||
    own(modeDescriptor, "get") ||
    own(modeDescriptor, "set")
  ) {
    fail(`${field}.mode`, "accessor_unsupported");
  }
  const mode = modeDescriptor.value;
  if (typeof mode !== "string" || !own(shapes, mode)) {
    fail(`${field}.mode`, "invalid");
  }
  return captureFromDescriptors(descriptors, shapes[mode], [], field);
}

function captureProviderScopePassiveData(value: unknown): ProviderScope {
  const captured = captureDiscriminatedPassiveData(
    value,
    PROVIDER_SCOPE_SHAPES,
    "payload.provider_scope"
  );
  return captured.mode === "exact"
      ? {
        mode: "exact",
        provider_id: captured.provider_id as ExactProviderScope["provider_id"],
      }
    : { mode: "any_authorized" };
}

function captureServiceScopePassiveData(value: unknown): ServiceScope {
  const captured = captureExactPassiveData(
    value,
    SERVICE_SCOPE_KEYS,
    "payload.service_scope"
  );
  return { service_id: captured.service_id as ServiceScope["service_id"] };
}

function captureExecutionScopePassiveData(value: unknown): ExecutionScope {
  const captured = captureDiscriminatedPassiveData(
    value,
    EXECUTION_SCOPE_SHAPES,
    "payload.execution_scope"
  );
  return captured.mode === "exact"
    ? {
        mode: "exact",
        execution_id: captured.execution_id as ExactExecutionScope["execution_id"],
        operation_type: captured.operation_type as string,
      }
    : {
        mode: "bounded",
        operation_type: captured.operation_type as string,
        capability_id: captured.capability_id as string,
        maximum_operations: captured.maximum_operations as number,
      };
}

function captureUsagePassiveData(value: unknown): UsageLimit {
  const captured = captureDiscriminatedPassiveData(
    value,
    USAGE_LIMIT_SHAPES,
    "payload.usage"
  );
  return captured.mode === "single_use"
    ? {
        mode: "single_use",
        maximum_usage_count: captured.maximum_usage_count as 1,
      }
    : {
        mode: "bounded",
        maximum_usage_count: captured.maximum_usage_count as number,
        sequence_mode: captured.sequence_mode as "monotonic",
      };
}

function captureEconomicScopePassiveData(value: unknown): EconomicScope {
  const captured = captureDiscriminatedPassiveData(
    value,
    ECONOMIC_SCOPE_SHAPES,
    "payload.economic_scope"
  );
  return captured.mode === "none"
    ? { mode: "none" }
    : {
        mode: "bounded",
        asset_id: captured.asset_id as string,
        maximum_amount: captured.maximum_amount as string,
        spending_envelope_id:
          captured.spending_envelope_id as BoundedEconomicScope["spending_envelope_id"],
        wallet_or_economic_epoch:
          captured.wallet_or_economic_epoch as number,
      };
}

function captureDelegationConstraintsPassiveData(
  value: unknown
): DelegationConstraints {
  const captured = captureExactPassiveData(
    value,
    DELEGATION_CONSTRAINT_KEYS,
    "payload.delegation_constraints"
  );
  return {
    delegation_mode:
      captured.delegation_mode as DelegationConstraints["delegation_mode"],
  };
}

function captureAuthorizationProofPayloadPassiveData(
  value: unknown
): AuthorizationProofPayload {
  const captured = captureExactPassiveData(
    value,
    AUTHORIZATION_PROOF_PAYLOAD_REQUIRED_KEYS,
    "payload",
    AUTHORIZATION_PROOF_PAYLOAD_OPTIONAL_KEYS
  );
  const payload: AuthorizationProofPayload = {
    protocol_version: captured.protocol_version as string,
    canonicalization_version: captured.canonicalization_version as string,
    issuer_id: captured.issuer_id as AuthorizationProofPayload["issuer_id"],
    issuer_key_id: captured.issuer_key_id as string,
    principal_id: captured.principal_id as AuthorizationProofPayload["principal_id"],
    subject_agent_id:
      captured.subject_agent_id as AuthorizationProofPayload["subject_agent_id"],
    audience: captured.audience as string,
    runtime_id: captured.runtime_id as AuthorizationProofPayload["runtime_id"],
    provider_scope: captureProviderScopePassiveData(captured.provider_scope),
    service_scope: captureServiceScopePassiveData(captured.service_scope),
    execution_scope: captureExecutionScopePassiveData(captured.execution_scope),
    authorization_request_id:
      captured.authorization_request_id as AuthorizationProofPayload["authorization_request_id"],
    authorization_decision_id:
      captured.authorization_decision_id as AuthorizationProofPayload["authorization_decision_id"],
    policy_digest: captured.policy_digest as string,
    policy_epoch: captured.policy_epoch as number,
    issued_at: captured.issued_at as AuthorizationProofPayload["issued_at"],
    valid_from: captured.valid_from as AuthorizationProofPayload["valid_from"],
    expires_at: captured.expires_at as AuthorizationProofPayload["expires_at"],
    revocation_epoch: captured.revocation_epoch as number,
    usage: captureUsagePassiveData(captured.usage),
    economic_scope: captureEconomicScopePassiveData(captured.economic_scope),
    delegation_constraints: captureDelegationConstraintsPassiveData(
      captured.delegation_constraints
    ),
    algorithm_id: captured.algorithm_id as string,
  };
  if (own(captured, "delegator_id")) {
    defineOwnDataProperty(payload, "delegator_id", captured.delegator_id);
  }
  return payload;
}

function captureAuthorizationProofPassiveData(value: unknown): AuthorizationProof {
  const captured = captureExactPassiveData(
    value,
    AUTHORIZATION_PROOF_KEYS,
    "proof"
  );
  return {
    proof_id: captured.proof_id as AuthorizationProof["proof_id"],
    payload: captureAuthorizationProofPayloadPassiveData(captured.payload),
    signature: captured.signature as string,
  };
}

function assertUuid(value: unknown, field: string): asserts value is string {
  // UUID is an opaque non-blank identifier in the existing contract surface.
  assertNonEmpty(value, field);
}

function assertNonEmpty(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) fail(field, "required");
}

function assertWellFormedUnicodeString(value: string, field: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (index + 1 >= value.length || next < 0xdc00 || next > 0xdfff) fail(field, "unicode_invalid");
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(field, "unicode_invalid");
    }
  }
}

function assertIdentityUnicode(preimage: AuthorizationProofIdentityPreimage): void {
  assertWellFormedUnicodeString(preimage.protocol_version, "protocol_version");
  assertWellFormedUnicodeString(preimage.canonicalization_version, "canonicalization_version");
  assertWellFormedUnicodeString(preimage.issuer_id, "issuer_id");
  assertWellFormedUnicodeString(preimage.issuer_key_id, "issuer_key_id");
  assertWellFormedUnicodeString(preimage.principal_id, "principal_id");
  assertWellFormedUnicodeString(preimage.subject_agent_id, "subject_agent_id");
  if (own(preimage, "delegator_id")) {
    assertWellFormedUnicodeString(preimage.delegator_id as string, "delegator_id");
  }
  assertWellFormedUnicodeString(preimage.audience, "audience");
  assertWellFormedUnicodeString(preimage.runtime_id, "runtime_id");
  if (preimage.provider_scope.mode === "exact") assertWellFormedUnicodeString(preimage.provider_scope.provider_id, "provider_scope.provider_id");
  assertWellFormedUnicodeString(preimage.service_scope.service_id, "service_scope.service_id");
  if (preimage.execution_scope.mode === "exact") {
    assertWellFormedUnicodeString(preimage.execution_scope.execution_id, "execution_scope.execution_id");
    assertWellFormedUnicodeString(preimage.execution_scope.operation_type, "execution_scope.operation_type");
  } else {
    assertWellFormedUnicodeString(preimage.execution_scope.operation_type, "execution_scope.operation_type");
    assertWellFormedUnicodeString(preimage.execution_scope.capability_id, "execution_scope.capability_id");
  }
  assertWellFormedUnicodeString(preimage.authorization_request_id, "authorization_request_id");
  assertWellFormedUnicodeString(preimage.authorization_decision_id, "authorization_decision_id");
  assertWellFormedUnicodeString(preimage.policy_digest, "policy_digest");
  assertWellFormedUnicodeString(preimage.issued_at, "issued_at");
  assertWellFormedUnicodeString(preimage.valid_from, "valid_from");
  assertWellFormedUnicodeString(preimage.expires_at, "expires_at");
  if (preimage.economic_scope.mode === "bounded") {
    assertWellFormedUnicodeString(preimage.economic_scope.asset_id, "economic_scope.asset_id");
    assertWellFormedUnicodeString(preimage.economic_scope.spending_envelope_id, "economic_scope.spending_envelope_id");
    assertWellFormedUnicodeString(preimage.economic_scope.maximum_amount, "economic_scope.maximum_amount");
  }
  assertWellFormedUnicodeString(preimage.algorithm_id, "algorithm_id");
}

function assertInteger(value: unknown, field: string, minimum: number): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < minimum) fail(field, "invalid");
}

function assertTimestamp(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !isISODateTime(value)) fail(field, "invalid");
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(value);
  if (!match) fail(field, "invalid");
  const year = decimalDigits(match[1]);
  const month = decimalDigits(match[2]);
  const day = decimalDigits(match[3]);
  const hour = decimalDigits(match[4]);
  const minute = decimalDigits(match[5]);
  const second = decimalDigits(match[6]);
  const daysInMonth = [31, (year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0)) ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
  if (!daysInMonth || day < 1 || day > daysInMonth || hour > 23 || minute > 59 || second > 59) fail(field, "invalid");
}

function decimalDigits(value: string): number {
  let result = 0;
  for (const character of value) result = result * 10 + character.charCodeAt(0) - 48;
  return result;
}

function timestampValue(value: string): number {
  const match = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,3}))?Z$/.exec(value);
  if (!match) fail("timestamp", "invalid");
  return (((((decimalDigits(match[1]) * 13 + decimalDigits(match[2])) * 32 + decimalDigits(match[3])) * 24 + decimalDigits(match[4])) * 60 + decimalDigits(match[5])) * 60 + decimalDigits(match[6])) * 1000 + decimalDigits((match[7] ?? "").padEnd(3, "0"));
}

function canonicalTimestamp(value: string): string {
  if (!isISODateTime(value)) fail("timestamp", "invalid");
  return new Date(value).toISOString();
}

type AuthorizationProofCanonicalTuple = [
  string, string, string, string, string, string, string | null, string, string,
  unknown[], unknown[], unknown[], string, string, string, number, string, string,
  string, number, unknown[], unknown[], unknown[], string,
];

function canonicalTuple(payload: AuthorizationProofPayload): AuthorizationProofCanonicalTuple {
  const preimage = createAuthorizationProofIdentityPreimage(payload);
  // V1 canonical strings must be Unicode scalar-value sequences. No
  // normalization is applied; JSON escaping and UTF-8 encoding follow.
  assertIdentityUnicode(preimage);
  const provider = preimage.provider_scope.mode === "any_authorized"
    ? ["any_authorized"]
    : ["exact", preimage.provider_scope.provider_id];
  const execution = preimage.execution_scope.mode === "exact"
    ? ["exact", preimage.execution_scope.execution_id, preimage.execution_scope.operation_type]
    : ["bounded", preimage.execution_scope.operation_type, preimage.execution_scope.capability_id, preimage.execution_scope.maximum_operations];
  const usage = preimage.usage.mode === "single_use"
    ? ["single_use", 1]
    : ["bounded", preimage.usage.maximum_usage_count, "monotonic"];
  const economic = preimage.economic_scope.mode === "none"
    ? ["none"]
    : ["bounded", preimage.economic_scope.asset_id, preimage.economic_scope.maximum_amount, preimage.economic_scope.spending_envelope_id, preimage.economic_scope.wallet_or_economic_epoch];
  const delegatorId = own(preimage, "delegator_id")
    ? preimage.delegator_id as string
    : null;
  return [
    preimage.protocol_version,
    preimage.canonicalization_version,
    preimage.issuer_id,
    preimage.issuer_key_id,
    preimage.principal_id,
    preimage.subject_agent_id,
    delegatorId,
    preimage.audience,
    preimage.runtime_id,
    provider,
    ["service_id", preimage.service_scope.service_id],
    execution,
    preimage.authorization_request_id,
    preimage.authorization_decision_id,
    preimage.policy_digest,
    preimage.policy_epoch,
    canonicalTimestamp(preimage.issued_at),
    canonicalTimestamp(preimage.valid_from),
    canonicalTimestamp(preimage.expires_at),
    preimage.revocation_epoch,
    usage,
    economic,
    [preimage.delegation_constraints.delegation_mode],
    preimage.algorithm_id,
  ];
}

/** Canonicalization V1 preserves validated strings and uses explicit tuple order. */
export function canonicalizeAuthorizationProofIdentity(payload: AuthorizationProofPayload): string {
  const serialized = JSON.stringify(canonicalTuple(payload));
  if (typeof serialized !== "string") fail("canonicalization", "failed");
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

function validateProviderScope(value: ProviderScope): void {
  assertObject(value, "provider_scope");
  assertRequiredOwnKeys(value, ANY_PROVIDER_SCOPE_KEYS, "provider_scope");
  const mode = readRequiredOwn(value, "mode", "provider_scope.mode");
  if (mode === "any_authorized") {
    assertKeys(value, ANY_PROVIDER_SCOPE_KEYS, "provider_scope");
    return;
  }
  if (mode === "exact") {
    const exactValue = value as ExactProviderScope;
    assertKeys(value, EXACT_PROVIDER_SCOPE_KEYS, "provider_scope");
    assertRequiredOwnKeys(value, EXACT_PROVIDER_SCOPE_KEYS, "provider_scope");
    assertUuid(
      readRequiredOwn(exactValue, "provider_id", "provider_scope.provider_id"),
      "provider_scope.provider_id"
    );
    return;
  }
  // any_authorized is policy/service/audience/runtime constrained, not global.
  fail("provider_scope.mode", "invalid");
}

function validateServiceScope(value: ServiceScope): void {
  assertObject(value, "service_scope");
  assertKeys(value, SERVICE_SCOPE_KEYS, "service_scope");
  assertRequiredOwnKeys(value, SERVICE_SCOPE_KEYS, "service_scope");
  assertUuid(
    readRequiredOwn(value, "service_id", "service_scope.service_id"),
    "service_scope.service_id"
  );
}

function validateExecutionScope(value: ExecutionScope): void {
  assertObject(value, "execution_scope");
  assertRequiredOwnKeys(value, ["mode"], "execution_scope");
  const mode = readRequiredOwn(value, "mode", "execution_scope.mode");
  if (mode === "exact") {
    const exactValue = value as ExactExecutionScope;
    assertKeys(value, EXACT_EXECUTION_SCOPE_KEYS, "execution_scope");
    assertRequiredOwnKeys(value, EXACT_EXECUTION_SCOPE_KEYS, "execution_scope");
    assertUuid(
      readRequiredOwn(exactValue, "execution_id", "execution_scope.execution_id"),
      "execution_scope.execution_id"
    );
    assertNonEmpty(
      readRequiredOwn(exactValue, "operation_type", "execution_scope.operation_type"),
      "execution_scope.operation_type"
    );
    return;
  }
  if (mode === "bounded") {
    const boundedValue = value as BoundedExecutionScope;
    assertKeys(value, BOUNDED_EXECUTION_SCOPE_KEYS, "execution_scope");
    assertRequiredOwnKeys(value, BOUNDED_EXECUTION_SCOPE_KEYS, "execution_scope");
    assertNonEmpty(
      readRequiredOwn(boundedValue, "operation_type", "execution_scope.operation_type"),
      "execution_scope.operation_type"
    );
    assertNonEmpty(
      readRequiredOwn(boundedValue, "capability_id", "execution_scope.capability_id"),
      "execution_scope.capability_id"
    );
    assertInteger(
      readRequiredOwn(boundedValue, "maximum_operations", "execution_scope.maximum_operations"),
      "execution_scope.maximum_operations",
      1
    );
    return;
  }
  fail("execution_scope.mode", "invalid");
}

function validateUsage(value: UsageLimit): void {
  assertObject(value, "usage");
  assertRequiredOwnKeys(value, ["mode"], "usage");
  const mode = readRequiredOwn(value, "mode", "usage.mode");
  if (mode === "single_use") {
    const singleUseValue = value as SingleUseLimit;
    assertKeys(value, SINGLE_USE_LIMIT_KEYS, "usage");
    assertRequiredOwnKeys(value, SINGLE_USE_LIMIT_KEYS, "usage");
    if (
      readRequiredOwn(singleUseValue, "maximum_usage_count", "usage.maximum_usage_count") !== 1
    ) {
      fail("usage.maximum_usage_count", "invalid");
    }
    return;
  }
  if (mode === "bounded") {
    const boundedValue = value as BoundedUsageLimit;
    assertKeys(value, BOUNDED_USAGE_LIMIT_KEYS, "usage");
    assertRequiredOwnKeys(value, BOUNDED_USAGE_LIMIT_KEYS, "usage");
    assertInteger(
      readRequiredOwn(boundedValue, "maximum_usage_count", "usage.maximum_usage_count"),
      "usage.maximum_usage_count",
      2
    );
    if (readRequiredOwn(boundedValue, "sequence_mode", "usage.sequence_mode") !== "monotonic") {
      fail("usage.sequence_mode", "invalid");
    }
    return;
  }
  fail("usage.mode", "invalid");
}

function validateEconomicScope(value: EconomicScope): void {
  assertObject(value, "economic_scope");
  assertRequiredOwnKeys(value, ["mode"], "economic_scope");
  const mode = readRequiredOwn(value, "mode", "economic_scope.mode");
  if (mode === "none") {
    assertKeys(value, NO_ECONOMIC_SCOPE_KEYS, "economic_scope");
    return;
  }
  if (mode === "bounded") {
    const boundedValue = value as BoundedEconomicScope;
    assertKeys(value, BOUNDED_ECONOMIC_SCOPE_KEYS, "economic_scope");
    assertRequiredOwnKeys(value, BOUNDED_ECONOMIC_SCOPE_KEYS, "economic_scope");
    assertNonEmpty(
      readRequiredOwn(boundedValue, "asset_id", "economic_scope.asset_id"),
      "economic_scope.asset_id"
    );
    const maximumAmount = readRequiredOwn(
      boundedValue,
      "maximum_amount",
      "economic_scope.maximum_amount"
    );
    if (typeof maximumAmount !== "string" || !AMOUNT_PATTERN.test(maximumAmount)) {
      fail("economic_scope.maximum_amount", "invalid");
    }
    assertUuid(
      readRequiredOwn(
        boundedValue,
        "spending_envelope_id",
        "economic_scope.spending_envelope_id"
      ),
      "economic_scope.spending_envelope_id"
    );
    assertInteger(
      readRequiredOwn(
        boundedValue,
        "wallet_or_economic_epoch",
        "economic_scope.wallet_or_economic_epoch"
      ),
      "economic_scope.wallet_or_economic_epoch",
      0
    );
    return;
  }
  fail("economic_scope.mode", "invalid");
}

function validateDelegation(value: DelegationConstraints, hasDelegator: boolean, delegatorId: unknown): void {
  assertObject(value, "delegation_constraints");
  assertKeys(value, DELEGATION_CONSTRAINT_KEYS, "delegation_constraints");
  assertRequiredOwnKeys(value, DELEGATION_CONSTRAINT_KEYS, "delegation_constraints");
  const mode = readRequiredOwn(
    value,
    "delegation_mode",
    "delegation_constraints.delegation_mode"
  );
  if (mode === "direct") {
    if (hasDelegator) fail("delegator_id", "unsupported_for_direct");
    return;
  }
  if (mode === "delegated") {
    assertUuid(delegatorId, "delegator_id");
    return;
  }
  fail("delegation_constraints.delegation_mode", "invalid");
}

function validateOwnedAuthorizationProofPayload(
  payload: AuthorizationProofPayload
): void {
  assertObject(payload, "payload");
  assertKeys(payload, AUTHORIZATION_PROOF_PAYLOAD_KEYS, "payload");
  assertRequiredOwnKeys(payload, AUTHORIZATION_PROOF_PAYLOAD_REQUIRED_KEYS, "");
  const protocolVersion = readRequiredOwn(payload, "protocol_version", "protocol_version");
  const canonicalizationVersion = readRequiredOwn(
    payload,
    "canonicalization_version",
    "canonicalization_version"
  );
  const issuerId = readRequiredOwn(payload, "issuer_id", "issuer_id");
  const issuerKeyId = readRequiredOwn(payload, "issuer_key_id", "issuer_key_id");
  const principalId = readRequiredOwn(payload, "principal_id", "principal_id");
  const subjectAgentId = readRequiredOwn(payload, "subject_agent_id", "subject_agent_id");
  const audience = readRequiredOwn(payload, "audience", "audience");
  const runtimeId = readRequiredOwn(payload, "runtime_id", "runtime_id");
  const providerScope = readRequiredOwn(payload, "provider_scope", "provider_scope");
  const serviceScope = readRequiredOwn(payload, "service_scope", "service_scope");
  const executionScope = readRequiredOwn(payload, "execution_scope", "execution_scope");
  const authorizationRequestId = readRequiredOwn(
    payload,
    "authorization_request_id",
    "authorization_request_id"
  );
  const authorizationDecisionId = readRequiredOwn(
    payload,
    "authorization_decision_id",
    "authorization_decision_id"
  );
  const policyDigest = readRequiredOwn(payload, "policy_digest", "policy_digest");
  const policyEpoch = readRequiredOwn(payload, "policy_epoch", "policy_epoch");
  const issuedAt = readRequiredOwn(payload, "issued_at", "issued_at");
  const validFrom = readRequiredOwn(payload, "valid_from", "valid_from");
  const expiresAt = readRequiredOwn(payload, "expires_at", "expires_at");
  const revocationEpoch = readRequiredOwn(payload, "revocation_epoch", "revocation_epoch");
  const usage = readRequiredOwn(payload, "usage", "usage");
  const economicScope = readRequiredOwn(payload, "economic_scope", "economic_scope");
  const delegationConstraints = readRequiredOwn(
    payload,
    "delegation_constraints",
    "delegation_constraints"
  );
  const algorithmId = readRequiredOwn(payload, "algorithm_id", "algorithm_id");

  if (protocolVersion !== AUTHORIZATION_PROOF_PROTOCOL_VERSION) fail("protocol_version", "unsupported");
  if (canonicalizationVersion !== AUTHORIZATION_PROOF_CANONICALIZATION_VERSION) fail("canonicalization_version", "unsupported");
  assertUuid(issuerId, "issuer_id");
  assertNonEmpty(issuerKeyId, "issuer_key_id");
  assertUuid(principalId, "principal_id");
  assertUuid(subjectAgentId, "subject_agent_id");
  const hasDelegator = own(payload, "delegator_id");
  const delegatorId = hasDelegator ? payload.delegator_id : undefined;
  if (hasDelegator && delegatorId !== undefined) assertUuid(delegatorId, "delegator_id");
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
  if (timestampValue(issuedAt) > timestampValue(validFrom)) fail("validity", "ordering");
  if (timestampValue(validFrom) >= timestampValue(expiresAt)) fail("validity", "ordering");
  assertInteger(revocationEpoch, "revocation_epoch", 0);
  validateUsage(usage);
  validateEconomicScope(economicScope);
  validateDelegation(delegationConstraints, hasDelegator, delegatorId);
  assertNonEmpty(algorithmId, "algorithm_id");
}

function captureAndValidateAuthorizationProofPayload(
  payload: AuthorizationProofPayload
): AuthorizationProofPayload {
  const owned = captureAuthorizationProofPayloadPassiveData(payload);
  validateOwnedAuthorizationProofPayload(owned);
  return owned;
}

export function validateAuthorizationProofPayload(
  payload: AuthorizationProofPayload
): void {
  captureAndValidateAuthorizationProofPayload(payload);
}

function snapshotProviderScope(value: ProviderScope): ProviderScope {
  const mode = readRequiredOwn(value, "mode", "provider_scope.mode");
  if (mode === "exact") {
    const exactValue = value as ExactProviderScope;
    return {
        mode: "exact",
        provider_id: readRequiredOwn(
          exactValue,
          "provider_id",
          "provider_scope.provider_id"
        ),
      };
  }
  return { mode: "any_authorized" };
}
function snapshotExecutionScope(value: ExecutionScope): ExecutionScope {
  const mode = readRequiredOwn(value, "mode", "execution_scope.mode");
  if (mode === "exact") {
    const exactValue = value as ExactExecutionScope;
    return {
        mode: "exact",
        execution_id: readRequiredOwn(
          exactValue,
          "execution_id",
          "execution_scope.execution_id"
        ),
        operation_type: readRequiredOwn(
          exactValue,
          "operation_type",
          "execution_scope.operation_type"
        ),
      };
  }
  const boundedValue = value as BoundedExecutionScope;
  return {
    mode: "bounded",
    operation_type: readRequiredOwn(
      boundedValue,
      "operation_type",
      "execution_scope.operation_type"
    ),
    capability_id: readRequiredOwn(
      boundedValue,
      "capability_id",
      "execution_scope.capability_id"
    ),
    maximum_operations: readRequiredOwn(
      boundedValue,
      "maximum_operations",
      "execution_scope.maximum_operations"
    ),
  };
}
function snapshotUsage(value: UsageLimit): UsageLimit {
  const mode = readRequiredOwn(value, "mode", "usage.mode");
  if (mode === "single_use") {
    const singleUseValue = value as SingleUseLimit;
    return {
        mode: "single_use",
        maximum_usage_count: readRequiredOwn(
          singleUseValue,
          "maximum_usage_count",
          "usage.maximum_usage_count"
        ),
      };
  }
  const boundedValue = value as BoundedUsageLimit;
  return {
    mode: "bounded",
    maximum_usage_count: readRequiredOwn(
      boundedValue,
      "maximum_usage_count",
      "usage.maximum_usage_count"
    ),
    sequence_mode: readRequiredOwn(
      boundedValue,
      "sequence_mode",
      "usage.sequence_mode"
    ),
  };
}
function snapshotEconomicScope(value: EconomicScope): EconomicScope {
  const mode = readRequiredOwn(value, "mode", "economic_scope.mode");
  if (mode === "none") return { mode: "none" };
  const boundedValue = value as BoundedEconomicScope;
  return {
    mode: "bounded",
    asset_id: readRequiredOwn(boundedValue, "asset_id", "economic_scope.asset_id"),
    maximum_amount: readRequiredOwn(
      boundedValue,
      "maximum_amount",
      "economic_scope.maximum_amount"
    ),
    spending_envelope_id: readRequiredOwn(
      boundedValue,
      "spending_envelope_id",
      "economic_scope.spending_envelope_id"
    ),
    wallet_or_economic_epoch: readRequiredOwn(
      boundedValue,
      "wallet_or_economic_epoch",
      "economic_scope.wallet_or_economic_epoch"
    ),
  };
}

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

function captureAndValidateAuthorizationProof(
  proof: AuthorizationProof
): AuthorizationProof {
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
