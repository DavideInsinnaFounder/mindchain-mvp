/**
 * mindchain-mvp - AuthorizationProof usage transition foundation (Day 71)
 *
 * This module calculates deterministic candidate proof-usage state transitions
 * given an authoritative current state supplied by the caller. It does not
 * commit consumption, provide durable replay authority, perform admission, or
 * coordinate economic capacity. Candidate next state != committed next state.
 */

import type {
  AuthorizationProof,
  AuthorizationProofPayload,
  DelegationConstraints,
  EconomicScope,
  ExecutionScope,
  ProviderScope,
  ServiceScope,
  UsageLimit,
  UUID,
} from "./contracts.js";
import {
  deriveAuthorizationProofId,
  snapshotAuthorizationProof,
  snapshotAuthorizationProofPayload,
} from "./authorization_proof.js";

export interface AuthorizationProofUsageState {
  proof_id: AuthorizationProof["proof_id"];
  /** Quantity of successful proof-use candidate transitions represented by this V1 state. */
  consumed_usage_count: number;
  /**
   * Version of the candidate mutable proof-usage state. It advances once per
   * successful V1 transition and equals consumed_usage_count in V1 only
   * because V1 has one state transition per successful use. It establishes no
   * compare-and-swap, freshness, authoritative current state, persistence,
   * concurrency exclusion, or authoritative commit semantics.
   */
  state_version: number;
}

export interface TransitionAuthorizationProofUsageInput {
  proof: AuthorizationProof;
  current_usage_state: AuthorizationProofUsageState | null;
  requested_usage_index: number;
}

export type AuthorizationProofUsageTransitionFailureReason =
  | "structural_invalid"
  | "proof_id_mismatch"
  | "usage_state_invalid"
  | "proof_usage_mismatch"
  | "single_use_index_mismatch"
  | "usage_exhausted"
  | "sequence_duplicate"
  | "sequence_gap";

export type AuthorizationProofUsageTransitionResult =
  | {
      transition: "usage_state_advanced";
      next_usage_state: AuthorizationProofUsageState;
    }
  | {
      transition: "usage_state_rejected";
      reason: AuthorizationProofUsageTransitionFailureReason;
    };

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

type DiscriminantShapeInventory<Mode extends PropertyKey> = {
  readonly [Value in Mode]: readonly string[];
};

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

type ExactUnionInventory<Declared, Inventoried> = [
  Exclude<Declared, Inventoried>,
] extends [never]
  ? [Exclude<Inventoried, Declared>] extends [never]
    ? true
    : false
  : false;

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

type AnyProviderScope = Extract<ProviderScope, { mode: "any_authorized" }>;
type ExactProviderScope = Extract<ProviderScope, { mode: "exact" }>;
const ANY_PROVIDER_SCOPE_KEYS = ["mode"] as const;
const EXACT_PROVIDER_SCOPE_KEYS = ["mode", "provider_id"] as const;
const PROVIDER_SCOPE_SHAPES = {
  any_authorized: ANY_PROVIDER_SCOPE_KEYS,
  exact: EXACT_PROVIDER_SCOPE_KEYS,
} as const satisfies DiscriminantShapeInventory<ProviderScope["mode"]>;
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
} as const satisfies DiscriminantShapeInventory<ExecutionScope["mode"]>;
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
} as const satisfies DiscriminantShapeInventory<UsageLimit["mode"]>;
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
} as const satisfies DiscriminantShapeInventory<EconomicScope["mode"]>;
type EconomicScopeShapeAssociationsChecked = AssertAllAssociationsTrue<
  KeyedDiscriminantShapeAssociations<
    EconomicScope,
    "mode",
    typeof ECONOMIC_SCOPE_SHAPES
  >
>;

const DELEGATION_CONSTRAINT_KEYS = ["delegation_mode"] as const;
type ReviewedDelegationMode = "direct" | "delegated";

const AUTHORIZATION_PROOF_USAGE_STATE_KEYS = [
  "proof_id",
  "consumed_usage_count",
  "state_version",
] as const;

const TRANSITION_AUTHORIZATION_PROOF_USAGE_INPUT_KEYS = [
  "proof",
  "current_usage_state",
  "requested_usage_index",
] as const;
type AuthorizationProofUsageInventoryChecks = AssertAllTrue<[
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
  ExactUnionInventory<
    DelegationConstraints["delegation_mode"],
    ReviewedDelegationMode
  >,
  AssociationIsValid<
    ExactKeyInventory<
      AuthorizationProofUsageState,
      typeof AUTHORIZATION_PROOF_USAGE_STATE_KEYS
    >
  >,
  AssociationIsValid<
    ExactKeyInventory<
      TransitionAuthorizationProofUsageInput,
      typeof TRANSITION_AUTHORIZATION_PROOF_USAGE_INPUT_KEYS
    >
  >,
]>;

class StructuralInputError extends Error {}
class UsageStateInputError extends Error {}

function structuralFail(field: string, reason: string): never {
  throw new StructuralInputError(`authorization_proof_usage_${field}_${reason}`);
}

function usageStateFail(field: string, reason: string): never {
  throw new UsageStateInputError(
    `authorization_proof_usage_state_${field}_${reason}`
  );
}

function assertObject(
  value: unknown,
  field: string,
  fail: (field: string, reason: string) => never
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(field, "invalid");
  }
}

function own(value: object, key: PropertyKey): boolean {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function defineOwnDataProperty(
  target: object,
  key: string,
  value: unknown
): void {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
}

function captureFromDescriptors(
  descriptors: PropertyDescriptorMap,
  requiredKeys: readonly string[],
  optionalKeys: readonly string[],
  field: string,
  fail: (field: string, reason: string) => never
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
    captured[key] = descriptor.value;
  }
  return captured;
}

function captureExactDataProperties(
  value: unknown,
  requiredKeys: readonly string[],
  field: string,
  fail: (field: string, reason: string) => never,
  optionalKeys: readonly string[] = []
): Record<string, unknown> {
  assertObject(value, field, fail);
  return captureFromDescriptors(
    Object.getOwnPropertyDescriptors(value),
    requiredKeys,
    optionalKeys,
    field,
    fail
  );
}

function captureDiscriminatedDataProperties(
  value: unknown,
  shapes: Readonly<Record<string, readonly string[]>>,
  field: string
): Record<string, unknown> {
  assertObject(value, field, structuralFail);
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (!own(descriptors, "mode")) structuralFail(`${field}.mode`, "required");
  const modeDescriptor = descriptors.mode;
  if (
    !own(modeDescriptor, "value") ||
    own(modeDescriptor, "get") ||
    own(modeDescriptor, "set")
  ) {
    structuralFail(`${field}.mode`, "accessor_unsupported");
  }
  const mode = modeDescriptor.value;
  if (typeof mode !== "string" || !own(shapes, mode)) {
    structuralFail(`${field}.mode`, "invalid");
  }
  return captureFromDescriptors(
    descriptors,
    shapes[mode],
    [],
    field,
    structuralFail
  );
}

function snapshotPassiveProviderScope(value: unknown): ProviderScope {
  const captured = captureDiscriminatedDataProperties(
    value,
    PROVIDER_SCOPE_SHAPES,
    "proof.payload.provider_scope"
  );
  return captured.mode === "exact"
    ? { mode: "exact", provider_id: captured.provider_id as UUID }
    : { mode: "any_authorized" };
}

function snapshotPassiveServiceScope(value: unknown): ServiceScope {
  const captured = captureExactDataProperties(
    value,
    SERVICE_SCOPE_KEYS,
    "proof.payload.service_scope",
    structuralFail
  );
  return { service_id: captured.service_id as UUID };
}

function snapshotPassiveExecutionScope(value: unknown): ExecutionScope {
  const captured = captureDiscriminatedDataProperties(
    value,
    EXECUTION_SCOPE_SHAPES,
    "proof.payload.execution_scope"
  );
  return captured.mode === "exact"
    ? {
        mode: "exact",
        execution_id: captured.execution_id as UUID,
        operation_type: captured.operation_type as string,
      }
    : {
        mode: "bounded",
        operation_type: captured.operation_type as string,
        capability_id: captured.capability_id as string,
        maximum_operations: captured.maximum_operations as number,
      };
}

function snapshotPassiveUsage(value: unknown): UsageLimit {
  const captured = captureDiscriminatedDataProperties(
    value,
    USAGE_LIMIT_SHAPES,
    "proof.payload.usage"
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

function snapshotPassiveEconomicScope(value: unknown): EconomicScope {
  const captured = captureDiscriminatedDataProperties(
    value,
    ECONOMIC_SCOPE_SHAPES,
    "proof.payload.economic_scope"
  );
  return captured.mode === "none"
    ? { mode: "none" }
    : {
        mode: "bounded",
        asset_id: captured.asset_id as string,
        maximum_amount: captured.maximum_amount as string,
        spending_envelope_id: captured.spending_envelope_id as UUID,
        wallet_or_economic_epoch:
          captured.wallet_or_economic_epoch as number,
      };
}

function snapshotPassiveDelegationConstraints(
  value: unknown
): DelegationConstraints {
  const captured = captureExactDataProperties(
    value,
    DELEGATION_CONSTRAINT_KEYS,
    "proof.payload.delegation_constraints",
    structuralFail
  );
  return {
    delegation_mode: captured.delegation_mode as "direct" | "delegated",
  };
}

function snapshotPassivePayload(value: unknown): AuthorizationProofPayload {
  const captured = captureExactDataProperties(
    value,
    AUTHORIZATION_PROOF_PAYLOAD_REQUIRED_KEYS,
    "proof.payload",
    structuralFail,
    AUTHORIZATION_PROOF_PAYLOAD_OPTIONAL_KEYS
  );
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
    delegation_constraints: snapshotPassiveDelegationConstraints(
      captured.delegation_constraints
    ),
    algorithm_id: captured.algorithm_id as string,
  };
  if (own(captured, "delegator_id")) {
    defineOwnDataProperty(payload, "delegator_id", captured.delegator_id);
  }
  return snapshotAuthorizationProofPayload(payload);
}

function snapshotPassiveProof(value: unknown): AuthorizationProof {
  const captured = captureExactDataProperties(
    value,
    AUTHORIZATION_PROOF_KEYS,
    "proof",
    structuralFail
  );
  const payload = snapshotPassivePayload(captured.payload);
  return snapshotAuthorizationProof({
    proof_id: captured.proof_id as AuthorizationProof["proof_id"],
    payload,
    signature: captured.signature as string,
  });
}

function snapshotIntrinsicUsageState(
  value: unknown
): AuthorizationProofUsageState {
  const captured = captureExactDataProperties(
    value,
    AUTHORIZATION_PROOF_USAGE_STATE_KEYS,
    "usage_state",
    usageStateFail
  );
  if (
    typeof captured.proof_id !== "string" ||
    captured.proof_id.trim().length === 0
  ) {
    usageStateFail("proof_id", "invalid");
  }
  if (
    typeof captured.consumed_usage_count !== "number" ||
    !Number.isSafeInteger(captured.consumed_usage_count) ||
    captured.consumed_usage_count < 1
  ) {
    usageStateFail("consumed_usage_count", "invalid");
  }
  if (
    typeof captured.state_version !== "number" ||
    !Number.isSafeInteger(captured.state_version) ||
    captured.state_version < 1
  ) {
    usageStateFail("state_version", "invalid");
  }
  if (captured.state_version !== captured.consumed_usage_count) {
    usageStateFail("state_version", "inconsistent");
  }
  return {
    proof_id: captured.proof_id,
    consumed_usage_count: captured.consumed_usage_count,
    state_version: captured.state_version,
  } as AuthorizationProofUsageState;
}

function isExpectedStructuralFailure(error: unknown): boolean {
  return (
    error instanceof StructuralInputError ||
    (error instanceof Error && error.message.startsWith("authorization_proof_"))
  );
}

function rejected(
  reason: AuthorizationProofUsageTransitionFailureReason
): AuthorizationProofUsageTransitionResult {
  return { transition: "usage_state_rejected", reason };
}

/**
 * Computes a candidate next proof-usage state from explicit caller-supplied
 * current state. Local transition eligibility != authoritative consumption;
 * usage-state evaluation != atomic admission; replay detection != durable
 * replay authority. Day 73 owns authoritative serialized commit semantics.
 *
 * Usage identity is the recomputed Day 68 proof_id for both single-use and
 * bounded proofs. Signature bytes and economic/runtime references do not form
 * a second usage identity.
 *
 * The passive-data guarantee covers ordinary data objects, not adversarial
 * Proxy/meta-object traps; Object.getOwnPropertyDescriptors can invoke traps.
 */
export function transitionAuthorizationProofUsage(
  input: TransitionAuthorizationProofUsageInput
): AuthorizationProofUsageTransitionResult {
  let proof: AuthorizationProof;
  let currentUsageStateValue: unknown;
  let requestedUsageIndex: number;
  try {
    const capturedInput = captureExactDataProperties(
      input,
      TRANSITION_AUTHORIZATION_PROOF_USAGE_INPUT_KEYS,
      "input",
      structuralFail
    );
    if (
      typeof capturedInput.requested_usage_index !== "number" ||
      !Number.isSafeInteger(capturedInput.requested_usage_index) ||
      capturedInput.requested_usage_index < 1
    ) {
      structuralFail("requested_usage_index", "invalid");
    }
    requestedUsageIndex = capturedInput.requested_usage_index;
    currentUsageStateValue = capturedInput.current_usage_state;
    // Own the complete identity-bearing graph before inspecting nested state.
    proof = snapshotPassiveProof(capturedInput.proof);
  } catch (error) {
    if (isExpectedStructuralFailure(error)) return rejected("structural_invalid");
    throw error;
  }

  let expectedProofId: AuthorizationProof["proof_id"];
  try {
    expectedProofId = deriveAuthorizationProofId(proof.payload);
  } catch (error) {
    if (isExpectedStructuralFailure(error)) return rejected("structural_invalid");
    throw error;
  }
  if (proof.proof_id !== expectedProofId) return rejected("proof_id_mismatch");

  let currentUsageState: AuthorizationProofUsageState | null;
  if (currentUsageStateValue === null) {
    currentUsageState = null;
  } else {
    try {
      currentUsageState = snapshotIntrinsicUsageState(currentUsageStateValue);
    } catch (error) {
      if (error instanceof UsageStateInputError) {
        return rejected("usage_state_invalid");
      }
      throw error;
    }
  }

  if (
    currentUsageState !== null &&
    currentUsageState.proof_id !== expectedProofId
  ) {
    return rejected("proof_usage_mismatch");
  }

  const maximumUsageCount = proof.payload.usage.maximum_usage_count;
  const consumedUsageCount =
    currentUsageState?.consumed_usage_count ?? 0;
  const stateVersion = currentUsageState?.state_version ?? 0;
  if (consumedUsageCount > maximumUsageCount) {
    return rejected("usage_state_invalid");
  }
  if (consumedUsageCount === maximumUsageCount) {
    return rejected("usage_exhausted");
  }

  if (proof.payload.usage.mode === "single_use") {
    if (requestedUsageIndex !== 1) {
      return rejected("single_use_index_mismatch");
    }
  } else {
    const nextUsageIndex = consumedUsageCount + 1;
    if (requestedUsageIndex < nextUsageIndex) {
      return rejected("sequence_duplicate");
    }
    if (requestedUsageIndex > nextUsageIndex) {
      return rejected("sequence_gap");
    }
  }

  return {
    transition: "usage_state_advanced",
    next_usage_state: {
      proof_id: expectedProofId,
      consumed_usage_count: consumedUsageCount + 1,
      state_version: stateVersion + 1,
    },
  };
}
