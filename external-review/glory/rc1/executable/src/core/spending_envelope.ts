/**
 * mindchain-mvp - SpendingEnvelope candidate reservation foundation (Day 72)
 *
 * This module calculates deterministic candidate economic-capacity reservation
 * transitions from caller-supplied state. It does not commit a reservation,
 * perform admission, consume proof usage or tokens, transfer payment, or settle.
 * Candidate next SpendingEnvelope state != committed economic state.
 */

import type { AuthorizationProof, UUID } from "./contracts.js";
import {
  deriveAuthorizationProofId,
  snapshotAuthorizationProof,
} from "./authorization_proof.js";

export interface SpendingEnvelope {
  spending_envelope_id: UUID;
  authorization_decision_id: UUID;
  principal_id: UUID;
  asset_id: string;
  maximum_amount: string;
  wallet_or_economic_epoch: number;
}

export interface SpendingEnvelopeState {
  spending_envelope_id: SpendingEnvelope["spending_envelope_id"];
  authorization_decision_id: SpendingEnvelope["authorization_decision_id"];
  principal_id: SpendingEnvelope["principal_id"];
  asset_id: SpendingEnvelope["asset_id"];
  maximum_amount: SpendingEnvelope["maximum_amount"];
  wallet_or_economic_epoch: SpendingEnvelope["wallet_or_economic_epoch"];
  reserved_amount: string;
  /**
   * Version of this candidate mutable economic-capacity state. It advances once
   * per successful V1 candidate reservation and establishes no compare-and-swap,
   * freshness, persistence, concurrency exclusion, authoritative state, or
   * authoritative commit semantics.
   */
  state_version: number;
}

export interface TransitionSpendingEnvelopeReservationInput {
  proof: AuthorizationProof;
  envelope: SpendingEnvelope;
  current_envelope_state: SpendingEnvelopeState | null;
  requested_amount: string;
}

export type SpendingEnvelopeReservationTransitionFailureReason =
  | "structural_invalid"
  | "proof_id_mismatch"
  | "proof_economic_scope_mismatch"
  | "envelope_state_invalid"
  | "envelope_state_mismatch"
  | "capacity_exhausted"
  | "requested_amount_exceeds_ceiling"
  | "insufficient_remaining_capacity"
  | "state_version_exhausted";

export type SpendingEnvelopeReservationTransitionResult =
  | {
      transition: "spending_envelope_state_advanced";
      next_spending_envelope_state: SpendingEnvelopeState;
    }
  | {
      transition: "spending_envelope_state_rejected";
      reason: SpendingEnvelopeReservationTransitionFailureReason;
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

type IsAny<Value> = 0 extends 1 & Value ? true : false;

type CheckIsValid<Check> = IsAny<Check> extends true
  ? false
  : [Check] extends [never]
    ? false
    : [Check] extends [true]
      ? true
      : false;

type ExactUnionInventory<Declared, Inventoried> = IsAny<Declared> extends true
  ? false
  : IsAny<Inventoried> extends true
    ? false
    : [Exclude<Declared, Inventoried>] extends [never]
      ? [Exclude<Inventoried, Declared>] extends [never]
        ? true
        : false
      : false;

type ExactType<Actual, Expected> = IsAny<Actual> extends true
  ? false
  : IsAny<Expected> extends true
    ? false
    : [Actual] extends [never]
      ? false
      : [Expected] extends [never]
        ? false
        : [Actual] extends [Expected]
          ? [Expected] extends [Actual]
            ? true
            : false
          : false;

type AssertAllTrue<Checks extends readonly true[]> = Checks;

type ExactRequiredKeyInventory<Value, Inventoried> = IsAny<Value> extends true
  ? false
  : ExactUnionInventory<keyof Value, Inventoried> extends true
    ? ExactUnionInventory<OptionalKeys<Value>, never> extends true
      ? true
      : false
    : false;

type ResultMemberIsValid<Member> = IsAny<Member> extends true
  ? false
  : Member extends { transition: infer Transition }
    ? ExactType<
        Transition,
        "spending_envelope_state_advanced"
      > extends true
      ? ExactRequiredKeyInventory<
          Member,
          "transition" | "next_spending_envelope_state"
        > extends true
        ? Member extends {
            next_spending_envelope_state: infer NextSpendingEnvelopeState;
          }
          ? ExactType<NextSpendingEnvelopeState, SpendingEnvelopeState>
          : false
        : false
      : ExactType<
            Transition,
            "spending_envelope_state_rejected"
          > extends true
        ? ExactRequiredKeyInventory<Member, "transition" | "reason"> extends true
          ? Member extends { reason: infer Reason }
            ? ExactType<
                Reason,
                SpendingEnvelopeReservationTransitionFailureReason
              >
            : false
          : false
        : false
    : false;

type DistributedResultMemberChecks<Result> = Result extends unknown
  ? ResultMemberIsValid<Result>
  : never;

type AllDistributedChecksTrue<Checks> = IsAny<Checks> extends true
  ? false
  : [Checks] extends [never]
    ? false
    : false extends Checks
      ? false
      : [Checks] extends [true]
        ? true
        : false;

const SPENDING_ENVELOPE_KEYS = [
  "spending_envelope_id",
  "authorization_decision_id",
  "principal_id",
  "asset_id",
  "maximum_amount",
  "wallet_or_economic_epoch",
] as const satisfies readonly (keyof SpendingEnvelope)[];

const SPENDING_ENVELOPE_STATE_KEYS = [
  "spending_envelope_id",
  "authorization_decision_id",
  "principal_id",
  "asset_id",
  "maximum_amount",
  "wallet_or_economic_epoch",
  "reserved_amount",
  "state_version",
] as const satisfies readonly (keyof SpendingEnvelopeState)[];

const TRANSITION_SPENDING_ENVELOPE_RESERVATION_INPUT_KEYS = [
  "proof",
  "envelope",
  "current_envelope_state",
  "requested_amount",
] as const satisfies readonly (keyof TransitionSpendingEnvelopeReservationInput)[];

type ReviewedFailureReason =
  | "structural_invalid"
  | "proof_id_mismatch"
  | "proof_economic_scope_mismatch"
  | "envelope_state_invalid"
  | "envelope_state_mismatch"
  | "capacity_exhausted"
  | "requested_amount_exceeds_ceiling"
  | "insufficient_remaining_capacity"
  | "state_version_exhausted";

type ReviewedTransition =
  | "spending_envelope_state_advanced"
  | "spending_envelope_state_rejected";

type SpendingEnvelopeInventoryChecks = AssertAllTrue<[
  CheckIsValid<
    ExactKeyInventory<SpendingEnvelope, typeof SPENDING_ENVELOPE_KEYS>
  >,
  ExactUnionInventory<OptionalKeys<SpendingEnvelope>, never>,
  CheckIsValid<
    ExactKeyInventory<
      SpendingEnvelopeState,
      typeof SPENDING_ENVELOPE_STATE_KEYS
    >
  >,
  ExactUnionInventory<OptionalKeys<SpendingEnvelopeState>, never>,
  CheckIsValid<
    ExactKeyInventory<
      TransitionSpendingEnvelopeReservationInput,
      typeof TRANSITION_SPENDING_ENVELOPE_RESERVATION_INPUT_KEYS
    >
  >,
  ExactUnionInventory<
    OptionalKeys<TransitionSpendingEnvelopeReservationInput>,
    never
  >,
  ExactUnionInventory<
    SpendingEnvelopeReservationTransitionFailureReason,
    ReviewedFailureReason
  >,
  ExactUnionInventory<
    SpendingEnvelopeReservationTransitionResult["transition"],
    ReviewedTransition
  >,
  AllDistributedChecksTrue<
    DistributedResultMemberChecks<SpendingEnvelopeReservationTransitionResult>
  >,
]>;

const AMOUNT_PATTERN = /^[1-9][0-9]*$/;

class StructuralInputError extends Error {}
class EnvelopeStateInputError extends Error {}

function structuralFail(field: string, reason: string): never {
  throw new StructuralInputError(`spending_envelope_${field}_${reason}`);
}

function envelopeStateFail(field: string, reason: string): never {
  throw new EnvelopeStateInputError(
    `spending_envelope_state_${field}_${reason}`
  );
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

function assertObject(
  value: unknown,
  field: string,
  fail: (field: string, reason: string) => never
): asserts value is Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(field, "invalid");
  }
}

function captureExactDataProperties(
  value: unknown,
  requiredKeys: readonly string[],
  field: string,
  fail: (field: string, reason: string) => never
): Record<string, unknown> {
  assertObject(value, field, fail);
  const descriptors = Object.getOwnPropertyDescriptors(value);

  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") fail(field, "symbol_unsupported");
    if (!requiredKeys.includes(key)) fail(`${field}.${key}`, "unsupported");
  }

  const captured = Object.create(null) as Record<string, unknown>;
  for (const key of requiredKeys) {
    if (!own(descriptors, key)) fail(`${field}.${key}`, "required");
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

function assertOpaqueNonblankString(
  value: unknown,
  field: string,
  fail: (field: string, reason: string) => never
): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) {
    fail(field, "invalid");
  }
}

function assertCanonicalAmount(
  value: unknown,
  field: string,
  fail: (field: string, reason: string) => never
): asserts value is string {
  if (typeof value !== "string" || !AMOUNT_PATTERN.test(value)) {
    fail(field, "invalid");
  }
}

function assertNonnegativeSafeInteger(
  value: unknown,
  field: string,
  fail: (field: string, reason: string) => never
): asserts value is number {
  if (
    typeof value !== "number" ||
    !Number.isSafeInteger(value) ||
    value < 0
  ) {
    fail(field, "invalid");
  }
}

function snapshotEnvelope(value: unknown): SpendingEnvelope {
  const captured = captureExactDataProperties(
    value,
    SPENDING_ENVELOPE_KEYS,
    "envelope",
    structuralFail
  );
  assertOpaqueNonblankString(
    captured.spending_envelope_id,
    "envelope.spending_envelope_id",
    structuralFail
  );
  assertOpaqueNonblankString(
    captured.authorization_decision_id,
    "envelope.authorization_decision_id",
    structuralFail
  );
  assertOpaqueNonblankString(
    captured.principal_id,
    "envelope.principal_id",
    structuralFail
  );
  assertOpaqueNonblankString(
    captured.asset_id,
    "envelope.asset_id",
    structuralFail
  );
  assertCanonicalAmount(
    captured.maximum_amount,
    "envelope.maximum_amount",
    structuralFail
  );
  assertNonnegativeSafeInteger(
    captured.wallet_or_economic_epoch,
    "envelope.wallet_or_economic_epoch",
    structuralFail
  );

  return {
    spending_envelope_id: captured.spending_envelope_id,
    authorization_decision_id: captured.authorization_decision_id,
    principal_id: captured.principal_id,
    asset_id: captured.asset_id,
    maximum_amount: captured.maximum_amount,
    wallet_or_economic_epoch: captured.wallet_or_economic_epoch,
  };
}

function snapshotIntrinsicEnvelopeState(value: unknown): SpendingEnvelopeState {
  const captured = captureExactDataProperties(
    value,
    SPENDING_ENVELOPE_STATE_KEYS,
    "state",
    envelopeStateFail
  );
  assertOpaqueNonblankString(
    captured.spending_envelope_id,
    "spending_envelope_id",
    envelopeStateFail
  );
  assertOpaqueNonblankString(
    captured.authorization_decision_id,
    "authorization_decision_id",
    envelopeStateFail
  );
  assertOpaqueNonblankString(
    captured.principal_id,
    "principal_id",
    envelopeStateFail
  );
  assertOpaqueNonblankString(
    captured.asset_id,
    "asset_id",
    envelopeStateFail
  );
  assertCanonicalAmount(
    captured.maximum_amount,
    "maximum_amount",
    envelopeStateFail
  );
  assertNonnegativeSafeInteger(
    captured.wallet_or_economic_epoch,
    "wallet_or_economic_epoch",
    envelopeStateFail
  );
  assertCanonicalAmount(
    captured.reserved_amount,
    "reserved_amount",
    envelopeStateFail
  );
  if (
    typeof captured.state_version !== "number" ||
    !Number.isSafeInteger(captured.state_version) ||
    captured.state_version < 1
  ) {
    envelopeStateFail("state_version", "invalid");
  }
  if (BigInt(captured.reserved_amount) > BigInt(captured.maximum_amount)) {
    envelopeStateFail("reserved_amount", "exceeds_maximum");
  }

  return {
    spending_envelope_id: captured.spending_envelope_id,
    authorization_decision_id: captured.authorization_decision_id,
    principal_id: captured.principal_id,
    asset_id: captured.asset_id,
    maximum_amount: captured.maximum_amount,
    wallet_or_economic_epoch: captured.wallet_or_economic_epoch,
    reserved_amount: captured.reserved_amount,
    state_version: captured.state_version,
  };
}

function stateMatchesEnvelope(
  state: SpendingEnvelopeState,
  envelope: SpendingEnvelope
): boolean {
  return (
    state.spending_envelope_id === envelope.spending_envelope_id &&
    state.authorization_decision_id === envelope.authorization_decision_id &&
    state.principal_id === envelope.principal_id &&
    state.asset_id === envelope.asset_id &&
    state.maximum_amount === envelope.maximum_amount &&
    state.wallet_or_economic_epoch === envelope.wallet_or_economic_epoch
  );
}

function rejected(
  reason: SpendingEnvelopeReservationTransitionFailureReason
): SpendingEnvelopeReservationTransitionResult {
  return {
    transition: "spending_envelope_state_rejected",
    reason,
  };
}

function isExpectedProofStructuralFailure(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith("authorization_proof_");
}

/**
 * Calculates a fresh candidate cumulative reservation from explicit caller
 * state. Day 72 local eligibility != authoritative reservation; reservation !=
 * payment, token transfer, or settlement. Day 73 owns authoritative atomic
 * coordination and commit.
 *
 * The passive-data guarantee covers ordinary data objects, not adversarial
 * Proxy/meta-object traps; Object.getOwnPropertyDescriptors can invoke traps.
 */
export function transitionSpendingEnvelopeReservation(
  input: TransitionSpendingEnvelopeReservationInput
): SpendingEnvelopeReservationTransitionResult {
  let proof: AuthorizationProof;
  let envelope: SpendingEnvelope;
  let currentEnvelopeStateValue: unknown;
  let requestedAmount: string;

  try {
    const capturedInput = captureExactDataProperties(
      input,
      TRANSITION_SPENDING_ENVELOPE_RESERVATION_INPUT_KEYS,
      "input",
      structuralFail
    );
    assertCanonicalAmount(
      capturedInput.requested_amount,
      "requested_amount",
      structuralFail
    );
    requestedAmount = capturedInput.requested_amount;
    currentEnvelopeStateValue = capturedInput.current_envelope_state;
    envelope = snapshotEnvelope(capturedInput.envelope);
    proof = snapshotAuthorizationProof(
      capturedInput.proof as TransitionSpendingEnvelopeReservationInput["proof"]
    );
  } catch (error) {
    if (
      error instanceof StructuralInputError ||
      isExpectedProofStructuralFailure(error)
    ) {
      return rejected("structural_invalid");
    }
    throw error;
  }

  let expectedProofId: AuthorizationProof["proof_id"];
  try {
    expectedProofId = deriveAuthorizationProofId(proof.payload);
  } catch (error) {
    if (isExpectedProofStructuralFailure(error)) {
      return rejected("structural_invalid");
    }
    throw error;
  }
  if (proof.proof_id !== expectedProofId) {
    return rejected("proof_id_mismatch");
  }

  const economicScope = proof.payload.economic_scope;
  if (
    economicScope.mode !== "bounded" ||
    economicScope.spending_envelope_id !== envelope.spending_envelope_id ||
    proof.payload.authorization_decision_id !==
      envelope.authorization_decision_id ||
    proof.payload.principal_id !== envelope.principal_id ||
    economicScope.asset_id !== envelope.asset_id ||
    economicScope.maximum_amount !== envelope.maximum_amount ||
    economicScope.wallet_or_economic_epoch !==
      envelope.wallet_or_economic_epoch
  ) {
    return rejected("proof_economic_scope_mismatch");
  }

  let currentEnvelopeState: SpendingEnvelopeState | null;
  if (currentEnvelopeStateValue === null) {
    currentEnvelopeState = null;
  } else {
    try {
      currentEnvelopeState = snapshotIntrinsicEnvelopeState(
        currentEnvelopeStateValue
      );
    } catch (error) {
      if (error instanceof EnvelopeStateInputError) {
        return rejected("envelope_state_invalid");
      }
      throw error;
    }
  }

  if (
    currentEnvelopeState !== null &&
    !stateMatchesEnvelope(currentEnvelopeState, envelope)
  ) {
    return rejected("envelope_state_mismatch");
  }

  const maximumAmount = BigInt(envelope.maximum_amount);
  const reservedAmount = BigInt(
    currentEnvelopeState?.reserved_amount ?? "0"
  );
  const requestedAmountValue = BigInt(requestedAmount);
  if (reservedAmount === maximumAmount) {
    return rejected("capacity_exhausted");
  }
  if (requestedAmountValue > maximumAmount) {
    return rejected("requested_amount_exceeds_ceiling");
  }
  if (requestedAmountValue > maximumAmount - reservedAmount) {
    return rejected("insufficient_remaining_capacity");
  }

  const stateVersion = currentEnvelopeState?.state_version ?? 0;
  if (stateVersion === Number.MAX_SAFE_INTEGER) {
    return rejected("state_version_exhausted");
  }

  return {
    transition: "spending_envelope_state_advanced",
    next_spending_envelope_state: {
      spending_envelope_id: envelope.spending_envelope_id,
      authorization_decision_id: envelope.authorization_decision_id,
      principal_id: envelope.principal_id,
      asset_id: envelope.asset_id,
      maximum_amount: envelope.maximum_amount,
      wallet_or_economic_epoch: envelope.wallet_or_economic_epoch,
      reserved_amount: (reservedAmount + requestedAmountValue).toString(),
      state_version: stateVersion + 1,
    },
  };
}
