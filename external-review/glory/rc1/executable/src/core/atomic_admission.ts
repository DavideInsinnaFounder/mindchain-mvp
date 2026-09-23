import type { AuthorizationProof, UUID } from "./contracts.js";
import {
  deriveAuthorizationProofId,
  snapshotAuthorizationProof,
} from "./authorization_proof.js";
import type {
  LocalAuthorizationProofVerificationFailureReason,
  LocalAuthorizationProofVerificationResult,
} from "./authorization_proof_verification.js";
import {
  transitionAuthorizationProofUsage,
  type AuthorizationProofUsageState,
  type AuthorizationProofUsageTransitionFailureReason,
} from "./authorization_proof_usage.js";
import {
  transitionSpendingEnvelopeReservation,
  type SpendingEnvelope,
  type SpendingEnvelopeReservationTransitionFailureReason,
  type SpendingEnvelopeState,
} from "./spending_envelope.js";

export interface CommitAuthorizationAdmissionInput {
  admission_id: UUID;
  proof: AuthorizationProof;
  local_verification: LocalAuthorizationProofVerificationResult;
  requested_usage_index: number;
  execution_request:
    | {
        mode: "exact";
        execution_attempt_id: UUID;
        operation_type: string;
      }
    | {
        mode: "bounded";
        execution_attempt_id: UUID;
        operation_type: string;
        capability_id: string;
      };
  economic_request:
    | { mode: "none" }
    | {
        mode: "bounded";
        envelope: SpendingEnvelope;
        requested_amount: string;
      };
}

export interface AdmissionRecord {
  admission_id: UUID;
  proof_id: AuthorizationProof["proof_id"];
  execution_attempt_id: UUID;
  requested_usage_index: number;
  authorization_decision_id: UUID;
  principal_id: UUID;
  spending_envelope_id: UUID | null;
  requested_amount: string | null;
  proof_usage_state_version: number;
  spending_envelope_state_version: number | null;
  outbox_record_id: UUID;
}

export interface AdmissionOutboxRecord {
  outbox_record_id: UUID;
  admission_id: AdmissionRecord["admission_id"];
  event_type: "authorization_admission_committed";
  proof_id: AdmissionRecord["proof_id"];
  execution_attempt_id: AdmissionRecord["execution_attempt_id"];
  spending_envelope_id: AdmissionRecord["spending_envelope_id"];
  proof_usage_state_version: AdmissionRecord["proof_usage_state_version"];
  spending_envelope_state_version: AdmissionRecord["spending_envelope_state_version"];
}

export type AtomicAdmissionFailure =
  | { reason: "structural_invalid" }
  | { reason: "proof_id_mismatch" }
  | { reason: "admission_conflict" }
  | {
      reason: "local_verification_rejected";
      local_verification_reason: LocalAuthorizationProofVerificationFailureReason;
    }
  | { reason: "local_verification_proof_mismatch" }
  | { reason: "execution_attempt_mismatch" }
  | {
      reason: "proof_usage_rejected";
      proof_usage_reason: AuthorizationProofUsageTransitionFailureReason;
    }
  | { reason: "spending_envelope_required" }
  | { reason: "spending_envelope_unexpected" }
  | {
      reason: "spending_envelope_rejected";
      spending_envelope_reason: SpendingEnvelopeReservationTransitionFailureReason;
    };

export type CommitAuthorizationAdmissionResult =
  | {
      admission: "admission_committed";
      admission_record: AdmissionRecord;
      outbox_record: AdmissionOutboxRecord;
      committed_proof_usage_state: AuthorizationProofUsageState;
      committed_spending_envelope_state: SpendingEnvelopeState | null;
    }
  | {
      admission: "admission_replayed";
      admission_record: AdmissionRecord;
      outbox_record: AdmissionOutboxRecord;
      committed_proof_usage_state: AuthorizationProofUsageState;
      committed_spending_envelope_state: SpendingEnvelopeState | null;
    }
  | {
      admission: "admission_rejected";
      failure: AtomicAdmissionFailure;
    };

export interface AtomicAdmissionAuthority {
  commitAuthorizationAdmission(
    input: CommitAuthorizationAdmissionInput
  ): CommitAuthorizationAdmissionResult;
  getProofUsageState(
    proof_id: AuthorizationProof["proof_id"]
  ): AuthorizationProofUsageState | null;
  getSpendingEnvelopeState(
    spending_envelope_id: SpendingEnvelope["spending_envelope_id"]
  ): SpendingEnvelopeState | null;
  getAdmissionRecord(
    admission_id: AdmissionRecord["admission_id"]
  ): AdmissionRecord | undefined;
  getAdmissionOutboxRecord(
    outbox_record_id: AdmissionOutboxRecord["outbox_record_id"]
  ): AdmissionOutboxRecord | undefined;
}

type IsAny<Value> = 0 extends 1 & Value ? true : false;
type CheckIsValid<Check> = IsAny<Check> extends true
  ? false
  : [Check] extends [never]
    ? false
    : [Check] extends [true]
      ? true
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
type ExactUnionInventory<Declared, Reviewed> = IsAny<Declared> extends true
  ? false
  : IsAny<Reviewed> extends true
    ? false
    : [Exclude<Declared, Reviewed>] extends [never]
      ? [Exclude<Reviewed, Declared>] extends [never]
        ? true
        : false
      : false;
type ExactKeyInventory<
  Value,
  Inventory extends readonly PropertyKey[],
> = Exclude<keyof Value, Inventory[number]> extends never
  ? Exclude<Inventory[number], keyof Value> extends never
    ? true
    : false
  : false;
type OptionalKeys<Value> = {
  [Key in keyof Value]-?: object extends Pick<Value, Key> ? Key : never;
}[keyof Value];
type ExactRequiredKeyInventory<Value, Keys extends PropertyKey> =
  ExactUnionInventory<keyof Value, Keys> extends true
    ? ExactUnionInventory<OptionalKeys<Value>, never>
    : false;
type AssertAllTrue<Checks extends readonly true[]> = Checks;
type AllDistributedChecksTrue<Checks> = IsAny<Checks> extends true
  ? false
  : [Checks] extends [never]
    ? false
    : false extends Checks
      ? false
      : [Checks] extends [true]
        ? true
        : false;
type ExactTupleElementTypes<
  Actual extends readonly unknown[],
  Expected extends readonly unknown[],
> = Actual extends readonly []
  ? Expected extends readonly [] ? true : false
  : Actual extends readonly [infer ActualHead, ...infer ActualTail]
    ? Expected extends readonly [infer ExpectedHead, ...infer ExpectedTail]
      ? ExactType<ActualHead, ExpectedHead> extends true
        ? ExactTupleElementTypes<ActualTail, ExpectedTail>
        : false
      : false
    : false;

type DiscriminantShapeInventory<Mode extends PropertyKey> = {
  readonly [Value in Mode]: readonly string[];
};
type AssociationIsValid<Association> = [Association] extends [never]
  ? false
  : [Association] extends [true]
    ? true
    : false;
type KeyedDiscriminantShapeAssociations<
  Union,
  Discriminant extends keyof Union,
  Shapes extends DiscriminantShapeInventory<Extract<Union[Discriminant], PropertyKey>>,
> = {
  [Mode in Extract<Union[Discriminant], PropertyKey>]: AssociationIsValid<
    ExactKeyInventory<
      Extract<Union, Record<Discriminant, Mode>>,
      Shapes[Mode]
    >
  >;
};
type AssertAllAssociationsTrue<
  Associations extends { [Mode in keyof Associations]: true },
> = Associations;

const COMMIT_INPUT_KEYS = [
  "admission_id",
  "proof",
  "local_verification",
  "requested_usage_index",
  "execution_request",
  "economic_request",
] as const satisfies readonly (keyof CommitAuthorizationAdmissionInput)[];
const EXACT_EXECUTION_REQUEST_KEYS = [
  "mode",
  "execution_attempt_id",
  "operation_type",
] as const;
const BOUNDED_EXECUTION_REQUEST_KEYS = [
  "mode",
  "execution_attempt_id",
  "operation_type",
  "capability_id",
] as const;
const EXECUTION_REQUEST_SHAPES = {
  exact: EXACT_EXECUTION_REQUEST_KEYS,
  bounded: BOUNDED_EXECUTION_REQUEST_KEYS,
} as const satisfies DiscriminantShapeInventory<
  CommitAuthorizationAdmissionInput["execution_request"]["mode"]
>;
type ExecutionRequestShapeAssociationsChecked = AssertAllAssociationsTrue<
  KeyedDiscriminantShapeAssociations<
    CommitAuthorizationAdmissionInput["execution_request"],
    "mode",
    typeof EXECUTION_REQUEST_SHAPES
  >
>;
const NONE_ECONOMIC_REQUEST_KEYS = ["mode"] as const;
const BOUNDED_ECONOMIC_REQUEST_KEYS = [
  "mode",
  "envelope",
  "requested_amount",
] as const;
const ECONOMIC_REQUEST_SHAPES = {
  none: NONE_ECONOMIC_REQUEST_KEYS,
  bounded: BOUNDED_ECONOMIC_REQUEST_KEYS,
} as const satisfies DiscriminantShapeInventory<
  CommitAuthorizationAdmissionInput["economic_request"]["mode"]
>;
type EconomicRequestShapeAssociationsChecked = AssertAllAssociationsTrue<
  KeyedDiscriminantShapeAssociations<
    CommitAuthorizationAdmissionInput["economic_request"],
    "mode",
    typeof ECONOMIC_REQUEST_SHAPES
  >
>;
const VERIFIED_LOCALLY_KEYS = ["verification", "proof_id"] as const;
const NOT_VERIFIED_KEYS = ["verification", "reason"] as const;
type ReviewedLocalVerificationFailureReasons = readonly [
  "structural_invalid",
  "proof_id_mismatch",
  "unsupported_algorithm",
  "verification_material_mismatch",
  "invalid_verification_material",
  "invalid_signature",
];
const LOCAL_VERIFICATION_FAILURE_REASONS = [
  "structural_invalid",
  "proof_id_mismatch",
  "unsupported_algorithm",
  "verification_material_mismatch",
  "invalid_verification_material",
  "invalid_signature",
] as const satisfies ReviewedLocalVerificationFailureReasons;
const LOCAL_VERIFICATION_SHAPES = {
  verified_locally: VERIFIED_LOCALLY_KEYS,
  not_verified: NOT_VERIFIED_KEYS,
} as const satisfies DiscriminantShapeInventory<
  LocalAuthorizationProofVerificationResult["verification"]
>;
type LocalVerificationShapeAssociationsChecked = AssertAllAssociationsTrue<
  KeyedDiscriminantShapeAssociations<
    LocalAuthorizationProofVerificationResult,
    "verification",
    typeof LOCAL_VERIFICATION_SHAPES
  >
>;
const ENVELOPE_KEYS = [
  "spending_envelope_id",
  "authorization_decision_id",
  "principal_id",
  "asset_id",
  "maximum_amount",
  "wallet_or_economic_epoch",
] as const satisfies readonly (keyof SpendingEnvelope)[];
type ReviewedAdmissionRecordKey =
  | "admission_id"
  | "proof_id"
  | "execution_attempt_id"
  | "requested_usage_index"
  | "authorization_decision_id"
  | "principal_id"
  | "spending_envelope_id"
  | "requested_amount"
  | "proof_usage_state_version"
  | "spending_envelope_state_version"
  | "outbox_record_id";
type ReviewedOutboxRecordKey =
  | "outbox_record_id"
  | "admission_id"
  | "event_type"
  | "proof_id"
  | "execution_attempt_id"
  | "spending_envelope_id"
  | "proof_usage_state_version"
  | "spending_envelope_state_version";

type ReviewedFailureReason =
  | "structural_invalid"
  | "proof_id_mismatch"
  | "admission_conflict"
  | "local_verification_rejected"
  | "local_verification_proof_mismatch"
  | "execution_attempt_mismatch"
  | "proof_usage_rejected"
  | "spending_envelope_required"
  | "spending_envelope_unexpected"
  | "spending_envelope_rejected";
type SimpleFailureReason = Exclude<
  ReviewedFailureReason,
  | "local_verification_rejected"
  | "proof_usage_rejected"
  | "spending_envelope_rejected"
>;
type IsExactSimpleFailureReason<Reason> =
  ExactType<Reason, "structural_invalid"> extends true ? true
    : ExactType<Reason, "proof_id_mismatch"> extends true ? true
      : ExactType<Reason, "admission_conflict"> extends true ? true
        : ExactType<Reason, "local_verification_proof_mismatch"> extends true ? true
          : ExactType<Reason, "execution_attempt_mismatch"> extends true ? true
            : ExactType<Reason, "spending_envelope_required"> extends true ? true
              : ExactType<Reason, "spending_envelope_unexpected"> extends true ? true
                : false;
type FailureMemberIsValid<Member> = IsAny<Member> extends true
  ? false
  : Member extends { reason: infer Reason }
    ? ExactType<Reason, "local_verification_rejected"> extends true
      ? ExactRequiredKeyInventory<Member, "reason" | "local_verification_reason"> extends true
        ? Member extends { local_verification_reason: infer Nested }
          ? ExactType<Nested, LocalAuthorizationProofVerificationFailureReason>
          : false
        : false
      : ExactType<Reason, "proof_usage_rejected"> extends true
        ? ExactRequiredKeyInventory<Member, "reason" | "proof_usage_reason"> extends true
          ? Member extends { proof_usage_reason: infer Nested }
            ? ExactType<Nested, AuthorizationProofUsageTransitionFailureReason>
            : false
          : false
        : ExactType<Reason, "spending_envelope_rejected"> extends true
          ? ExactRequiredKeyInventory<Member, "reason" | "spending_envelope_reason"> extends true
            ? Member extends { spending_envelope_reason: infer Nested }
              ? ExactType<Nested, SpendingEnvelopeReservationTransitionFailureReason>
              : false
            : false
          : Reason extends SimpleFailureReason
            ? IsExactSimpleFailureReason<Reason> extends true
              ? ExactRequiredKeyInventory<Member, "reason">
              : false
            : false
    : false;
type DistributedFailureChecks<Failure> = Failure extends unknown
  ? FailureMemberIsValid<Failure>
  : never;

type ResultMemberIsValid<Member> = IsAny<Member> extends true
  ? false
  : Member extends { admission: infer Admission }
    ? ExactType<Admission, "admission_committed"> extends true
      ? ExactRequiredKeyInventory<
          Member,
          | "admission"
          | "admission_record"
          | "outbox_record"
          | "committed_proof_usage_state"
          | "committed_spending_envelope_state"
        > extends true
        ? Member extends {
            admission_record: infer RecordValue;
            outbox_record: infer OutboxValue;
            committed_proof_usage_state: infer ProofState;
            committed_spending_envelope_state: infer EnvelopeState;
          }
          ? ExactType<RecordValue, AdmissionRecord> extends true
            ? ExactType<OutboxValue, AdmissionOutboxRecord> extends true
              ? ExactType<ProofState, AuthorizationProofUsageState> extends true
                ? ExactType<EnvelopeState, SpendingEnvelopeState | null>
                : false
              : false
            : false
          : false
        : false
      : ExactType<Admission, "admission_replayed"> extends true
        ? ExactRequiredKeyInventory<
            Member,
            | "admission"
            | "admission_record"
            | "outbox_record"
            | "committed_proof_usage_state"
            | "committed_spending_envelope_state"
          > extends true
          ? Member extends {
              admission_record: infer RecordValue;
              outbox_record: infer OutboxValue;
              committed_proof_usage_state: infer ProofState;
              committed_spending_envelope_state: infer EnvelopeState;
            }
            ? ExactType<RecordValue, AdmissionRecord> extends true
              ? ExactType<OutboxValue, AdmissionOutboxRecord> extends true
                ? ExactType<ProofState, AuthorizationProofUsageState> extends true
                  ? ExactType<EnvelopeState, SpendingEnvelopeState | null>
                  : false
                : false
              : false
            : false
          : false
        : ExactType<Admission, "admission_rejected"> extends true
        ? ExactRequiredKeyInventory<Member, "admission" | "failure"> extends true
          ? Member extends { failure: infer Failure }
            ? ExactType<Failure, AtomicAdmissionFailure>
            : false
          : false
          : false
    : false;
type DistributedResultChecks<Result> = Result extends unknown
  ? ResultMemberIsValid<Result>
  : never;

type ReviewedNoneFingerprintTuple = readonly [
  domain: "atomic-admission-request",
  version: "v1",
  admission_id: UUID,
  proof_id: AuthorizationProof["proof_id"],
  execution_mode: "exact" | "bounded",
  execution_attempt_id: UUID,
  operation_type: string,
  capability_id: string | null,
  requested_usage_index: number,
  economic_mode: "none",
  spending_envelope_id: null,
  authorization_decision_id: null,
  principal_id: null,
  asset_id: null,
  maximum_amount: null,
  wallet_or_economic_epoch: null,
  requested_amount: null,
];
type ReviewedBoundedFingerprintTuple = readonly [
  domain: "atomic-admission-request",
  version: "v1",
  admission_id: UUID,
  proof_id: AuthorizationProof["proof_id"],
  execution_mode: "exact" | "bounded",
  execution_attempt_id: UUID,
  operation_type: string,
  capability_id: string | null,
  requested_usage_index: number,
  economic_mode: "bounded",
  spending_envelope_id: UUID,
  authorization_decision_id: UUID,
  principal_id: UUID,
  asset_id: string,
  maximum_amount: string,
  wallet_or_economic_epoch: number,
  requested_amount: string,
];
type ReviewedFingerprintTuple =
  | ReviewedNoneFingerprintTuple
  | ReviewedBoundedFingerprintTuple;
type FingerprintTupleMemberIsValid<Member> = IsAny<Member> extends true
  ? false
  : Member extends readonly unknown[]
    ? ExactTupleElementTypes<Member, ReviewedNoneFingerprintTuple> extends true
      ? true
      : ExactTupleElementTypes<Member, ReviewedBoundedFingerprintTuple>
    : false;
type DistributedFingerprintTupleChecks<FingerprintTuple> =
  FingerprintTuple extends unknown
    ? FingerprintTupleMemberIsValid<FingerprintTuple>
    : never;
declare const ADMISSION_REQUEST_FINGERPRINT_BRAND: unique symbol;
type AdmissionRequestFingerprint = string & {
  readonly [ADMISSION_REQUEST_FINGERPRINT_BRAND]: "serialized_admission_request";
};

type ExactMapType<
  Actual,
  ExpectedKey,
  ExpectedValue,
> = IsAny<Actual> extends true
  ? false
  : [Actual] extends [never]
    ? false
    : Actual extends Map<infer ActualKey, infer ActualValue>
      ? IsAny<ActualKey> extends true
        ? false
        : IsAny<ActualValue> extends true
          ? false
          : ExactType<ActualKey, ExpectedKey> extends true
            ? ExactType<ActualValue, ExpectedValue> extends true
              ? ExactType<Actual, Map<ExpectedKey, ExpectedValue>>
              : false
            : false
      : false;

interface StoredAdmission {
  fingerprint: AdmissionRequestFingerprint;
  admission_record: AdmissionRecord;
  outbox_record: AdmissionOutboxRecord;
  committed_proof_usage_state: AuthorizationProofUsageState;
  committed_spending_envelope_state: SpendingEnvelopeState | null;
}
interface AtomicAdmissionAggregateState {
  proof_usage_states: Map<UUID, AuthorizationProofUsageState>;
  spending_envelope_states: Map<UUID, SpendingEnvelopeState>;
  admissions: Map<UUID, StoredAdmission>;
  outbox_records: Map<UUID, AdmissionOutboxRecord>;
}
type PreparedAtomicAdmissionOutcome =
  | readonly [
      kind: "result",
      result: CommitAuthorizationAdmissionResult,
    ]
  | readonly [
      kind: "commit",
      next_state: AtomicAdmissionAggregateState,
      result: CommitAuthorizationAdmissionResult,
    ];
type ReviewedAuthority = {
  commitAuthorizationAdmission(input: CommitAuthorizationAdmissionInput): CommitAuthorizationAdmissionResult;
  getProofUsageState(proof_id: AuthorizationProof["proof_id"]): AuthorizationProofUsageState | null;
  getSpendingEnvelopeState(spending_envelope_id: SpendingEnvelope["spending_envelope_id"]): SpendingEnvelopeState | null;
  getAdmissionRecord(admission_id: AdmissionRecord["admission_id"]): AdmissionRecord | undefined;
  getAdmissionOutboxRecord(outbox_record_id: AdmissionOutboxRecord["outbox_record_id"]): AdmissionOutboxRecord | undefined;
};
type ExactExecutionRequest = Extract<
  CommitAuthorizationAdmissionInput["execution_request"],
  { mode: "exact" }
>;
type BoundedExecutionRequest = Extract<
  CommitAuthorizationAdmissionInput["execution_request"],
  { mode: "bounded" }
>;
type NoneEconomicRequest = Extract<
  CommitAuthorizationAdmissionInput["economic_request"],
  { mode: "none" }
>;
type BoundedEconomicRequest = Extract<
  CommitAuthorizationAdmissionInput["economic_request"],
  { mode: "bounded" }
>;
type AtomicAdmissionInventoryChecks = AssertAllTrue<[
  CheckIsValid<ExactKeyInventory<CommitAuthorizationAdmissionInput, typeof COMMIT_INPUT_KEYS>>,
  ExactUnionInventory<OptionalKeys<CommitAuthorizationAdmissionInput>, never>,
  ExactType<CommitAuthorizationAdmissionInput["admission_id"], UUID>,
  ExactType<CommitAuthorizationAdmissionInput["proof"], AuthorizationProof>,
  ExactType<CommitAuthorizationAdmissionInput["local_verification"], LocalAuthorizationProofVerificationResult>,
  ExactType<CommitAuthorizationAdmissionInput["requested_usage_index"], number>,
  ExactType<ExactExecutionRequest["mode"], "exact">,
  ExactType<ExactExecutionRequest["execution_attempt_id"], UUID>,
  ExactType<ExactExecutionRequest["operation_type"], string>,
  ExactType<BoundedExecutionRequest["mode"], "bounded">,
  ExactType<BoundedExecutionRequest["execution_attempt_id"], UUID>,
  ExactType<BoundedExecutionRequest["operation_type"], string>,
  ExactType<BoundedExecutionRequest["capability_id"], string>,
  ExactType<NoneEconomicRequest["mode"], "none">,
  ExactType<BoundedEconomicRequest["mode"], "bounded">,
  ExactType<BoundedEconomicRequest["envelope"], SpendingEnvelope>,
  ExactType<BoundedEconomicRequest["requested_amount"], string>,
  ExactUnionInventory<keyof AdmissionRecord, ReviewedAdmissionRecordKey>,
  ExactUnionInventory<OptionalKeys<AdmissionRecord>, never>,
  ExactType<AdmissionRecord["admission_id"], UUID>,
  ExactType<AdmissionRecord["proof_id"], AuthorizationProof["proof_id"]>,
  ExactType<AdmissionRecord["execution_attempt_id"], UUID>,
  ExactType<AdmissionRecord["requested_usage_index"], number>,
  ExactType<AdmissionRecord["authorization_decision_id"], UUID>,
  ExactType<AdmissionRecord["principal_id"], UUID>,
  ExactType<AdmissionRecord["spending_envelope_id"], UUID | null>,
  ExactType<AdmissionRecord["requested_amount"], string | null>,
  ExactType<AdmissionRecord["proof_usage_state_version"], number>,
  ExactType<AdmissionRecord["spending_envelope_state_version"], number | null>,
  ExactType<AdmissionRecord["outbox_record_id"], UUID>,
  ExactUnionInventory<keyof AdmissionOutboxRecord, ReviewedOutboxRecordKey>,
  ExactUnionInventory<OptionalKeys<AdmissionOutboxRecord>, never>,
  ExactType<AdmissionOutboxRecord["outbox_record_id"], UUID>,
  ExactType<AdmissionOutboxRecord["admission_id"], AdmissionRecord["admission_id"]>,
  ExactType<AdmissionOutboxRecord["event_type"], "authorization_admission_committed">,
  ExactType<AdmissionOutboxRecord["proof_id"], AdmissionRecord["proof_id"]>,
  ExactType<AdmissionOutboxRecord["execution_attempt_id"], AdmissionRecord["execution_attempt_id"]>,
  ExactType<AdmissionOutboxRecord["spending_envelope_id"], AdmissionRecord["spending_envelope_id"]>,
  ExactType<AdmissionOutboxRecord["proof_usage_state_version"], AdmissionRecord["proof_usage_state_version"]>,
  ExactType<AdmissionOutboxRecord["spending_envelope_state_version"], AdmissionRecord["spending_envelope_state_version"]>,
  ExactUnionInventory<AtomicAdmissionFailure["reason"], ReviewedFailureReason>,
  AllDistributedChecksTrue<DistributedFailureChecks<AtomicAdmissionFailure>>,
  ExactUnionInventory<
    LocalAuthorizationProofVerificationFailureReason,
    typeof LOCAL_VERIFICATION_FAILURE_REASONS[number]
  >,
  ExactType<
    typeof LOCAL_VERIFICATION_FAILURE_REASONS,
    ReviewedLocalVerificationFailureReasons
  >,
  ExactUnionInventory<CommitAuthorizationAdmissionResult["admission"], "admission_committed" | "admission_replayed" | "admission_rejected">,
  AllDistributedChecksTrue<DistributedResultChecks<CommitAuthorizationAdmissionResult>>,
  ExactType<ReturnType<typeof buildFingerprintTuple>, ReviewedFingerprintTuple>,
  AllDistributedChecksTrue<
    DistributedFingerprintTupleChecks<ReturnType<typeof buildFingerprintTuple>>
  >,
  ExactType<AtomicAdmissionAuthority, ReviewedAuthority>,
  ExactUnionInventory<OptionalKeys<AtomicAdmissionAuthority>, never>,
  ExactUnionInventory<
    keyof AtomicAdmissionAuthority,
    | "commitAuthorizationAdmission"
    | "getProofUsageState"
    | "getSpendingEnvelopeState"
    | "getAdmissionRecord"
    | "getAdmissionOutboxRecord"
  >,
  ExactTupleElementTypes<
    Parameters<AtomicAdmissionAuthority["commitAuthorizationAdmission"]>,
    [CommitAuthorizationAdmissionInput]
  >,
  ExactType<
    ReturnType<AtomicAdmissionAuthority["commitAuthorizationAdmission"]>,
    CommitAuthorizationAdmissionResult
  >,
  ExactTupleElementTypes<
    Parameters<AtomicAdmissionAuthority["getProofUsageState"]>,
    [AuthorizationProof["proof_id"]]
  >,
  ExactType<
    ReturnType<AtomicAdmissionAuthority["getProofUsageState"]>,
    AuthorizationProofUsageState | null
  >,
  ExactTupleElementTypes<
    Parameters<AtomicAdmissionAuthority["getSpendingEnvelopeState"]>,
    [SpendingEnvelope["spending_envelope_id"]]
  >,
  ExactType<
    ReturnType<AtomicAdmissionAuthority["getSpendingEnvelopeState"]>,
    SpendingEnvelopeState | null
  >,
  ExactTupleElementTypes<
    Parameters<AtomicAdmissionAuthority["getAdmissionRecord"]>,
    [AdmissionRecord["admission_id"]]
  >,
  ExactType<
    ReturnType<AtomicAdmissionAuthority["getAdmissionRecord"]>,
    AdmissionRecord | undefined
  >,
  ExactTupleElementTypes<
    Parameters<AtomicAdmissionAuthority["getAdmissionOutboxRecord"]>,
    [AdmissionOutboxRecord["outbox_record_id"]]
  >,
  ExactType<
    ReturnType<AtomicAdmissionAuthority["getAdmissionOutboxRecord"]>,
    AdmissionOutboxRecord | undefined
  >,
  ExactUnionInventory<OptionalKeys<StoredAdmission>, never>,
  ExactUnionInventory<keyof StoredAdmission, "fingerprint" | "admission_record" | "outbox_record" | "committed_proof_usage_state" | "committed_spending_envelope_state">,
  ExactType<StoredAdmission["fingerprint"], AdmissionRequestFingerprint>,
  ExactType<StoredAdmission["admission_record"], AdmissionRecord>,
  ExactType<StoredAdmission["outbox_record"], AdmissionOutboxRecord>,
  ExactType<StoredAdmission["committed_proof_usage_state"], AuthorizationProofUsageState>,
  ExactType<StoredAdmission["committed_spending_envelope_state"], SpendingEnvelopeState | null>,
  ExactUnionInventory<OptionalKeys<AtomicAdmissionAggregateState>, never>,
  ExactUnionInventory<keyof AtomicAdmissionAggregateState, "proof_usage_states" | "spending_envelope_states" | "admissions" | "outbox_records">,
  ExactMapType<AtomicAdmissionAggregateState["proof_usage_states"], UUID, AuthorizationProofUsageState>,
  ExactMapType<AtomicAdmissionAggregateState["spending_envelope_states"], UUID, SpendingEnvelopeState>,
  ExactMapType<AtomicAdmissionAggregateState["admissions"], UUID, StoredAdmission>,
  ExactMapType<AtomicAdmissionAggregateState["outbox_records"], UUID, AdmissionOutboxRecord>,
]>;

const CANONICAL_AMOUNT_PATTERN = /^[1-9][0-9]*$/;
class StructuralAdmissionInputError extends Error {}
class ReentrantAtomicAdmissionPreparationError extends Error {}

function structuralFail(field: string, reason: string): never {
  throw new StructuralAdmissionInputError(`atomic_admission_${field}_${reason}`);
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
function ownedRecord(): Record<string, unknown> {
  return Object.create(null) as Record<string, unknown>;
}
function captureExactDataProperties(
  value: unknown,
  keys: readonly string[],
  field: string
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    structuralFail(field, "invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") structuralFail(field, "symbol_unsupported");
    if (!keys.includes(key)) structuralFail(`${field}.${key}`, "unsupported");
  }
  const captured = ownedRecord();
  for (const key of keys) {
    if (!own(descriptors, key)) structuralFail(`${field}.${key}`, "required");
    const descriptor = descriptors[key];
    if (!own(descriptor, "value") || own(descriptor, "get") || own(descriptor, "set")) {
      structuralFail(`${field}.${key}`, "accessor_unsupported");
    }
    defineOwnDataProperty(captured, key, descriptor.value);
  }
  return captured;
}
function captureDiscriminatedDataProperties<
  Shapes extends Readonly<Record<string, readonly string[]>>,
>(
  value: unknown,
  discriminator: string,
  shapes: Shapes,
  field: string
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    structuralFail(field, "invalid");
  }
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (!own(descriptors, discriminator)) {
    structuralFail(`${field}.${discriminator}`, "required");
  }
  const discriminatorDescriptor = descriptors[discriminator];
  if (
    !own(discriminatorDescriptor, "value") ||
    own(discriminatorDescriptor, "get") ||
    own(discriminatorDescriptor, "set")
  ) {
    structuralFail(`${field}.${discriminator}`, "accessor_unsupported");
  }
  const mode = discriminatorDescriptor.value;
  if (typeof mode !== "string" || !own(shapes, mode)) {
    structuralFail(`${field}.${discriminator}`, "invalid");
  }
  const keys = shapes[mode];
  const captured = ownedRecord();
  for (const key of Reflect.ownKeys(descriptors)) {
    if (typeof key !== "string") structuralFail(field, "symbol_unsupported");
    if (!keys.includes(key)) structuralFail(`${field}.${key}`, "unsupported");
  }
  for (const key of keys) {
    if (!own(descriptors, key)) structuralFail(`${field}.${key}`, "required");
    const descriptor = descriptors[key];
    if (!own(descriptor, "value") || own(descriptor, "get") || own(descriptor, "set")) {
      structuralFail(`${field}.${key}`, "accessor_unsupported");
    }
    defineOwnDataProperty(captured, key, descriptor.value);
  }
  return captured;
}
function assertOpaqueNonblankString(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || value.trim().length === 0) structuralFail(field, "invalid");
}
function assertPositiveSafeInteger(value: unknown, field: string): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 1) structuralFail(field, "invalid");
}
function assertNonnegativeSafeInteger(value: unknown, field: string): asserts value is number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) structuralFail(field, "invalid");
}
function assertCanonicalAmount(value: unknown, field: string): asserts value is string {
  if (typeof value !== "string" || !CANONICAL_AMOUNT_PATTERN.test(value)) structuralFail(field, "invalid");
}
function isExpectedProofStructuralFailure(error: unknown): boolean {
  return error instanceof Error && error.message.startsWith("authorization_proof_");
}

function snapshotEnvelope(value: unknown): SpendingEnvelope {
  const captured = captureExactDataProperties(value, ENVELOPE_KEYS, "economic_request.envelope");
  assertOpaqueNonblankString(captured.spending_envelope_id, "economic_request.envelope.spending_envelope_id");
  assertOpaqueNonblankString(captured.authorization_decision_id, "economic_request.envelope.authorization_decision_id");
  assertOpaqueNonblankString(captured.principal_id, "economic_request.envelope.principal_id");
  assertOpaqueNonblankString(captured.asset_id, "economic_request.envelope.asset_id");
  assertCanonicalAmount(captured.maximum_amount, "economic_request.envelope.maximum_amount");
  assertNonnegativeSafeInteger(captured.wallet_or_economic_epoch, "economic_request.envelope.wallet_or_economic_epoch");
  return makeEnvelope(
    captured.spending_envelope_id,
    captured.authorization_decision_id,
    captured.principal_id,
    captured.asset_id,
    captured.maximum_amount,
    captured.wallet_or_economic_epoch
  );
}
function makeEnvelope(
  spendingEnvelopeId: string,
  authorizationDecisionId: string,
  principalId: string,
  assetId: string,
  maximumAmount: string,
  epoch: number
): SpendingEnvelope {
  return {
    spending_envelope_id: spendingEnvelopeId,
    authorization_decision_id: authorizationDecisionId,
    principal_id: principalId,
    asset_id: assetId,
    maximum_amount: maximumAmount,
    wallet_or_economic_epoch: epoch,
  };
}

type OwnedExecutionRequest = CommitAuthorizationAdmissionInput["execution_request"];
type OwnedEconomicRequest = CommitAuthorizationAdmissionInput["economic_request"];
function snapshotExecutionRequest(value: unknown): OwnedExecutionRequest {
  const captured = captureDiscriminatedDataProperties(
    value,
    "mode",
    EXECUTION_REQUEST_SHAPES,
    "execution_request"
  );
  if (captured.mode === "exact") {
    assertOpaqueNonblankString(captured.execution_attempt_id, "execution_request.execution_attempt_id");
    assertOpaqueNonblankString(captured.operation_type, "execution_request.operation_type");
    return makeExecutionRequestExact(captured.execution_attempt_id, captured.operation_type);
  }
  if (captured.mode === "bounded") {
    assertOpaqueNonblankString(captured.execution_attempt_id, "execution_request.execution_attempt_id");
    assertOpaqueNonblankString(captured.operation_type, "execution_request.operation_type");
    assertOpaqueNonblankString(captured.capability_id, "execution_request.capability_id");
    return makeExecutionRequestBounded(captured.execution_attempt_id, captured.operation_type, captured.capability_id);
  }
  return structuralFail("execution_request.mode", "invalid");
}
function makeExecutionRequestExact(executionAttemptId: string, operationType: string): OwnedExecutionRequest {
  return {
    mode: "exact",
    execution_attempt_id: executionAttemptId,
    operation_type: operationType,
  };
}
function makeExecutionRequestBounded(executionAttemptId: string, operationType: string, capabilityId: string): OwnedExecutionRequest {
  return {
    mode: "bounded",
    execution_attempt_id: executionAttemptId,
    operation_type: operationType,
    capability_id: capabilityId,
  };
}
function snapshotEconomicRequest(value: unknown): OwnedEconomicRequest {
  const captured = captureDiscriminatedDataProperties(
    value,
    "mode",
    ECONOMIC_REQUEST_SHAPES,
    "economic_request"
  );
  if (captured.mode === "none") {
    return { mode: "none" };
  }
  if (captured.mode === "bounded") {
    const envelope = snapshotEnvelope(captured.envelope);
    assertCanonicalAmount(captured.requested_amount, "economic_request.requested_amount");
    return {
      mode: "bounded",
      envelope,
      requested_amount: captured.requested_amount,
    };
  }
  return structuralFail("economic_request.mode", "invalid");
}
function snapshotLocalVerification(value: unknown): LocalAuthorizationProofVerificationResult {
  const captured = captureDiscriminatedDataProperties(
    value,
    "verification",
    LOCAL_VERIFICATION_SHAPES,
    "local_verification"
  );
  if (captured.verification === "verified_locally") {
    assertOpaqueNonblankString(captured.proof_id, "local_verification.proof_id");
    return { verification: "verified_locally", proof_id: captured.proof_id };
  }
  if (captured.verification === "not_verified") {
    assertLocalVerificationReason(captured.reason);
    return { verification: "not_verified", reason: captured.reason };
  }
  return structuralFail("local_verification.verification", "invalid");
}
function assertLocalVerificationReason(value: unknown): asserts value is LocalAuthorizationProofVerificationFailureReason {
  if (
    typeof value !== "string" ||
    !LOCAL_VERIFICATION_FAILURE_REASONS.includes(
      value as typeof LOCAL_VERIFICATION_FAILURE_REASONS[number]
    )
  ) {
    structuralFail("local_verification.reason", "invalid");
  }
}

interface OwnedAdmissionInput {
  admission_id: UUID;
  proof: AuthorizationProof;
  local_verification: LocalAuthorizationProofVerificationResult;
  requested_usage_index: number;
  execution_request: OwnedExecutionRequest;
  economic_request: OwnedEconomicRequest;
}
function snapshotAdmissionInput(input: CommitAuthorizationAdmissionInput): OwnedAdmissionInput {
  const captured = captureExactDataProperties(input, COMMIT_INPUT_KEYS, "input");
  assertOpaqueNonblankString(captured.admission_id, "input.admission_id");
  assertPositiveSafeInteger(captured.requested_usage_index, "input.requested_usage_index");
  const proof = snapshotAuthorizationProof(captured.proof as AuthorizationProof);
  return {
    admission_id: captured.admission_id,
    proof,
    local_verification: snapshotLocalVerification(captured.local_verification),
    requested_usage_index: captured.requested_usage_index,
    execution_request: snapshotExecutionRequest(captured.execution_request),
    economic_request: snapshotEconomicRequest(captured.economic_request),
  };
}

function buildFingerprintTuple(input: OwnedAdmissionInput) {
  const admissionId = input.admission_id;
  const proofId = input.proof.proof_id;
  const executionAttemptId = input.execution_request.execution_attempt_id;
  const operationType = input.execution_request.operation_type;
  const executionCapability = input.execution_request.mode === "bounded"
    ? input.execution_request.capability_id
    : null;
  const requestedUsageIndex = input.requested_usage_index;
  if (input.economic_request.mode === "none") {
    return [
      "atomic-admission-request", "v1", admissionId, proofId,
      input.execution_request.mode, executionAttemptId, operationType,
      executionCapability, requestedUsageIndex, "none",
      null, null, null, null, null, null, null,
    ] as const;
  }
  const envelope = input.economic_request.envelope;
  const spendingEnvelopeId = envelope.spending_envelope_id;
  const authorizationDecisionId = envelope.authorization_decision_id;
  const principalId = envelope.principal_id;
  const assetId = envelope.asset_id;
  const maximumAmount = envelope.maximum_amount;
  const walletOrEconomicEpoch = envelope.wallet_or_economic_epoch;
  const requestedAmount = input.economic_request.requested_amount;
  return [
    "atomic-admission-request", "v1", admissionId, proofId,
    input.execution_request.mode, executionAttemptId, operationType,
    executionCapability, requestedUsageIndex, "bounded", spendingEnvelopeId,
    authorizationDecisionId, principalId, assetId, maximumAmount,
    walletOrEconomicEpoch, requestedAmount,
  ] as const;
}

function snapshotUsageState(state: AuthorizationProofUsageState): AuthorizationProofUsageState {
  return {
    proof_id: state.proof_id,
    consumed_usage_count: state.consumed_usage_count,
    state_version: state.state_version,
  };
}
function snapshotEnvelopeState(state: SpendingEnvelopeState): SpendingEnvelopeState {
  return {
    spending_envelope_id: state.spending_envelope_id,
    authorization_decision_id: state.authorization_decision_id,
    principal_id: state.principal_id,
    asset_id: state.asset_id,
    maximum_amount: state.maximum_amount,
    wallet_or_economic_epoch: state.wallet_or_economic_epoch,
    reserved_amount: state.reserved_amount,
    state_version: state.state_version,
  };
}
function snapshotAdmissionRecord(record: AdmissionRecord): AdmissionRecord {
  return { ...record };
}
function snapshotOutboxRecord(record: AdmissionOutboxRecord): AdmissionOutboxRecord {
  return { ...record };
}
function publicSuccess(
  admission: "admission_committed" | "admission_replayed",
  stored: StoredAdmission
): CommitAuthorizationAdmissionResult {
  return {
    admission,
    admission_record: snapshotAdmissionRecord(stored.admission_record),
    outbox_record: snapshotOutboxRecord(stored.outbox_record),
    committed_proof_usage_state: snapshotUsageState(stored.committed_proof_usage_state),
    committed_spending_envelope_state: stored.committed_spending_envelope_state === null
      ? null
      : snapshotEnvelopeState(stored.committed_spending_envelope_state),
  };
}
function rejected(
  failure: AtomicAdmissionFailure
): CommitAuthorizationAdmissionResult {
  return {
    admission: "admission_rejected",
    failure,
  };
}
function executionMatches(input: OwnedAdmissionInput): boolean {
  const scope = input.proof.payload.execution_scope;
  const request = input.execution_request;
  if (scope.mode === "exact") {
    return request.mode === "exact" &&
      request.execution_attempt_id === scope.execution_id &&
      request.operation_type === scope.operation_type;
  }
  return request.mode === "bounded" &&
    request.operation_type === scope.operation_type &&
    request.capability_id === scope.capability_id &&
    input.requested_usage_index <= scope.maximum_operations;
}
function validateProspectiveBundle(stored: StoredAdmission): void {
  const record = stored.admission_record;
  const outbox = stored.outbox_record;
  if (
    record.proof_id !== stored.committed_proof_usage_state.proof_id ||
    record.proof_usage_state_version !== stored.committed_proof_usage_state.state_version ||
    record.outbox_record_id !== outbox.outbox_record_id ||
    record.admission_id !== outbox.admission_id ||
    record.proof_id !== outbox.proof_id ||
    record.execution_attempt_id !== outbox.execution_attempt_id ||
    record.spending_envelope_id !== outbox.spending_envelope_id ||
    record.proof_usage_state_version !== outbox.proof_usage_state_version ||
    record.spending_envelope_state_version !== outbox.spending_envelope_state_version
  ) throw new Error("atomic_admission_internal_cross_reference_invalid");
  if (stored.committed_spending_envelope_state === null) {
    if (record.spending_envelope_id !== null || record.requested_amount !== null || record.spending_envelope_state_version !== null) {
      throw new Error("atomic_admission_internal_none_economic_invalid");
    }
  } else if (
    record.spending_envelope_id !== stored.committed_spending_envelope_state.spending_envelope_id ||
    record.spending_envelope_state_version !== stored.committed_spending_envelope_state.state_version
  ) throw new Error("atomic_admission_internal_bounded_economic_invalid");
}

/**
 * Creates one synchronous, non-durable, process-local admission authority.
 * Admission commitment is not execution, payment, Token transfer, settlement,
 * distributed atomicity, durable authority, or exactly-once execution.
 * Ordinary passive data objects are supported; Proxy/meta-object traps are not.
 */
export function createAtomicAdmissionAuthority(): AtomicAdmissionAuthority {
  let state: AtomicAdmissionAggregateState = {
    proof_usage_states: new Map<UUID, AuthorizationProofUsageState>(),
    spending_envelope_states: new Map<UUID, SpendingEnvelopeState>(),
    admissions: new Map<UUID, StoredAdmission>(),
    outbox_records: new Map<UUID, AdmissionOutboxRecord>(),
  };
  let admissionPreparationActive = false;

  function prepareAuthorizationAdmission(
    input: CommitAuthorizationAdmissionInput
  ): PreparedAtomicAdmissionOutcome {
    let owned: OwnedAdmissionInput;
    try {
      owned = snapshotAdmissionInput(input);
    } catch (error) {
      if (error instanceof StructuralAdmissionInputError || isExpectedProofStructuralFailure(error)) {
        return ["result", rejected({ reason: "structural_invalid" })] as const;
      }
      throw error;
    }

    let expectedProofId: string;
    try {
      expectedProofId = deriveAuthorizationProofId(owned.proof.payload);
    } catch (error) {
      if (isExpectedProofStructuralFailure(error)) {
        return ["result", rejected({ reason: "structural_invalid" })] as const;
      }
      throw error;
    }
    if (owned.proof.proof_id !== expectedProofId) {
      return ["result", rejected({ reason: "proof_id_mismatch" })] as const;
    }

    const fingerprint = JSON.stringify(
      buildFingerprintTuple(owned)
    ) as AdmissionRequestFingerprint;
    const existing = state.admissions.get(owned.admission_id);
    if (existing !== undefined) {
      if (existing.fingerprint === fingerprint) {
        return ["result", publicSuccess("admission_replayed", existing)] as const;
      }
      return ["result", rejected({ reason: "admission_conflict" })] as const;
    }

    if (owned.local_verification.verification === "not_verified") {
      return ["result", rejected({
        reason: "local_verification_rejected",
        local_verification_reason: owned.local_verification.reason,
      })] as const;
    }
    if (owned.local_verification.proof_id !== expectedProofId) {
      return ["result", rejected({ reason: "local_verification_proof_mismatch" })] as const;
    }
    if (!executionMatches(owned)) {
      return ["result", rejected({ reason: "execution_attempt_mismatch" })] as const;
    }

    const currentProofState = state.proof_usage_states.get(expectedProofId) ?? null;
    const proofTransition = transitionAuthorizationProofUsage({
      proof: owned.proof,
      current_usage_state: currentProofState,
      requested_usage_index: owned.requested_usage_index,
    });
    if (proofTransition.transition === "usage_state_rejected") {
      return ["result", rejected({
        reason: "proof_usage_rejected",
        proof_usage_reason: proofTransition.reason,
      })] as const;
    }
    const nextProofState = snapshotUsageState(proofTransition.next_usage_state);

    let nextEnvelopeState: SpendingEnvelopeState | null = null;
    const proofEconomicMode = owned.proof.payload.economic_scope.mode;
    if (proofEconomicMode === "bounded" && owned.economic_request.mode === "none") {
      return ["result", rejected({ reason: "spending_envelope_required" })] as const;
    }
    if (proofEconomicMode === "none" && owned.economic_request.mode === "bounded") {
      return ["result", rejected({ reason: "spending_envelope_unexpected" })] as const;
    }
    if (proofEconomicMode === "bounded" && owned.economic_request.mode === "bounded") {
      const envelopeId = owned.economic_request.envelope.spending_envelope_id;
      const currentEnvelopeState = state.spending_envelope_states.get(envelopeId) ?? null;
      const envelopeTransition = transitionSpendingEnvelopeReservation({
        proof: owned.proof,
        envelope: owned.economic_request.envelope,
        current_envelope_state: currentEnvelopeState,
        requested_amount: owned.economic_request.requested_amount,
      });
      if (envelopeTransition.transition === "spending_envelope_state_rejected") {
        return ["result", rejected({
          reason: "spending_envelope_rejected",
          spending_envelope_reason: envelopeTransition.reason,
        })] as const;
      }
      nextEnvelopeState = snapshotEnvelopeState(envelopeTransition.next_spending_envelope_state);
    }

    const executionAttemptId = owned.execution_request.execution_attempt_id;
    const spendingEnvelopeId = nextEnvelopeState?.spending_envelope_id ?? null;
    const requestedAmount = owned.economic_request.mode === "bounded"
      ? owned.economic_request.requested_amount
      : null;
    const outboxRecordId = `atomic-admission-outbox:${owned.admission_id}`;
    const admissionRecord: AdmissionRecord = {
      admission_id: owned.admission_id,
      proof_id: expectedProofId,
      execution_attempt_id: executionAttemptId,
      requested_usage_index: owned.requested_usage_index,
      authorization_decision_id: owned.proof.payload.authorization_decision_id,
      principal_id: owned.proof.payload.principal_id,
      spending_envelope_id: spendingEnvelopeId,
      requested_amount: requestedAmount,
      proof_usage_state_version: nextProofState.state_version,
      spending_envelope_state_version: nextEnvelopeState?.state_version ?? null,
      outbox_record_id: outboxRecordId,
    };
    const outboxRecord: AdmissionOutboxRecord = {
      outbox_record_id: outboxRecordId,
      admission_id: owned.admission_id,
      event_type: "authorization_admission_committed",
      proof_id: expectedProofId,
      execution_attempt_id: executionAttemptId,
      spending_envelope_id: spendingEnvelopeId,
      proof_usage_state_version: nextProofState.state_version,
      spending_envelope_state_version: nextEnvelopeState?.state_version ?? null,
    };
    const stored: StoredAdmission = {
      fingerprint,
      admission_record: snapshotAdmissionRecord(admissionRecord),
      outbox_record: snapshotOutboxRecord(outboxRecord),
      committed_proof_usage_state: snapshotUsageState(nextProofState),
      committed_spending_envelope_state: nextEnvelopeState === null ? null : snapshotEnvelopeState(nextEnvelopeState),
    };
    validateProspectiveBundle(stored);

    const nextProofStates = new Map<UUID, AuthorizationProofUsageState>(state.proof_usage_states.entries());
    nextProofStates.set(
      expectedProofId,
      snapshotUsageState(nextProofState)
    );
    const nextEnvelopeStates = new Map<UUID, SpendingEnvelopeState>(state.spending_envelope_states.entries());
    if (nextEnvelopeState !== null) {
      nextEnvelopeStates.set(
        nextEnvelopeState.spending_envelope_id,
        snapshotEnvelopeState(nextEnvelopeState)
      );
    }
    const nextAdmissions = new Map<UUID, StoredAdmission>(state.admissions.entries());
    nextAdmissions.set(owned.admission_id, stored);
    const nextOutboxRecords = new Map<UUID, AdmissionOutboxRecord>(state.outbox_records.entries());
    nextOutboxRecords.set(
      outboxRecordId,
      snapshotOutboxRecord(outboxRecord)
    );
    const nextState: AtomicAdmissionAggregateState = {
      proof_usage_states: nextProofStates,
      spending_envelope_states: nextEnvelopeStates,
      admissions: nextAdmissions,
      outbox_records: nextOutboxRecords,
    };
    const committedResult = publicSuccess("admission_committed", stored);
    return ["commit", nextState, committedResult] as const;
  }

  function commitAuthorizationAdmission(
    input: CommitAuthorizationAdmissionInput
  ): CommitAuthorizationAdmissionResult {
    if (admissionPreparationActive) {
      throw new ReentrantAtomicAdmissionPreparationError(
        "atomic_admission_reentrant_preparation"
      );
    }
    admissionPreparationActive = true;
    let shouldPublish = false;
    let nextStateToPublish:
      | AtomicAdmissionAggregateState
      | undefined;
    let resultToReturn:
      | CommitAuthorizationAdmissionResult
      | undefined;
    try {
      const prepared = prepareAuthorizationAdmission(input);
      if (prepared[0] === "commit") {
        nextStateToPublish = prepared[1];
        resultToReturn = prepared[2];
        shouldPublish = true;
      } else {
        resultToReturn = prepared[1];
      }
    } finally {
      admissionPreparationActive = false;
    }
    if (shouldPublish) {
      state = nextStateToPublish!;
    }
    return resultToReturn!;
  }

  return {
    commitAuthorizationAdmission,
    getProofUsageState(proofId) {
      const value = state.proof_usage_states.get(proofId);
      return value === undefined ? null : snapshotUsageState(value);
    },
    getSpendingEnvelopeState(spendingEnvelopeId) {
      const value = state.spending_envelope_states.get(spendingEnvelopeId);
      return value === undefined ? null : snapshotEnvelopeState(value);
    },
    getAdmissionRecord(admissionId) {
      const value = state.admissions.get(admissionId);
      return value === undefined ? undefined : snapshotAdmissionRecord(value.admission_record);
    },
    getAdmissionOutboxRecord(outboxRecordId) {
      const value = state.outbox_records.get(outboxRecordId);
      return value === undefined ? undefined : snapshotOutboxRecord(value);
    },
  };
}
