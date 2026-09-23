/**
 * mindchain-mvp - core contracts (types + minimal helpers)
 * Constraints: no DB, no I/O, no networking.
 * Timestamps are ISO-8601 strings (Date.toISOString()).
 */

/* ============================================================================
 * 1) Base types
 * ========================================================================== */

export type ISODateTime = string;
export type CurrencyCode = "EUR" | "USD";
export type UUID = string;

/* ============================================================================
 * 2) Enumerations / unions
 * ========================================================================== */

export type ActorType = "agent" | "merchant" | "service" | "wallet";

export type AgentStatus =
  | "active"
  | "inactive"
  | "suspended"
  | "revoked";

export type AgentKind =
  | "ai_agent"
  | "software_service"
  | "machine"
  | "human_operator"
  | "organization";

export type AgentRelationshipType =
  | "owned_by"
  | "operated_by"
  | "delegated_to"
  | "supervised_by"
  | "member_of"
  | "linked_to";

export type LedgerEntryType =
  | "intent_submitted"
  | "intent_denied"
  | "intent_accepted"
  | "proof_submitted"
  | "transaction_state_changed"
  | "settlement_batched";

export type TransactionState =
  | "pending"
  | "fulfilled"
  | "expired"
  | "cancelled"
  | "denied";

export type ExecutionPlanStatus =
  | "planned"
  | "running"
  | "blocked"
  | "failed"
  | "completed"
  | "expired";

export type ExecutionStepStatus =
  | "planned"
  | "running"
  | "blocked"
  | "failed"
  | "completed"
  | "skipped";

export type ReservationStatus =
  | "active"
  | "released"
  | "expired"
  | "cancelled";

export type PendingSettlementStatus =
  | "pending"
  | "finalized"
  | "failed"
  | "cancelled";

export type ConcurrencySubjectType =
  | "wallet"
  | "provider"
  | "resource_type"
  | "execution_plan";

export type MACSubjectType =
  | "wallet"
  | "provider"
  | "resource_type"
  | "execution_plan"
  | "intent";

export type PolicyPressureSubjectType =
  | "wallet"
  | "provider"
  | "resource_type"
  | "execution_plan"
  | "intent";

export type PolicyDecisionSubjectType =
  | "wallet"
  | "provider"
  | "resource_type"
  | "execution_plan"
  | "intent";

export type ReputationSubjectType =
  | "wallet"
  | "provider"
  | "resource_type"
  | "execution_plan"
  | "intent";

export type AuditExplanationSubjectType =
  | "wallet"
  | "provider"
  | "resource_type"
  | "execution_plan"
  | "intent"
  | "transaction"
  | "policy_decision"
  | "mac"
  | "policy_pressure"
  | "reputation";

export type AuditExplanationSourceType =
  | "policy_decision"
  | "mac"
  | "policy_pressure"
  | "concurrency"
  | "reputation"
  | "transaction"
  | "settlement"
  | "pending_settlement"
  | "execution_plan"
  | "reservation";

export type AuditExplanationSeverity = "info" | "warning" | "critical";

export type AntiCollusionSubjectType =
  | "wallet"
  | "provider"
  | "resource_type"
  | "execution_plan"
  | "intent"
  | "transaction";

export type AntiCollusionSignalType =
  | "repeated_counterparty"
  | "circular_flow"
  | "suspicious_timing"
  | "abnormal_failure_pattern"
  | "shared_metadata_pattern"
  | "manual_review_hint";

export type AntiCollusionSeverity = "low" | "medium" | "high" | "critical";

export type ProtocolContextSubjectType =
  | "wallet"
  | "provider"
  | "resource_type"
  | "execution_plan"
  | "intent"
  | "transaction"
  | "agent";

export type ComposedPolicyDecisionOutcome =
  | "ALLOW"
  | "REVIEW"
  | "DENY"
  | "UNDECIDED";

export type PolicyDecisionOutcome = "ALLOW" | "REVIEW" | "DENY";

export type MACCurrency = "MCT_INTERNAL";

export type ResourceType =
  | "compute"
  | "memory"
  | "storage"
  | "network"
  | "api";

export type ServiceSubtype =
  | "gpu_inference"
  | "gpu_training"
  | "cpu_compute"
  | "ram"
  | "ram_extended"
  | "vram"
  | "nvme_cache"
  | "object_storage"
  | "bandwidth"
  | "low_latency"
  | "ai_inference"
  | "dataset_access"
  | "external_service";

export type ResourceAvailability = "always" | "on_demand" | "scheduled";

export type PricingModel = "per_second" | "per_request" | "per_mb";

/* ============================================================================
 * 3) Entities and payloads
 * ========================================================================== */

export interface ServiceCapabilities {
  cpu?: string;
  gpu?: boolean;
  gpu_model?: string;
  vram_gb?: number;
  ram_gb?: number;
  storage_gb?: number;
  bandwidth_mbps?: number;
  latency_ms?: number;
}

export interface AgentCapability {
  capability_id: UUID;
  capability_type: string;
  description?: string;
}

export interface AgentProfile {
  display_name?: string;
  description?: string;
  metadata_refs: UUID[];
}

export interface Agent {
  agent_id: UUID;
  owner_id?: UUID;
  kind: AgentKind;
  status: AgentStatus;
  capabilities: AgentCapability[];
  profile: AgentProfile;
  created_at: ISODateTime;
  updated_at: ISODateTime;
}

export interface AgentRegistryRecord {
  registry_id: UUID;
  agent_id: UUID;
  agent: Agent;
  created_at: ISODateTime;
}

export interface AgentRelationship {
  relationship_id: UUID;
  source_agent_id: UUID;
  target_agent_id: UUID;
  relationship_type: AgentRelationshipType;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentReputationLink {
  link_id: UUID;
  agent_id: UUID;
  reputation_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentAuditLink {
  link_id: UUID;
  agent_id: UUID;
  audit_explanation_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentContextLink {
  link_id: UUID;
  agent_id: UUID;
  context_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentPolicyLink {
  link_id: UUID;
  agent_id: UUID;
  policy_composition_input_id?: UUID;
  composed_policy_decision_id?: UUID;
  policy_decision_id?: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentCapabilityLink {
  link_id: UUID;
  agent_id: UUID;
  capability_id: UUID;
  capability_type?: string;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentOwnershipLink {
  link_id: UUID;
  agent_id: UUID;
  owner_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type AgentRuntimeBoundaryStatus =
  | "declared"
  | "available"
  | "unavailable"
  | "disabled";

export interface AgentRuntimeBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  status: AgentRuntimeBoundaryStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentRuntimeIntentBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  intent_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentRuntimeExecutionBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentRuntimeProofBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  proof_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentRuntimeSettlementBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  proof_id: UUID;
  settlement_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentRuntimePolicyBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  policy_composition_input_id?: UUID;
  composed_policy_decision_id?: UUID;
  policy_decision_id?: UUID;
  mac_id?: UUID;
  pressure_id?: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentRuntimeAuditBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  audit_explanation_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AgentRuntimeReputationBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  reputation_id: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type AuthorizationRequestStatus =
  | "draft"
  | "requested"
  | "expired"
  | "cancelled";

export interface AuthorizationRequest {
  request_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  intent_id?: UUID;
  authorization_plan_id?: UUID;
  status: AuthorizationRequestStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type AuthorizationConstraintKind =
  | "budget"
  | "time_window"
  | "expiration"
  | "provider_allowlist"
  | "provider_denylist"
  | "resource_limit"
  | "execution_limit"
  | "metadata";

export interface AuthorizationConstraint {
  constraint_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  authorization_request_id?: UUID;
  authorization_plan_id?: UUID;
  kind: AuthorizationConstraintKind;
  constraint_ref: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type AuthorizationLifecycleState =
  | "draft"
  | "requested"
  | "pending_review"
  | "authorized"
  | "denied"
  | "expired"
  | "cancelled";

export interface AuthorizationLifecycle {
  lifecycle_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  authorization_request_id?: UUID;
  authorization_plan_id?: UUID;
  constraint_id?: UUID;
  state: AuthorizationLifecycleState;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface AuthorizationDecisionBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  authorization_request_id?: UUID;
  authorization_plan_id?: UUID;
  constraint_id?: UUID;
  lifecycle_id?: UUID;
  policy_decision_id?: UUID;
  composed_policy_decision_id?: UUID;
  policy_composition_input_id?: UUID;
  mac_id?: UUID;
  pressure_id?: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

/** First-class authorization proof contract foundation (Day 67). */
export type ProviderScope =
  | { mode: "any_authorized" }
  | { mode: "exact"; provider_id: UUID };

export type ServiceScope = { service_id: UUID };

export type ExecutionScope =
  | { mode: "exact"; execution_id: UUID; operation_type: string }
  | {
      mode: "bounded";
      operation_type: string;
      capability_id: string;
      maximum_operations: number;
    };

export type UsageLimit =
  | { mode: "single_use"; maximum_usage_count: 1 }
  | {
      mode: "bounded";
      maximum_usage_count: number;
      sequence_mode: "monotonic";
    };

export type EconomicScope =
  | { mode: "none" }
  | {
      mode: "bounded";
      asset_id: string;
      maximum_amount: string;
      spending_envelope_id: UUID;
      wallet_or_economic_epoch: number;
    };

export interface DelegationConstraints {
  delegation_mode: "direct" | "delegated";
}

export interface AuthorizationProofPayload {
  protocol_version: string;
  canonicalization_version: string;
  issuer_id: UUID;
  issuer_key_id: string;
  principal_id: UUID;
  subject_agent_id: UUID;
  delegator_id?: UUID;
  audience: string;
  runtime_id: UUID;
  provider_scope: ProviderScope;
  service_scope: ServiceScope;
  execution_scope: ExecutionScope;
  authorization_request_id: UUID;
  authorization_decision_id: UUID;
  policy_digest: string;
  policy_epoch: number;
  issued_at: ISODateTime;
  valid_from: ISODateTime;
  expires_at: ISODateTime;
  revocation_epoch: number;
  usage: UsageLimit;
  economic_scope: EconomicScope;
  delegation_constraints: DelegationConstraints;
  algorithm_id: string;
}

/** Exact immutable field inventory used by Day 68 identity derivation. */
export interface AuthorizationProofIdentityPreimage {
  protocol_version: string;
  canonicalization_version: string;
  issuer_id: UUID;
  issuer_key_id: string;
  principal_id: UUID;
  subject_agent_id: UUID;
  delegator_id?: UUID;
  audience: string;
  runtime_id: UUID;
  provider_scope: ProviderScope;
  service_scope: ServiceScope;
  execution_scope: ExecutionScope;
  authorization_request_id: UUID;
  authorization_decision_id: UUID;
  policy_digest: string;
  policy_epoch: number;
  issued_at: ISODateTime;
  valid_from: ISODateTime;
  expires_at: ISODateTime;
  revocation_epoch: number;
  usage: UsageLimit;
  economic_scope: EconomicScope;
  delegation_constraints: DelegationConstraints;
  algorithm_id: string;
}

export interface AuthorizationProof {
  proof_id: UUID;
  payload: AuthorizationProofPayload;
  signature: string;
}

export type MACPreparationStatus =
  | "draft"
  | "prepared"
  | "superseded"
  | "cancelled";

export interface MACPreparation {
  preparation_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  authorization_request_id?: UUID;
  authorization_plan_id?: UUID;
  constraint_id?: UUID;
  lifecycle_id?: UUID;
  decision_boundary_id?: UUID;
  mac_ref: UUID;
  status: MACPreparationStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type WalletAuthorizationBoundaryStatus =
  | "draft"
  | "declared"
  | "superseded"
  | "cancelled";

export interface WalletAuthorizationBoundary {
  boundary_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  wallet_id: UUID;
  authorization_request_id?: UUID;
  authorization_plan_id?: UUID;
  constraint_id?: UUID;
  lifecycle_id?: UUID;
  decision_boundary_id?: UUID;
  mac_preparation_id?: UUID;
  status: WalletAuthorizationBoundaryStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type MCTHoldPlanStatus =
  | "draft"
  | "planned"
  | "superseded"
  | "cancelled";

export interface MCTHoldPlan {
  hold_plan_id: UUID;
  wallet_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  authorization_request_id?: UUID;
  authorization_plan_id?: UUID;
  constraint_id?: UUID;
  lifecycle_id?: UUID;
  decision_boundary_id?: UUID;
  mac_preparation_id?: UUID;
  wallet_authorization_boundary_id?: UUID;
  mac_ref: UUID;
  status: MCTHoldPlanStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type MCTBurnReleasePlanStatus =
  | "draft"
  | "planned"
  | "superseded"
  | "cancelled";

export interface MCTBurnReleasePlan {
  burn_release_plan_id: UUID;
  wallet_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  authorization_request_id?: UUID;
  authorization_plan_id?: UUID;
  constraint_id?: UUID;
  lifecycle_id?: UUID;
  decision_boundary_id?: UUID;
  mac_preparation_id?: UUID;
  wallet_authorization_boundary_id?: UUID;
  hold_plan_id?: UUID;
  mac_ref: UUID;
  status: MCTBurnReleasePlanStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type WalletLedgerDesignStatus =
  | "draft"
  | "designed"
  | "superseded"
  | "cancelled";

export interface WalletLedgerDesign {
  design_id: UUID;
  wallet_id: UUID;
  mac_preparation_id?: UUID;
  wallet_authorization_boundary_id?: UUID;
  hold_plan_id?: UUID;
  burn_release_plan_id?: UUID;
  status: WalletLedgerDesignStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type WalletStateStatus =
  | "created"
  | "initialized"
  | "active"
  | "suspended"
  | "closed";

export interface WalletState {
  state_id: UUID;
  wallet_id: UUID;
  wallet_ledger_design_id?: UUID;
  status: WalletStateStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type MCTLedgerEntryKind =
  | "hold_planned"
  | "burn_planned"
  | "release_planned"
  | "wallet_state"
  | "authorization_link"
  | "metadata";

export interface MCTLedgerEntry {
  entry_id: UUID;
  wallet_id: UUID;
  wallet_ledger_design_id?: UUID;
  wallet_state_id?: UUID;
  wallet_authorization_boundary_id?: UUID;
  hold_plan_id?: UUID;
  burn_release_plan_id?: UUID;
  mac_preparation_id?: UUID;
  kind: MCTLedgerEntryKind;
  entry_ref: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type MCTEconomicLifecycleState =
  | "planned"
  | "hold_prepared"
  | "hold_recorded"
  | "burn_planned"
  | "release_planned"
  | "completed"
  | "cancelled"
  | "failed";

export interface MCTEconomicLifecycle {
  lifecycle_id: UUID;
  wallet_id: UUID;
  wallet_ledger_design_id?: UUID;
  wallet_state_id?: UUID;
  wallet_authorization_boundary_id?: UUID;
  hold_plan_id?: UUID;
  burn_release_plan_id?: UUID;
  mac_preparation_id?: UUID;
  ledger_entry_id?: UUID;
  state: MCTEconomicLifecycleState;
  lifecycle_ref: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type WalletAccountingSemanticKind =
  | "hold_intent"
  | "burn_intent"
  | "release_intent"
  | "ledger_intent"
  | "lifecycle_intent"
  | "metadata";

export interface WalletAccountingSemantics {
  accounting_id: UUID;
  wallet_id: UUID;
  wallet_ledger_design_id?: UUID;
  wallet_state_id?: UUID;
  wallet_authorization_boundary_id?: UUID;
  hold_plan_id?: UUID;
  burn_release_plan_id?: UUID;
  mac_preparation_id?: UUID;
  ledger_entry_id?: UUID;
  economic_lifecycle_id?: UUID;
  kind: WalletAccountingSemanticKind;
  accounting_ref: UUID;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export type ExecutionAuthorizationPlanStatus =
  | "draft"
  | "ready"
  | "superseded"
  | "cancelled";

export interface ExecutionAuthorizationPlan {
  plan_id: UUID;
  agent_id: UUID;
  runtime_id: UUID;
  execution_id: UUID;
  intent_id?: UUID;
  policy_boundary_id?: UUID;
  proof_boundary_id?: UUID;
  settlement_boundary_id?: UUID;
  status: ExecutionAuthorizationPlanStatus;
  metadata_refs: UUID[];
  created_at: ISODateTime;
}

export interface ServiceConstraints {
  region?: string;
  availability?: ResourceAvailability;
  max_duration_sec?: number;
}

export interface ServicePricing {
  model: PricingModel;
  price: number;
}

export interface Service {
  service_id: UUID;
  provider: UUID;
  resource_type: ResourceType;
  subtype: ServiceSubtype;
  capabilities: ServiceCapabilities;
  constraints?: ServiceConstraints;
  pricing: ServicePricing;
}

export interface ResourceRequirements {
  cpu?: string;
  gpu?: boolean;
  gpu_model?: string;
  vram_gb?: number;
  ram_gb?: number;
  storage_gb?: number;
  bandwidth_mbps?: number;
  latency_ms?: number;
  region?: string;
}

export interface QuoteRequest {
  serviceId?: UUID;
  units?: number;
  currency: CurrencyCode;
  requirements?: Partial<Record<ResourceType, ResourceRequirements>>;
  duration_sec?: number;
  max_price?: number;
  region?: string;
}

export interface QuoteServiceAllocation {
  service_id: UUID;
  allocated: Partial<ResourceRequirements>;
  price: number;
}

export interface Quote {
  quoteId: UUID;
  serviceId: UUID;
  /** Compatibility adapter for transaction lifecycle; mirrors total_price. */
  amount: number;
  currency: CurrencyCode;
  createdAt: ISODateTime;
  expiresAt: ISODateTime;
  units: number;
  quote_id: UUID;
  services: QuoteServiceAllocation[];
  total_price: number;
  valid_until: ISODateTime;
  duration_sec?: number;
}

export interface IntentConstraints {
  max_price?: number;
  max_latency_ms?: number;
  timeout_sec?: number;
}

export interface Intent {
  intentId: UUID;
  fromWalletId: UUID;
  toServiceId: UUID;
  quoteId: UUID;
  amount: number;
  currency: CurrencyCode;
  createdAt: ISODateTime;
  expiresAt: ISODateTime;
  nonce: string;
  constraints?: IntentConstraints;
  execution_plan_id?: UUID;
  reservation_ids?: UUID[];
  metadata?: Record<string, unknown>;
}

export interface SignedIntent {
  intent: Intent;
  signature: string;
  signer: string;
}

export interface WalletPolicy {
  walletId: UUID;
  dailyLimit: number;
  allowedServices?: UUID[];
  blockedServices?: UUID[];
}

export interface WalletPolicyDecision {
  decisionId: UUID;
  allow: boolean;
  reason: string;
  evaluatedAt: ISODateTime;
  limitsApplied?: { dailyLimit: number; usedToday: number; wouldUse: number };
}

export interface LedgerEntry<T = unknown> {
  entryId: UUID;
  timestamp: ISODateTime;
  type: LedgerEntryType;
  payload: T;
}

export interface Receipt {
  receiptId: UUID;
  intentId: UUID;
  status: "accepted" | "denied";
  policyDecisionId?: UUID;
  ledgerEntryId: UUID;
  timestamp: ISODateTime;
}

export interface ResourceAllocationMetadata {
  service_id: UUID;
  provider: UUID;
  resource_type: ResourceType;
  subtype: ServiceSubtype;
  allocated: Partial<ResourceRequirements>;
  duration_sec?: number;
  total_price: number;
}

export interface TransactionRecord {
  intentId: UUID;
  state: TransactionState;
  createdAt: ISODateTime;
  updatedAt: ISODateTime;
  expiresAt?: ISODateTime;
  amount: number;
  currency: CurrencyCode;
  fromWalletId: UUID;
  toServiceId: UUID;
  constraints?: IntentConstraints;
  execution_plan_id?: UUID;
  reservation_ids?: UUID[];
  reason?: string;
  resourceAllocation?: ResourceAllocationMetadata;
  resourceAllocations?: ResourceAllocationMetadata[];
}

export interface ServiceProof {
  intentId: UUID;
  serviceId: UUID;
  resultHash: string;
  completedAt: ISODateTime;
}

export interface SignedServiceProof {
  proof: ServiceProof;
  signer: string;
  signature: string;
}

export interface SettlementResourceSummary {
  resource_type: ResourceType;
  transaction_count: number;
  total_price: number;
  total_duration_sec: number;
}

export interface SettlementProviderSummary {
  provider: UUID;
  transaction_count: number;
  total_price: number;
  total_duration_sec: number;
  resource_types: ResourceType[];
}

export interface SettlementBatch {
  batchId: UUID;
  createdAt: ISODateTime;
  intentIds: UUID[];
  totalAmount: number;
  currency: CurrencyCode;
  status: "open" | "posted";
  transaction_count: number;
  total_price: number;
  providers: UUID[];
  resource_types: ResourceType[];
  total_duration_sec: number;
  resource_summary: SettlementResourceSummary[];
  provider_summary: SettlementProviderSummary[];
}

export interface PendingSettlement {
  pending_settlement_id: UUID;
  transaction_id: UUID;
  intent_id: UUID;
  quote_id: UUID;
  total_price: number;
  currency: CurrencyCode;
  provider: UUID;
  resource_allocations?: ResourceAllocationMetadata[];
  status: PendingSettlementStatus;
  created_at: ISODateTime;
  updated_at: ISODateTime;
  finalized_at?: ISODateTime;
  failed_at?: ISODateTime;
  failure_reason?: string;
}

export interface ConcurrencyPolicy {
  policy_id: UUID;
  subject_id: UUID;
  subject_type: ConcurrencySubjectType;
  max_active_reservations?: number;
  max_active_execution_plans?: number;
  max_pending_settlements?: number;
  max_failed_steps?: number;
  max_blocked_steps?: number;
  created_at: ISODateTime;
  updated_at: ISODateTime;
}

export interface ConcurrencyObservedMetrics {
  active_reservations: number;
  active_execution_plans: number;
  pending_settlements: number;
  failed_steps: number;
  blocked_steps: number;
}

export interface ConcurrencyLimits {
  max_active_reservations?: number;
  max_active_execution_plans?: number;
  max_pending_settlements?: number;
  max_failed_steps?: number;
  max_blocked_steps?: number;
}

export interface ConcurrencyEvaluation {
  allowed: boolean;
  reasons: string[];
  observed: ConcurrencyObservedMetrics;
  limits: ConcurrencyLimits;
  notes?: string[];
}

export interface MACRecord {
  mac_id: UUID;
  subject_id: UUID;
  subject_type: MACSubjectType;
  quote_id?: UUID;
  intent_id?: UUID;
  execution_plan_id?: UUID;
  base_cost: number;
  risk_multiplier: number;
  concurrency_multiplier: number;
  failure_multiplier: number;
  final_mac: number;
  currency: MACCurrency;
  created_at: ISODateTime;
}

export interface PolicyPressure {
  pressure_id: UUID;
  subject_id: UUID;
  subject_type: PolicyPressureSubjectType;
  quote_id?: UUID;
  intent_id?: UUID;
  execution_plan_id?: UUID;
  base_pressure: number;
  concurrency_pressure: number;
  failure_pressure: number;
  settlement_pressure: number;
  policy_pressure: number;
  final_pressure: number;
  created_at: ISODateTime;
}

export interface PolicyDecision {
  decision_id: UUID;
  subject_id: UUID;
  subject_type: PolicyDecisionSubjectType;
  quote_id?: UUID;
  intent_id?: UUID;
  execution_plan_id?: UUID;
  mac_score?: number;
  pressure_score?: number;
  decision: PolicyDecisionOutcome;
  reasons: string[];
  created_at: ISODateTime;
}

export interface ReputationRecord {
  reputation_id: UUID;
  subject_id: UUID;
  subject_type: ReputationSubjectType;
  successful_events: number;
  failed_events: number;
  expired_events: number;
  denied_events: number;
  total_events: number;
  success_ratio: number;
  failure_ratio: number;
  expired_ratio: number;
  denied_ratio: number;
  created_at: ISODateTime;
  updated_at: ISODateTime;
}

export interface AuditExplanation {
  explanation_id: UUID;
  subject_id: UUID;
  subject_type: AuditExplanationSubjectType;
  source_type: AuditExplanationSourceType;
  source_id: UUID;
  summary: string;
  reasons: string[];
  evidence_refs: string[];
  severity: AuditExplanationSeverity;
  created_at: ISODateTime;
}

export interface AntiCollusionSignal {
  signal_id: UUID;
  subject_id: UUID;
  subject_type: AntiCollusionSubjectType;
  related_subject_ids: UUID[];
  signal_type: AntiCollusionSignalType;
  severity: AntiCollusionSeverity;
  score: number;
  reasons: string[];
  evidence_refs: string[];
  created_at: ISODateTime;
}

export interface ProtocolContext {
  context_id: UUID;
  subject_id: UUID;
  subject_type: ProtocolContextSubjectType;
  mac_id?: UUID;
  pressure_id?: UUID;
  policy_decision_id?: UUID;
  reputation_id?: UUID;
  anti_collusion_signal_ids: UUID[];
  audit_explanation_ids: UUID[];
  created_at: ISODateTime;
}

export interface ComposedPolicyInputRefs {
  mac_id?: UUID;
  pressure_id?: UUID;
  policy_decision_id?: UUID;
  reputation_id?: UUID;
  anti_collusion_signal_ids: UUID[];
  audit_explanation_ids: UUID[];
}

export interface ComposedPolicyDecision {
  composed_decision_id: UUID;
  context_id: UUID;
  subject_id: UUID;
  subject_type: ProtocolContextSubjectType;
  input_refs: ComposedPolicyInputRefs;
  decision: ComposedPolicyDecisionOutcome;
  reasons: string[];
  created_at: ISODateTime;
}

export interface PolicyCompositionInput {
  input_id: UUID;
  context_id: UUID;
  mac_id?: UUID;
  pressure_id?: UUID;
  policy_decision_id?: UUID;
  reputation_id?: UUID;
  anti_collusion_signal_ids: UUID[];
  audit_explanation_ids: UUID[];
  created_at: ISODateTime;
}

export interface ExecutionStep {
  step_id: UUID;
  resource_type: ResourceType;
  service_id: UUID;
  provider: UUID;
  allocated: Partial<ResourceRequirements>;
  depends_on: UUID[];
  status: ExecutionStepStatus;
  order: number;
  failure_reason?: string;
  failed_at?: ISODateTime;
  retry_count: number;
  max_retries?: number;
}

export interface ExecutionPlan {
  plan_id: UUID;
  quote_id: UUID;
  intent_id?: UUID;
  transaction_id?: UUID;
  status: ExecutionPlanStatus;
  steps: ExecutionStep[];
  created_at: ISODateTime;
  updated_at: ISODateTime;
  failure_reason?: string;
  failed_at?: ISODateTime;
}

export interface Reservation {
  reservation_id: UUID;
  execution_plan_id: UUID;
  step_id: UUID;
  resource_type: ResourceType;
  provider: UUID;
  reserved: Partial<ResourceRequirements>;
  status: ReservationStatus;
  created_at: ISODateTime;
  expires_at: ISODateTime;
  released_at?: ISODateTime;
}

/* ============================================================================
 * 4) Minimal helpers (export)
 * ========================================================================== */

/** Current time as ISO-8601 string (UTC). */
export function nowISO(): ISODateTime {
  return new Date().toISOString();
}

/**
 * Lightweight ISO-8601 check:
 * - must parse with Date without throwing
 * - must resemble `YYYY-MM-DDTHH:mm:ss(.sss)Z`
 * Not a full validator; avoids exceptions and obvious garbage.
 */
export function isISODateTime(s: string): boolean {
  if (typeof s !== "string" || s.length < 20) return false;

  // Quick shape check for common toISOString() output.
  // Example: 2026-02-02T20:15:30.123Z
  const re = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
  if (!re.test(s)) return false;

  const t = Date.parse(s);
  return Number.isFinite(t);
}

/** Assert a string is non-empty after trimming. */
export function assertNonEmptyString(name: string, value: string): void {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error(`${name} must be a non-empty string`);
  }
}

/**
 * Clamp and normalize amounts:
 * - reject NaN / Infinity
 * - reject negative amounts
 * - preserve sub-cent precision for machine-to-machine resource pricing
 */
export function clampAmount(amount: number): number {
  if (typeof amount !== "number" || !Number.isFinite(amount)) {
    throw new Error("amount must be a finite number");
  }
  if (amount < 0) {
    throw new Error("amount must be >= 0");
  }

  // Keep pricing simple while avoiding common binary floating-point artifacts.
  const rounded = Math.round(amount * 100_000_000) / 100_000_000;

  // Guard against weird float artifacts and extremely large numbers.
  if (!Number.isFinite(rounded)) {
    throw new Error("amount normalization failed");
  }

  return rounded;
}

/* ============================================================================
 * 5) Documented invariants (enforced by higher layers)
 * ========================================================================== */
/**
 * Invariants:
 * - quote.expiresAt > quote.createdAt
 * - intent.expiresAt should be short-lived (e.g. <= 5 minutes) and >= intent.createdAt
 * - intent.amount / intent.currency must match the referenced Quote
 * - intent.nonce is required and unique per wallet per day
 *   (uniqueness enforcement is implemented in policy/ledger, not here)
 */

/* ============================================================================
 * 6) API response helper type
 * ========================================================================== */

export interface TxResult {
  receipt: Receipt;
  policyDecision: WalletPolicyDecision;
  ledgerEntry: LedgerEntry;
  transaction: TransactionRecord;
}
