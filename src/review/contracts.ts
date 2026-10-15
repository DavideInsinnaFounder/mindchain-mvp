export type ISODateTime = string;

export type UUID = string;

export type ProviderScope = { mode: "exact"; provider_id: UUID };

export type ServiceScope = {
    service_id: UUID;
};

export type ExecutionScope = { mode: "exact"; execution_id: UUID; operation_type: string };

export type UsageLimit = { mode: "single_use"; maximum_usage_count: 1 };

export type EconomicScope = { mode: "none" };

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

export function isISODateTime(s: string): boolean {
    if (typeof s !== "string" || s.length < 20)
        return false;
    const re = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
    if (!re.test(s))
        return false;
    const t = Date.parse(s);
    return Number.isFinite(t);
}
