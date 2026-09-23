/**
 * Runtime AuthorizationProof issuer for the bounded simulated Glory POC.
 * It reuses the existing proof envelope, identity and Ed25519 protocol.
 */

import {
  createPublicKey,
  generateKeyPairSync,
  sign as signEd25519,
} from "node:crypto";
import type { AuthorizationProof, AuthorizationProofPayload } from "../../core/contracts.js";
import {
  AUTHORIZATION_PROOF_CANONICALIZATION_VERSION,
  AUTHORIZATION_PROOF_PROTOCOL_VERSION,
  encodeAuthorizationProofIdentity,
} from "../../core/authorization_proof.js";
import { createAuthorizationProofEnvelope } from "../../core/authorization_proof_issuance.js";
import {
  AUTHORIZATION_PROOF_SIGNATURE_MESSAGE_DOMAIN,
  LOCAL_AUTHORIZATION_PROOF_ALGORITHM_ID,
  verifyAuthorizationProofLocally,
  type SuppliedLocalAuthorizationProofVerificationMaterial,
} from "../../core/authorization_proof_verification.js";
import type { GloryAuthorizationRecordAuthority } from "./authorization_records.js";

export const GLORY_POC_ISSUER_ID = "vectorrail-glory-poc-issuer";
export const GLORY_POC_AUDIENCE = "vectorrail-glory-poc";
export const GLORY_POC_RUNTIME_ID = "vectorrail-glory-poc-runtime";
export const GLORY_POC_PROVIDER_ID = "glory-simulated-crm-provider";
export const GLORY_POC_SERVICE_ID = "glory-simulated-crm-service";
export const GLORY_POC_POLICY_DIGEST = "policy:glory-discount-poc:v1";
export const GLORY_POC_PROOF_VALIDITY_MS = 30_000;

export interface GloryProofSigner {
  algorithm_id: typeof LOCAL_AUTHORIZATION_PROOF_ALGORITHM_ID;
  issuer_key_id: string;
  public_key_spki_der_base64url: string;
  signMessage(message: Uint8Array): string;
}

export interface GloryTrustedProofVerificationContext {
  issuer_id: typeof GLORY_POC_ISSUER_ID;
  audience: typeof GLORY_POC_AUDIENCE;
  runtime_id: typeof GLORY_POC_RUNTIME_ID;
  provider_id: typeof GLORY_POC_PROVIDER_ID;
  service_id: typeof GLORY_POC_SERVICE_ID;
  operation_type: "crm.discount.apply";
  policy_digest: typeof GLORY_POC_POLICY_DIGEST;
  policy_epoch: 1;
  revocation_epoch: 0;
  key_status: "active";
  maximum_validity_ms: typeof GLORY_POC_PROOF_VALIDITY_MS;
  verification_material: SuppliedLocalAuthorizationProofVerificationMaterial;
}

export type GloryProofIssuanceResult =
  | { issuance: "issued"; proof: AuthorizationProof }
  | {
      issuance: "not_issued";
      reason:
        | "authorization_record_not_found"
        | "authorization_record_not_current"
        | "invalid_clock"
        | "signing_failed"
        | "proof_self_verification_failed";
    };

export interface GloryRuntimeProofIssuer {
  issueForDecision(authorizationDecisionId: string): GloryProofIssuanceResult;
  getTrustedVerificationContext(): Readonly<GloryTrustedProofVerificationContext>;
}

export interface CreateGloryRuntimeProofIssuerInput {
  records: GloryAuthorizationRecordAuthority;
  signer: GloryProofSigner;
  clock: { now(): Date };
}

function snapshotVerificationContext(
  context: GloryTrustedProofVerificationContext
): Readonly<GloryTrustedProofVerificationContext> {
  return Object.freeze({
    ...context,
    verification_material: Object.freeze({ ...context.verification_material }),
  });
}

/** Creates a test/dev-only ephemeral Ed25519 signer; no private key is persisted. */
export function createEphemeralGloryPocSigner(
  issuerKeyId = "glory-poc-ephemeral-key"
): GloryProofSigner {
  if (issuerKeyId.trim().length === 0) {
    throw new Error("glory_poc_issuer_key_id_invalid");
  }
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const publicKeySpki = publicKey
    .export({ format: "der", type: "spki" })
    .toString("base64url");
  return Object.freeze({
    algorithm_id: LOCAL_AUTHORIZATION_PROOF_ALGORITHM_ID,
    issuer_key_id: issuerKeyId,
    public_key_spki_der_base64url: publicKeySpki,
    signMessage(message: Uint8Array): string {
      return signEd25519(null, Buffer.from(message), privateKey).toString("base64url");
    },
  });
}

function signatureMessage(payload: AuthorizationProofPayload): Buffer {
  return Buffer.concat([
    Buffer.from(AUTHORIZATION_PROOF_SIGNATURE_MESSAGE_DOMAIN, "utf8"),
    Buffer.from(encodeAuthorizationProofIdentity(payload)),
  ]);
}

export function createGloryRuntimeProofIssuer(
  input: CreateGloryRuntimeProofIssuerInput
): GloryRuntimeProofIssuer {
  if (
    input.signer.algorithm_id !== LOCAL_AUTHORIZATION_PROOF_ALGORITHM_ID ||
    input.signer.issuer_key_id.trim().length === 0 ||
    input.signer.public_key_spki_der_base64url.trim().length === 0
  ) {
    throw new Error("glory_poc_signer_invalid");
  }

  // Parse/re-export now so malformed or non-Ed25519 public material never enters
  // the trusted runtime context.
  const canonicalPublicKey = createPublicKey({
    key: Buffer.from(input.signer.public_key_spki_der_base64url, "base64url"),
    format: "der",
    type: "spki",
  });
  if (
    canonicalPublicKey.asymmetricKeyType !== "ed25519" ||
    canonicalPublicKey
      .export({ format: "der", type: "spki" })
      .toString("base64url") !== input.signer.public_key_spki_der_base64url
  ) {
    throw new Error("glory_poc_signer_public_key_invalid");
  }

  const context = snapshotVerificationContext({
    issuer_id: GLORY_POC_ISSUER_ID,
    audience: GLORY_POC_AUDIENCE,
    runtime_id: GLORY_POC_RUNTIME_ID,
    provider_id: GLORY_POC_PROVIDER_ID,
    service_id: GLORY_POC_SERVICE_ID,
    operation_type: "crm.discount.apply",
    policy_digest: GLORY_POC_POLICY_DIGEST,
    policy_epoch: 1,
    revocation_epoch: 0,
    key_status: "active",
    maximum_validity_ms: GLORY_POC_PROOF_VALIDITY_MS,
    verification_material: {
      algorithm_id: input.signer.algorithm_id,
      issuer_key_id: input.signer.issuer_key_id,
      public_key_spki_der_base64url: input.signer.public_key_spki_der_base64url,
    },
  });

  return Object.freeze({
    issueForDecision(authorizationDecisionId: string): GloryProofIssuanceResult {
      const record = input.records.resolveByDecisionId(authorizationDecisionId);
      if (record === null || record.internal_decision !== "ALLOW") {
        return Object.freeze({
          issuance: "not_issued",
          reason: "authorization_record_not_found",
        });
      }

      let now: Date;
      try {
        now = input.clock.now();
      } catch {
        return Object.freeze({ issuance: "not_issued", reason: "invalid_clock" });
      }
      const nowMs = now.getTime();
      if (!Number.isFinite(nowMs)) {
        return Object.freeze({ issuance: "not_issued", reason: "invalid_clock" });
      }
      const expiresAtMs = Math.min(
        nowMs + GLORY_POC_PROOF_VALIDITY_MS,
        Date.parse(record.intent_expires_at)
      );
      if (nowMs < Date.parse(record.decided_at) || expiresAtMs <= nowMs) {
        return Object.freeze({
          issuance: "not_issued",
          reason: "authorization_record_not_current",
        });
      }

      const nowIso = now.toISOString();
      const payload: AuthorizationProofPayload = {
        protocol_version: AUTHORIZATION_PROOF_PROTOCOL_VERSION,
        canonicalization_version: AUTHORIZATION_PROOF_CANONICALIZATION_VERSION,
        issuer_id: context.issuer_id,
        issuer_key_id: context.verification_material.issuer_key_id,
        principal_id: record.principal_id,
        subject_agent_id: record.agent_id,
        delegator_id: record.principal_id,
        audience: context.audience,
        runtime_id: context.runtime_id,
        provider_scope: { mode: "exact", provider_id: context.provider_id },
        service_scope: { service_id: context.service_id },
        execution_scope: {
          mode: "exact",
          execution_id: record.execution_id,
          operation_type: record.action,
        },
        authorization_request_id: record.authorization_request_id,
        authorization_decision_id: record.authorization_decision_id,
        policy_digest: context.policy_digest,
        policy_epoch: context.policy_epoch,
        issued_at: nowIso,
        valid_from: nowIso,
        expires_at: new Date(expiresAtMs).toISOString(),
        revocation_epoch: context.revocation_epoch,
        usage: { mode: "single_use", maximum_usage_count: 1 },
        // Discount basis points are deliberately not payment/economic amount.
        economic_scope: { mode: "none" },
        delegation_constraints: { delegation_mode: "delegated" },
        algorithm_id: context.verification_material.algorithm_id,
      };

      let proof: AuthorizationProof;
      try {
        const signature = input.signer.signMessage(signatureMessage(payload));
        proof = createAuthorizationProofEnvelope({
          payload,
          decision_provenance: {
            authorization_request_id: record.authorization_request_id,
            authorization_decision_id: record.authorization_decision_id,
            policy_digest: context.policy_digest,
            policy_epoch: context.policy_epoch,
          },
          signature,
        });
      } catch {
        return Object.freeze({ issuance: "not_issued", reason: "signing_failed" });
      }

      const verification = verifyAuthorizationProofLocally({
        proof,
        verification_material: context.verification_material,
      });
      if (verification.verification !== "verified_locally") {
        return Object.freeze({
          issuance: "not_issued",
          reason: "proof_self_verification_failed",
        });
      }
      return Object.freeze({ issuance: "issued", proof });
    },

    getTrustedVerificationContext() {
      return snapshotVerificationContext(context);
    },
  });
}
