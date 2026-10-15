/** Trusted, process-local authorization records for the bounded Glory POC. */

import { randomUUID } from "node:crypto";
import {
  authorizeGloryDiscountIntent,
  type GloryAuthorizationEvaluation,
  type GloryBusinessIntent,
  type GloryTrustedDelegationAuthority,
} from "./authorization.js";

export interface GloryAuthorizedActionRecord {
  authorization_request_id: string;
  authorization_decision_id: string;
  execution_id: string;
  intent_id: string;
  principal_id: string;
  agent_id: string;
  action: "crm.discount.apply";
  target: string;
  requested_discount_bps: number;
  delegated_limit_bps: number;
  internal_decision: "ALLOW";
  decided_at: string;
  intent_expires_at: string;
}

export interface GloryAuthorizationRecordingResult {
  evaluation: GloryAuthorizationEvaluation;
  authorization_record: Readonly<GloryAuthorizedActionRecord> | null;
}

export interface GloryAuthorizationRecordAuthority {
  authorizeAndRecord(rawIntent: unknown, now: Date): GloryAuthorizationRecordingResult;
  resolveByDecisionId(
    authorizationDecisionId: string
  ): Readonly<GloryAuthorizedActionRecord> | null;
}

export interface CreateGloryAuthorizationRecordAuthorityInput {
  delegations: GloryTrustedDelegationAuthority;
  /** Trusted server-side source. It is never read from Business Intent. */
  decisionIdSource?: () => string;
}

function snapshotRecord(
  record: GloryAuthorizedActionRecord
): Readonly<GloryAuthorizedActionRecord> {
  return Object.freeze({ ...record });
}

function requiredGeneratedId(value: unknown): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("glory_authorization_decision_id_invalid");
  }
  return value;
}

export function createGloryAuthorizationRecordAuthority(
  input: CreateGloryAuthorizationRecordAuthorityInput
): GloryAuthorizationRecordAuthority {
  const decisionIdSource = input.decisionIdSource ?? randomUUID;
  const records = new Map<string, Readonly<GloryAuthorizedActionRecord>>();

  return Object.freeze({
    authorizeAndRecord(rawIntent: unknown, now: Date): GloryAuthorizationRecordingResult {
      const evaluation = authorizeGloryDiscountIntent(rawIntent, input.delegations, now);
      if (
        evaluation.internal_decision !== "ALLOW" ||
        evaluation.external_decision !== "ALLOW" ||
        evaluation.intent === null ||
        evaluation.resolved_principal_id === null ||
        evaluation.delegated_limit_bps === null
      ) {
        return Object.freeze({ evaluation, authorization_record: null });
      }

      const intent: Readonly<GloryBusinessIntent> = evaluation.intent;
      const authorizationDecisionId = requiredGeneratedId(decisionIdSource());
      if (records.has(authorizationDecisionId)) {
        throw new Error("glory_authorization_decision_id_conflict");
      }
      const record = snapshotRecord({
        authorization_request_id: intent.intent_id,
        authorization_decision_id: authorizationDecisionId,
        execution_id: `glory-execution:${authorizationDecisionId}`,
        intent_id: intent.intent_id,
        principal_id: evaluation.resolved_principal_id,
        agent_id: intent.agent_id,
        action: intent.action,
        target: intent.target,
        requested_discount_bps: intent.requested_discount_bps,
        delegated_limit_bps: evaluation.delegated_limit_bps,
        internal_decision: "ALLOW",
        decided_at: now.toISOString(),
        intent_expires_at: intent.expires_at,
      });
      records.set(authorizationDecisionId, record);
      return Object.freeze({
        evaluation,
        authorization_record: snapshotRecord(record),
      });
    },

    resolveByDecisionId(
      authorizationDecisionId: string
    ): Readonly<GloryAuthorizedActionRecord> | null {
      const record = records.get(authorizationDecisionId);
      return record === undefined ? null : snapshotRecord(record);
    },
  });
}
