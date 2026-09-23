/**
 * Minimal process-local CRM simulator for the Glory POC.
 * It is authoritative only for the state it changed and receipts it emitted;
 * it does not receive AuthorizationProof and makes no authorization decision.
 */

import { GLORY_MAX_DISCOUNT_BPS } from "./authorization.js";
import type {
  GloryCrmDispatchResult,
  GloryCrmExecutionCommand,
  GloryCrmExecutionPort,
  GloryExecutionEvidence,
} from "./execution_guard.js";

export interface SimulatedGloryOpportunitySeed {
  opportunity_id: string;
  approved_discount_bps: number;
}

export interface SimulatedGloryOpportunityState {
  opportunity_id: string;
  approved_discount_bps: number;
  execution_id: string | null;
  authorization_correlation_id: string | null;
  execution_status: "NOT_EXECUTED" | "APPLIED";
  executed_at: string | null;
}

export interface SimulatedGloryCrm extends GloryCrmExecutionPort {
  getOpportunity(opportunityId: string): SimulatedGloryOpportunityState | null;
  getExecutionEvidence(executionId: string): GloryExecutionEvidence | null;
  getRequestCount(): number;
  getEffectCount(): number;
}

export interface CreateSimulatedGloryCrmInput {
  opportunities: readonly SimulatedGloryOpportunitySeed[];
  clock: { now(): Date };
  /** Test-only determinate downstream rejection before any CRM effect. */
  rejectBeforeEffect?: boolean;
  /** Test-only fault: commit the effect, then lose the downstream response. */
  timeoutAfterEffect?: boolean;
}

function validBps(value: unknown): value is number {
  return typeof value === "number" &&
    Number.isSafeInteger(value) &&
    value >= 0 &&
    value <= GLORY_MAX_DISCOUNT_BPS;
}

function requiredString(value: unknown): string {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new Error("simulated_glory_crm_command_invalid");
  }
  return value;
}

function snapshotOpportunity(
  state: SimulatedGloryOpportunityState
): SimulatedGloryOpportunityState {
  return Object.freeze({ ...state });
}

function snapshotEvidence(
  evidence: GloryExecutionEvidence
): GloryExecutionEvidence {
  return Object.freeze({ ...evidence });
}

function snapshotCommand(
  command: Readonly<GloryCrmExecutionCommand>
): GloryCrmExecutionCommand {
  if (command === null || typeof command !== "object" || Array.isArray(command)) {
    throw new Error("simulated_glory_crm_command_invalid");
  }
  const executionId = requiredString(command.execution_id);
  const opportunityId = requiredString(command.opportunity_id);
  const authorizationCorrelationId = requiredString(
    command.authorization_correlation_id
  );
  if (!validBps(command.discount_bps)) {
    throw new Error("simulated_glory_crm_command_invalid");
  }
  return Object.freeze({
    execution_id: executionId,
    opportunity_id: opportunityId,
    discount_bps: command.discount_bps,
    authorization_correlation_id: authorizationCorrelationId,
  });
}

export function createSimulatedGloryCrm(
  input: CreateSimulatedGloryCrmInput
): SimulatedGloryCrm {
  if (input.rejectBeforeEffect === true && input.timeoutAfterEffect === true) {
    throw new Error("simulated_glory_crm_fault_mode_conflict");
  }
  const opportunities = new Map<string, SimulatedGloryOpportunityState>();
  for (const seed of input.opportunities) {
    if (
      typeof seed.opportunity_id !== "string" ||
      seed.opportunity_id.trim().length === 0 ||
      !validBps(seed.approved_discount_bps)
    ) {
      throw new Error("simulated_glory_crm_opportunity_invalid");
    }
    if (opportunities.has(seed.opportunity_id)) {
      throw new Error("simulated_glory_crm_opportunity_duplicate");
    }
    opportunities.set(
      seed.opportunity_id,
      snapshotOpportunity({
        opportunity_id: seed.opportunity_id,
        approved_discount_bps: seed.approved_discount_bps,
        execution_id: null,
        authorization_correlation_id: null,
        execution_status: "NOT_EXECUTED",
        executed_at: null,
      })
    );
  }

  const receipts = new Map<string, GloryExecutionEvidence>();
  let requestCount = 0;
  let effectCount = 0;

  return Object.freeze({
    async applyDiscount(
      commandInput: Readonly<GloryCrmExecutionCommand>
    ): Promise<GloryCrmDispatchResult> {
      requestCount += 1;
      const command = snapshotCommand(commandInput);
      const previousReceipt = receipts.get(command.execution_id);
      if (previousReceipt !== undefined) {
        if (
          previousReceipt.opportunity_id !== command.opportunity_id ||
          previousReceipt.actual_discount_bps !== command.discount_bps ||
          previousReceipt.authorization_correlation_id !==
            command.authorization_correlation_id
        ) {
          throw new Error("simulated_glory_crm_execution_conflict");
        }
        return Object.freeze({
          outcome:
            previousReceipt.execution_status === "APPLIED"
              ? "SUCCEEDED"
              : "REJECTED",
          execution_evidence: snapshotEvidence(previousReceipt),
        });
      }

      const current = opportunities.get(command.opportunity_id);
      if (current === undefined) {
        throw new Error("simulated_glory_crm_opportunity_not_found");
      }
      const executedAt = input.clock.now().toISOString();
      if (input.rejectBeforeEffect === true) {
        const rejectedReceipt = snapshotEvidence({
          execution_id: command.execution_id,
          opportunity_id: command.opportunity_id,
          actual_discount_bps: current.approved_discount_bps,
          execution_status: "REJECTED",
          executed_at: executedAt,
          authorization_correlation_id: command.authorization_correlation_id,
        });
        receipts.set(command.execution_id, rejectedReceipt);
        return Object.freeze({
          outcome: "REJECTED",
          execution_evidence: snapshotEvidence(rejectedReceipt),
        });
      }
      const next = snapshotOpportunity({
        opportunity_id: current.opportunity_id,
        approved_discount_bps: command.discount_bps,
        execution_id: command.execution_id,
        authorization_correlation_id: command.authorization_correlation_id,
        execution_status: "APPLIED",
        executed_at: executedAt,
      });
      const receipt = snapshotEvidence({
        execution_id: command.execution_id,
        opportunity_id: command.opportunity_id,
        actual_discount_bps: command.discount_bps,
        execution_status: "APPLIED",
        executed_at: executedAt,
        authorization_correlation_id: command.authorization_correlation_id,
      });

      opportunities.set(command.opportunity_id, next);
      receipts.set(command.execution_id, receipt);
      effectCount += 1;

      if (input.timeoutAfterEffect === true) {
        throw new Error("simulated_glory_crm_timeout_after_effect");
      }
      return Object.freeze({
        outcome: "SUCCEEDED",
        execution_evidence: snapshotEvidence(receipt),
      });
    },

    getOpportunity(opportunityId: string) {
      const value = opportunities.get(opportunityId);
      return value === undefined ? null : snapshotOpportunity(value);
    },

    getExecutionEvidence(executionId: string) {
      const value = receipts.get(executionId);
      return value === undefined ? null : snapshotEvidence(value);
    },

    getRequestCount() {
      return requestCount;
    },

    getEffectCount() {
      return effectCount;
    },
  });
}
