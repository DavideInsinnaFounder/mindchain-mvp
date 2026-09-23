/** Command-line diagnostic harness for independent Glory POC review. */

import type { AuthorizationProof } from "../../core/contracts.js";
import {
  createGloryDemoIntent,
  createGloryPocRuntime,
  type GloryPocExecutionOptions,
} from "./poc.js";

interface CliOptions {
  discountBps: number;
  executionBps?: number;
  executionTarget?: string;
  executionAction?: string;
  executionPrincipal?: string;
  executionAgent?: string;
  missingProof: boolean;
  tamperProof: boolean;
  repeat: boolean;
  downstreamMode: "success" | "reject" | "timeout_after_effect";
  adapterClaim?: string;
}

function parseBps(value: string | undefined, flag: string): number {
  if (value === undefined || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`${flag} requires integer basis points`);
  }
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${flag} is outside the safe integer range`);
  }
  return parsed;
}

function requiredValue(value: string | undefined, flag: string): string {
  if (value === undefined || value.length === 0) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function parseArguments(args: readonly string[]): CliOptions {
  const options: CliOptions = {
    discountBps: 700,
    missingProof: false,
    tamperProof: false,
    repeat: false,
    downstreamMode: "success",
  };
  for (let index = 0; index < args.length; index += 1) {
    const flag = args[index];
    switch (flag) {
      case "--discount-bps":
        options.discountBps = parseBps(args[++index], flag);
        break;
      case "--execution-bps":
        options.executionBps = parseBps(args[++index], flag);
        break;
      case "--execution-target":
        options.executionTarget = requiredValue(args[++index], flag);
        break;
      case "--execution-action":
        options.executionAction = requiredValue(args[++index], flag);
        break;
      case "--execution-principal":
        options.executionPrincipal = requiredValue(args[++index], flag);
        break;
      case "--execution-agent":
        options.executionAgent = requiredValue(args[++index], flag);
        break;
      case "--missing-proof":
        options.missingProof = true;
        break;
      case "--tamper-proof":
        options.tamperProof = true;
        break;
      case "--repeat":
        options.repeat = true;
        break;
      case "--downstream": {
        const mode = requiredValue(args[++index], flag);
        if (
          mode !== "success" &&
          mode !== "reject" &&
          mode !== "timeout_after_effect"
        ) {
          throw new Error(
            "--downstream requires success, reject, or timeout_after_effect"
          );
        }
        options.downstreamMode = mode;
        break;
      }
      case "--adapter-claim":
        options.adapterClaim = requiredValue(args[++index], flag);
        break;
      default:
        throw new Error(`unsupported argument: ${flag}`);
    }
  }
  if (options.missingProof && options.tamperProof) {
    throw new Error("--missing-proof and --tamper-proof are mutually exclusive");
  }
  return options;
}

function alteredSignature(proof: AuthorizationProof): AuthorizationProof {
  const altered = structuredClone(proof);
  altered.signature = `${altered.signature[0] === "A" ? "B" : "A"}${altered.signature.slice(1)}`;
  return altered;
}

async function main(): Promise<void> {
  const options = parseArguments(process.argv.slice(2));
  const runtime = createGloryPocRuntime({
    downstreamMode: options.downstreamMode,
  });
  const attempt = runtime.authorize(createGloryDemoIntent(options.discountBps));
  let submittedProof = attempt.proof;
  if (options.missingProof) submittedProof = null;
  if (options.tamperProof && submittedProof !== null) {
    submittedProof = alteredSignature(submittedProof);
  }

  const executionOptions: GloryPocExecutionOptions = {
    executionOverrides: {
      ...(options.executionBps === undefined
        ? {}
        : { requested_discount_bps: options.executionBps }),
      ...(options.executionTarget === undefined
        ? {}
        : { target: options.executionTarget }),
      ...(options.executionAction === undefined
        ? {}
        : { action: options.executionAction }),
      ...(options.executionPrincipal === undefined
        ? {}
        : { principal_id: options.executionPrincipal }),
      ...(options.executionAgent === undefined
        ? {}
        : { agent_id: options.executionAgent }),
    },
    ...(options.missingProof || options.tamperProof
      ? { proof: submittedProof }
      : {}),
    ...(options.adapterClaim === undefined
      ? {}
      : { adapterClaimedDownstreamStatus: options.adapterClaim }),
  };
  const first = await runtime.execute(
    attempt.authorization_attempt_id,
    executionOptions
  );
  const replay = options.repeat
    ? await runtime.execute(attempt.authorization_attempt_id, executionOptions)
    : null;
  const decisionId = first.authorization_evidence.authorization_decision_id;

  const output = {
    scenario: options,
    trusted_verification_context: runtime.getTrustedVerificationContext(),
    submitted_proof_verification:
      submittedProof === null ? null : runtime.verifyProof(submittedProof),
    proof: first.proof,
    authorization_record:
      decisionId === null
        ? null
        : runtime.getAuthorizedActionRecord(decisionId),
    authorization_evidence: first.authorization_evidence,
    execution_evidence: first.execution_evidence,
    determination: first.determination,
    untrusted_adapter_claimed_downstream_status:
      first.untrusted_adapter_claimed_downstream_status,
    simulated_crm_state: first.simulated_opportunity,
    downstream_request_count: runtime.getRequestCount(),
    simulated_effect_count: runtime.getEffectCount(),
    replay:
      replay === null
        ? null
        : {
            authorization_evidence: replay.authorization_evidence,
            execution_evidence: replay.execution_evidence,
          },
  };
  process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : "unknown CLI failure";
  process.stderr.write(`Glory POC error: ${message}\n`);
  process.exitCode = 1;
});
