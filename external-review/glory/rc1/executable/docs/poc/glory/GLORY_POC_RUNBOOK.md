# Glory CRM Discount POC V1.2 — External Review Runbook

This runbook exercises a bounded, simulated CRM discount flow. It does not connect to GHL and is not a production API.

## Install and verify

Requirements: Node.js 20 or later and npm.

```powershell
npm ci
npm test
npm run test:gateway:i2
npm run test:glory
```

The Glory suite contains the 14 named acceptance cases `POC-01` through `POC-14` in `tests/poc/glory/glory-acceptance.test.ts`.

## Positive case

```powershell
npm run poc:glory -- --discount-bps 700
```

Verify in the JSON output:

- `authorization_evidence.normalized_external_decision` is `ALLOW`;
- `submitted_proof_verification.verification` is `verified_locally`;
- `authorization_evidence.guard_result` is `PASS`;
- `execution_evidence.actual_discount_bps` is `700`;
- `simulated_crm_state.approved_discount_bps` changed from the fixture value `0` to `700`;
- `simulated_effect_count` is `1`.

The emitted `trusted_verification_context` contains only the ephemeral public-key material needed by the existing local verifier. No private key is written to the repository or output.

## Mandatory negative cases

Delegated limit exceeded (DENY, no proof, no effect):

```powershell
npm run poc:glory -- --discount-bps 1500
```

Altered proof signature (BLOCK):

```powershell
npm run poc:glory -- --discount-bps 700 --tamper-proof
```

Missing proof (BLOCK):

```powershell
npm run poc:glory -- --discount-bps 700 --missing-proof
```

Target substitution (BLOCK before downstream):

```powershell
npm run poc:glory -- --discount-bps 700 --execution-target "Opportunity B"
```

Discount substitution (BLOCK before downstream):

```powershell
npm run poc:glory -- --discount-bps 700 --execution-bps 900
```

Action substitution (BLOCK before downstream):

```powershell
npm run poc:glory -- --discount-bps 700 --execution-action crm.discount.preview
```

Principal or agent substitution (BLOCK before downstream):

```powershell
npm run poc:glory -- --discount-bps 700 --execution-principal principal-attacker-999
npm run poc:glory -- --discount-bps 700 --execution-agent agent-attacker-999
```

Single-use replay (first PASS, second BLOCK, one effect):

```powershell
npm run poc:glory -- --discount-bps 700 --repeat
```

Indeterminate timeout after a possible effect (no blind retry):

```powershell
npm run poc:glory -- --discount-bps 700 --downstream timeout_after_effect --repeat
```

False adapter success claim versus authoritative CRM rejection evidence:

```powershell
npm run poc:glory -- --discount-bps 700 --downstream reject --adapter-claim SUCCEEDED
```

## Evidence locations

- Authorization Evidence: `authorization_evidence` in CLI JSON output.
- Execution Evidence: separate `execution_evidence` in CLI JSON output; it contains what the simulator actually did and contains no `authorized` claim.
- Signed proof and public verification material: `proof` and `trusted_verification_context` in CLI JSON output.
- Trusted exact-action record snapshot: `authorization_record` in CLI JSON output.
- Observable CRM state and counts: `simulated_crm_state`, `downstream_request_count`, and `simulated_effect_count`.
- Automated evidence: `tests/poc/glory/*.test.ts`.

Exact-action binding is: verified signed `authorization_decision_id` → trusted immutable process-local authorization record → exact principal, agent, action, target, and integer discount-bps comparison. One-use admission is applied separately before dispatch.

## Known limitations

- The endpoint is an in-memory simulator, not GHL.
- The signing key is test/dev-only, ephemeral, and regenerated on each process start.
- Trusted records, admission state, replay protection, CRM state, and evidence are process-local and non-durable.
- The CLI uses a fixed POC clock and deterministic fixture identities for reproducibility.
- `INDETERMINATE / REQUIRES_DETERMINATION` has no automatic retry and no full reconciliation lifecycle.
- There is no production HTTP API, external requester authentication, production key custody, deployment packaging, or high-availability claim.
- No Raspberry deployment was performed. No x86-only dependency was added; Node.js 20 ARM64 packaging and persistent state/key handling remain minor follow-up work.
- No core or T4 component is modified by the POC.

## Claims allowed

- VectorRail POC demonstrates authorization-before-execution for a bounded CRM discount scenario.
- The POC produces signed AuthorizationProof after explicit ALLOW.
- The POC blocks execution when required authorization/proof conditions fail.
- The POC binds the authorized CRM action instance through the validated POC-specific mechanism.
- The POC prevents a second consequential effect from the same authorization within the running POC process.
- Authorization Evidence and Execution Evidence are separated.

## Claims prohibited

- Production ready or enterprise ready.
- Externally or independently validated before an external reviewer completes review.
- General-purpose CRM authorization or completed GHL production integration.
- Full durable replay/reconciliation or exactly-once execution across process failures.
- T4 formal closure or general agent-governance completeness.
