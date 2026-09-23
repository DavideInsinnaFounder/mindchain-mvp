# Glory CRM Discount POC V1.2 RC1 — Reproducibility Report

**EXPORT-ONLY / NON-RC1 SEMANTIC MATERIAL**

## Verdict

```text
SOURCE IDENTITY VERIFIED = YES
DEPENDENCY CLOSURE = VERIFIED
UNRESOLVED INTERNAL DEPENDENCIES = 0
SOURCE BYTE PROVENANCE = PASS
npm ci = PASS
npm run test:glory = PASS
CLI ADVERSARIAL SCENARIOS = 12 / 12 PASS
SECRET SCAN = PASS
DISCLOSURE SCAN = PASS
REPRODUCIBILITY = PASS
RC1 SEMANTICS MODIFIED = NO
```

This is internal publication-gate evidence, not an external-review PASS.

## Source identity

- tag: `glory-poc-v1.2-external-review-rc1`
- annotated tag object: `183bfa35b2ba4e96b5b20ab605fa3323e5b97bc7`
- annotated tag signature: unsigned
- peeled commit: `2606358ab9a591b67f047a3b9a84032d2b5ffc9e`
- commit tree: `2851356d28711fcfee30c201724caea00fec3e7f`
- branch: `poc/glory-v1-2-minimum-build`
- remote branch head equals source commit: yes

The unsigned annotated source tag was expected and was not treated as an RC1
implementation failure.

## Dependency closure

Recursive traversal began from seven Glory implementation/CLI files and five
Glory test files. It resolved 19 frozen TypeScript files in total, including
seven unique transitive core files, across 55 internal import edges. It also
found 14 Node built-in import edges and no npm import in substantive source.

`tsx@4.21.0` is the sole direct npm runner dependency. The export-only lock has
31 npm package entries including platform-conditional esbuild packages.
Unresolved internal dependencies: zero. Full edge and Git-blob evidence is in
`RC1_DEPENDENCY_CLOSURE.json`.

## Environment and clean execution

```text
Node.js = v24.14.1
npm = 11.11.0
required Node.js = >=20
npm ci = PASS (5 packages installed)
npm run test:glory = PASS
tests = 31
passed = 31
failed = 0
```

The clean install and test ran from the bounded export directory. The package
contains no relative import outside the export and no private-repository
dependency.

## CLI adversarial execution

`DISPATCH COUNT` below is the frozen CLI's `downstream_request_count`; `EFFECT
COUNT` is `simulated_effect_count`.

| ID | Command | Expected frozen behavior | Actual result | Dispatch | Effect | Result |
|---|---|---|---|---:|---:|---|
| CLI-01 | `npm run poc:glory -- --discount-bps 700` | ALLOW, verified proof, guard PASS, CRM applies 700 | ALLOW; `verified_locally`; PASS; `SUCCEEDED/APPLIED`; 700 bps | 1 | 1 | PASS |
| CLI-02 | `npm run poc:glory -- --discount-bps 1500` | DENY/STOP, no proof, no dispatch | DENY; STOP; `NOT_ELIGIBLE`; guard `NOT_REACHED`; `NOT_SENT` | 0 | 0 | PASS |
| CLI-03 | `npm run poc:glory -- --discount-bps 700 --tamper-proof` | Altered signature blocked before dispatch | `not_verified/invalid_signature`; BLOCK `proof_verification_failed` | 0 | 0 | PASS |
| CLI-04 | `npm run poc:glory -- --discount-bps 700 --missing-proof` | Missing proof blocked before dispatch | BLOCK `invalid_execution_request`; `NOT_SENT` | 0 | 0 | PASS |
| CLI-05 | `npm run poc:glory -- --discount-bps 700 --execution-target "Opportunity B"` | Target substitution blocked | BLOCK `target_mismatch`; `NOT_SENT` | 0 | 0 | PASS |
| CLI-06 | `npm run poc:glory -- --discount-bps 700 --execution-bps 900` | Discount substitution blocked | BLOCK `discount_mismatch`; `NOT_SENT` | 0 | 0 | PASS |
| CLI-07 | `npm run poc:glory -- --discount-bps 700 --execution-action crm.discount.preview` | Action substitution blocked | BLOCK `action_mismatch`; `NOT_SENT` | 0 | 0 | PASS |
| CLI-08 | `npm run poc:glory -- --discount-bps 700 --execution-principal principal-attacker-999` | Principal substitution blocked | BLOCK `principal_mismatch`; `NOT_SENT` | 0 | 0 | PASS |
| CLI-09 | `npm run poc:glory -- --discount-bps 700 --execution-agent agent-attacker-999` | Agent substitution blocked | BLOCK `agent_mismatch`; `NOT_SENT` | 0 | 0 | PASS |
| CLI-10 | `npm run poc:glory -- --discount-bps 700 --repeat` | First execution succeeds; replay blocked; one effect | First PASS/APPLIED; second BLOCK `authorization_replay` and `NOT_SENT` | 1 | 1 | PASS |
| CLI-11 | `npm run poc:glory -- --discount-bps 700 --downstream timeout_after_effect --repeat` | Possible effect becomes indeterminate; repeat blocked; no blind retry | PASS; `INDETERMINATE`; `REQUIRES_DETERMINATION`; second BLOCK `authorization_replay`; CRM state 700 | 1 | 1 | PASS |
| CLI-12 | `npm run poc:glory -- --discount-bps 700 --downstream reject --adapter-claim SUCCEEDED` | Adapter claim cannot override authoritative CRM rejection | Adapter says `SUCCEEDED`; downstream/evidence say `REJECTED`; CRM remains 0 | 1 | 0 | PASS |

## Frozen-code mechanism review

The expected exact-action description matches the frozen code without
discrepancy:

```text
verified signed authorization_decision_id
-> trusted immutable process-local authorization record
-> exact principal + agent + action + target + integer discount-bps comparison
-> Execution Guard
```

The proof signs the authorization decision anchor and exact execution ID/action.
The trusted process-local record supplies the target and requested integer bps
that the guard compares to the execution request. This is the actual frozen
mechanism; no stronger direct proof-payload target/bps claim is made.

## Admission versus authorization

After proof, trusted-context, time, authorization-record, and exact-action
checks, `execution_guard.ts` invokes the process-local atomic admission
authority. A committed first-use admission occurs before downstream dispatch;
a second use is blocked before dispatch.

This admission is not durable across process failure and does not establish
durable exactly-once behavior.

## Authorization versus execution evidence

Authorization evidence records the decision, proof issuance, guard result, and
downstream outcome. Execution evidence is emitted separately by the simulated
CRM and describes the effect it actually applied or rejected. CLI-12 confirms
that an untrusted adapter `SUCCEEDED` claim does not replace authoritative CRM
`REJECTED` evidence.

## Indeterminate path

CLI-11 confirms the frozen limitation: timeout after a possible effect returns
`INDETERMINATE / REQUIRES_DETERMINATION`; the effect may already exist and the
same authorization is not blindly retried. RC1 has no complete reconciliation
or automatic crash-safe determination lifecycle.

## Packaging differences

- The private root package metadata is not published because it contains
  unrelated scripts and dependencies.
- Export-only `package.json` exposes only `test:glory` and `poc:glory`, with
  exact `tsx@4.21.0`.
- Export-only `package-lock.json` contains only the runner closure and pins the
  frozen-source transitive versions. npm generated `get-tsconfig@4.13.7` under
  `tsx`; the version matches the frozen private lock.
- Export-only `tsconfig.json` is scoped to exported `src` and `tests`.
- The byte-identical frozen runbook remains for provenance, but its unrelated
  broad-repository test commands are not available. This export's governing
  commands are in `EXTERNAL_REVIEW_RUNBOOK.md`.
- The pre-build evidence file, minimum-build plan, and private reality map are
  excluded because they are not executable dependencies and expose stale or
  unrelated private inventory.

These are packaging differences only. No substantive RC1 source byte changed.

## Security and disclosure

The complete reviewer-visible export was scanned for private-key blocks,
credential/token formats, assigned secrets, `.env` material, private absolute
paths, private Git metadata/history, Token T4 source paths, unrelated POC
source, roadmap/investor/commercial material, and files outside the declared
inventory.

```text
SECRET SCAN = PASS
DISCLOSURE SCAN = PASS
```

Boundary-only prose stating that Token T4 is not included is not Token T4
source and is retained where required to prevent scope inflation.

## Known RC1 limitations

- in-memory simulated CRM; no production GHL connection;
- ephemeral test/dev Ed25519 signer; no production key custody;
- process-local authorization records, admission/replay state, CRM state, and
  evidence;
- no durable exactly-once guarantee across process failure;
- no full reconciliation or automatic determination lifecycle;
- no production HTTP API, external requester authentication, deployment
  packaging, or high availability;
- no production-readiness, enterprise-readiness, general governance, or
  external-review PASS claim.

## Unresolved items

```text
UNRESOLVED INTERNAL DEPENDENCIES = 0
UNRESOLVED PUBLICATION GATE ITEMS = 0
EXTERNAL REVIEW = NOT YET PERFORMED
```
