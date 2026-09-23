# Glory CRM Discount POC V1.2 RC1 — Bounded Executable Export

**EXPORT-ONLY / NON-RC1 SEMANTIC MATERIAL**

This directory is the bounded public executable surface for attempting to
falsify Glory CRM Discount POC V1.2 RC1. It is not the private engineering
repository and does not expose its history or unrelated work.

## Frozen identity

- source tag: `glory-poc-v1.2-external-review-rc1`
- annotated tag object: `183bfa35b2ba4e96b5b20ab605fa3323e5b97bc7`
- tag signature: unsigned (expected; not an RC1 implementation failure)
- source commit: `2606358ab9a591b67f047a3b9a84032d2b5ffc9e`
- source tree: `2851356d28711fcfee30c201724caea00fec3e7f`
- source branch: `poc/glory-v1-2-minimum-build`

The substantive TypeScript and frozen source runbook in this export are
byte-identical to that commit. See `RC1_SOURCE_PROVENANCE.json`.

## Run the bounded package

Requirements: Node.js 20 or later and npm.

```powershell
npm ci
npm run test:glory
npm run poc:glory -- --discount-bps 700
```

Use `EXTERNAL_REVIEW_RUNBOOK.md` for all adversarial CLI commands. The frozen
source runbook is retained at `docs/poc/glory/GLORY_POC_RUNBOOK.md` for byte
provenance, but its broad private-repository test commands are intentionally
not part of this minimum export. `npm run test:glory` is the governing exported
test command.

## What is included

- seven frozen Glory implementation files and the frozen CLI;
- five frozen Glory test files;
- the exact seven-file transitive core import closure;
- the byte-identical frozen Glory runbook;
- minimal export-only package metadata and review evidence.

`RC1_DEPENDENCY_CLOSURE.json` records every static internal import edge, Git
blob identity, Node built-in, and npm runner dependency. Unresolved internal
dependencies are zero.

## Verified mechanism and limits

The frozen code implements exact-action binding as:

```text
verified signed authorization_decision_id
-> trusted immutable process-local authorization record
-> exact principal + agent + action + target + integer discount-bps comparison
-> Execution Guard
```

One-use admission is a separate process-local step after authorization/proof
checks and before downstream dispatch. It is not durable exactly-once behavior
across process failure.

Authorization evidence and simulated CRM execution evidence remain separate.
An adapter claim cannot replace authoritative simulator evidence. A timeout
after a possible effect returns `INDETERMINATE / REQUIRES_DETERMINATION` and is
not blindly retried; RC1 does not implement complete reconciliation.

## Claim boundary

This package is provided for independent falsification. It does not claim
production readiness, enterprise readiness, production GHL integration,
durable exactly-once execution, full reconciliation, general agent-governance
completeness, Token T4 closure, or an external-review PASS.

The hash manifest covers every reviewer-visible file except itself; this
non-recursive exclusion is documented in `RC1_FILE_HASHES.sha256`.
