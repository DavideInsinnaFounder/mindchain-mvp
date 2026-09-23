# Glory RC1 Bounded Executable Review Runbook

**EXPORT-ONLY / NON-RC1 SEMANTIC MATERIAL**

Run every command from this `executable/` directory. These commands exercise
the frozen CLI without requiring any private-repository file.

## Install and test

```powershell
node --version
npm --version
npm ci
npm run test:glory
```

The validated export executed 31 tests: the 14 named `POC-01` through
`POC-14` cases plus 17 supporting bounded cases.

## CLI falsification matrix

ALLOW, one authoritative CRM effect:

```powershell
npm run poc:glory -- --discount-bps 700
```

DENY/STOP, no proof and no dispatch:

```powershell
npm run poc:glory -- --discount-bps 1500
```

Tampered proof and missing proof:

```powershell
npm run poc:glory -- --discount-bps 700 --tamper-proof
npm run poc:glory -- --discount-bps 700 --missing-proof
```

Exact target, discount, and action substitution:

```powershell
npm run poc:glory -- --discount-bps 700 --execution-target "Opportunity B"
npm run poc:glory -- --discount-bps 700 --execution-bps 900
npm run poc:glory -- --discount-bps 700 --execution-action crm.discount.preview
```

Exact principal and agent substitution:

```powershell
npm run poc:glory -- --discount-bps 700 --execution-principal principal-attacker-999
npm run poc:glory -- --discount-bps 700 --execution-agent agent-attacker-999
```

Single-use replay:

```powershell
npm run poc:glory -- --discount-bps 700 --repeat
```

Timeout after a possible effect plus a repeat attempt:

```powershell
npm run poc:glory -- --discount-bps 700 --downstream timeout_after_effect --repeat
```

Authoritative CRM rejection versus an untrusted adapter success claim:

```powershell
npm run poc:glory -- --discount-bps 700 --downstream reject --adapter-claim SUCCEEDED
```

For each command inspect `authorization_evidence`, `execution_evidence`,
`determination`, `simulated_crm_state`, `downstream_request_count`,
`simulated_effect_count`, and `replay`. The validated expected/actual matrix is
recorded in `RC1_REPRODUCIBILITY_REPORT.md`; a reviewer should try to falsify
it rather than assume it.

## Integrity

`RC1_FILE_HASHES.sha256` contains one SHA-256 line for every reviewer-visible
file other than the hash manifest itself. The manifest cannot hash itself
without recursion; the frozen public Git commit and optional annotated tag
bind that final file.

## Do not infer

This is an in-memory simulator with an ephemeral test/dev signing key.
Authorization records, admission state, replay state, CRM state, and evidence
are process-local. Do not infer production GHL integration, durable
exactly-once behavior, complete reconciliation, production key custody, or an
external-review PASS.
