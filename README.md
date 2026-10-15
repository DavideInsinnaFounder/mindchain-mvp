# VectorRail — public reference and Glory RC1

VectorRail explores infrastructure for autonomous agents through two connected pillars:

- **Machine Economy:** AI-to-AI and machine-to-machine (M2M) micropayments, transactions and settlement between autonomous participants. This public repository describes that product scope without providing payment or settlement implementations.
- **Governance:** identity, delegation, policy, authorization and control of autonomous agents. The runnable RC1 demonstration shows a bounded governance workflow using synthetic identities and a simulated CRM discount action.

## Bounded RC1 demonstration

Release identity: `VECTORRAIL_GLORY_RC1_SANITIZED_R1`.

This self-contained review derivative preserves the original bounded CRM logic and acceptance test bodies, with imports redirected to a reduced review implementation. It accepts only exact provider and execution scopes, single use and economic scope `none`. Unsupported scopes fail closed. No private repository, private package, service credential or production account is required.

The runtime binds a verified signed decision to an immutable local authorization record and checks principal, agent, action, target and integer discount basis points before dispatch. Ed25519 keys are generated in memory for each runtime. The demo policy and its digest are synthetic fixtures.

All state is process local. Concurrent calls within one runtime admit one dispatch; this does not establish replay protection across processes, restarts or crashes. A timeout after a possible effect requires determination and does not trigger a blind retry. Simulator receipts and untrusted adapter claims remain distinct from authorization.

## Run locally

Use Node.js 20 or later and npm. Validation was performed on Windows x64 with Node.js 24.14.1.

```sh
npm ci --ignore-scripts
node verify-package.mjs
npm run test:glory
npm run test:containment
npm run poc:glory -- --discount-bps 700
```

Mutation scenarios include `--missing-proof`, `--tamper-proof`, `--execution-target`, `--execution-bps`, `--execution-action`, `--execution-principal`, `--execution-agent`, `--repeat`, `--downstream reject`, `--downstream timeout_after_effect` and `--adapter-claim SUCCEEDED`.

The demonstration does not execute financial transactions or validate proprietary production components. See [REPRODUCIBILITY.md](REPRODUCIBILITY.md) for the validation boundary and [PUBLIC_DISCLOSURE_MATRIX.json](PUBLIC_DISCLOSURE_MATRIX.json) for the complete approved file inventory.

## Integrity and rights

`PACKAGE_MANIFEST.json` records SHA-256, byte length and Git blob ID for every payload file. `SHA256SUMS` also covers the manifest. Self-referential integrity files are excluded where necessary; the new release commit binds the entire tree. These are file integrity checks, not a publisher signature or an external review endorsement.

This repository has independent Git history. Historical evidence is retained separately under private access. Public visibility grants no additional license; see [LICENSE.md](LICENSE.md).
