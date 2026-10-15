# RC1 reproducibility and validation boundary

Release: `VECTORRAIL_GLORY_RC1_SANITIZED_R1`.

Run the commands in README.md from a fresh checkout. `npm ci --ignore-scripts` installs the exact public-registry dependencies in the lockfile. No dependency installation or build step accesses a private repository. `private: true` prevents accidental npm publication; it does not restrict GitHub visibility.

The public suites contain 31 original acceptance tests and six containment regressions. The regressions include 32 simultaneous same-authorization calls and a separate 32-call timeout-after-effect case. Each case must issue exactly one request and produce one simulated effect. Concurrency is tested in one JavaScript process and runtime, not as distributed coordination.

Acceptance covers intent validation, trusted delegation, signed proof issuance and verification, exact action binding, mutation and replay refusal, simulated downstream evidence and indeterminate outcomes. The containment suite also rejects unsupported scopes, unknown proof fields, payload accessors, decision substitution and cross-runtime key substitution.

Before release, local validation additionally compares 12 CLI scenarios and 100 supported proof identities with the preserved RC1 reference, regenerates the sanitized package twice, and checks adversarial package mutations. The reference and private remediation records are not release dependencies. Those local comparisons establish the stated bounded compatibility only; they do not validate economic behavior or production systems. Earlier audit results are preliminary evidence and are kept separate from the release validation.

`node verify-package.mjs` independently recomputes payload SHA-256 and Git blob IDs, validates the complete disclosure inventory and rejects unknown files, malformed paths, private inputs and unresolved source imports. It checks each locked package for a public registry URL and an integrity value. `.git` and the locally installed root `node_modules` directory are excluded from the working-tree file inventory. No dependency code is vendored in this release.

Git stores the exact release bytes: `.gitattributes` disables text conversion, and the release is staged with `core.autocrlf=false`. The manifest excludes itself and SHA256SUMS to avoid recursion; SHA256SUMS excludes only itself. The release commit provides the final binding for both files. No legacy commits or tags are part of this history.

The independent disclosure check uses a separately authored verifier and per-file review; it is not a third-party certification. Secret-pattern scans and dependency audit results describe the inspected version and cannot guarantee detection of every unknown issue. The fixture policy is the only implemented policy in this package.
