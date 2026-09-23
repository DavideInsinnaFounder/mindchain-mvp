# Glory CRM Discount POC V1.2 — External Review RC1

Status: **FROZEN REVIEW CANDIDATE — EXECUTABLE EXPORT READY**

This directory identifies the exact RC1 baseline intended for independent external review.

## Frozen source baseline

- Source repository: private VectorRail engineering repository
- Source tag: `glory-poc-v1.2-external-review-rc1`
- Source commit: `2606358ab9a591b67f047a3b9a84032d2b5ffc9e`
- Boundary: frozen V1.2
- Source commit title: `feat: add executable Glory acceptance harness`

The source tag has been verified to resolve exactly to the source commit above.

## Review objective

Attempt to falsify the bounded Glory CRM Discount POC V1.2 candidate.

The review must not assume capabilities outside the frozen V1.2 boundary.

Any mismatch, ambiguity, missing dependency or unsupported claim should be reported as an explicit finding.

## External-package rule

This public review surface is deliberately isolated from the private engineering repository.

Only material required to review RC1 may be exported here. The private engineering repository, Token T4 work, unrelated POCs, private roadmap material, credentials, keys and non-RC1 engineering material are out of scope.

## Current package status

The bounded executable package is published at [`executable/`](./executable/).

The frozen executable package commit is:

`19b904f533604921ae9abbcad654e975e719218c`

The unsigned annotated public freeze tag is:

`glory-poc-v1.2-external-review-rc1-executable-export`

Its tag object is `f6688c70ceb893d5ea03db60d914bea84800001f`
and it resolves exactly to the executable package commit above.

**EXECUTABLE_EXPORT_READY = YES**

**DEPENDENCY_CLOSURE = VERIFIED**

**REPRODUCIBILITY = PASS**

**RC1_SEMANTICS_MODIFIED = NO**

**FROZEN SOURCE BASELINE IDENTIFIED = YES**

**SOURCE TAG VERIFIED = YES**

**SOURCE COMMIT VERIFIED = YES**

**V1.2 BOUNDARY CHANGED = NO**

These statuses are publication-gate results, not an external-review PASS.
Glory's falsification review has not yet occurred.
