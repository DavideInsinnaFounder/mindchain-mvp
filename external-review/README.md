# VectorRail External Review Room

This directory is the public, bounded review surface for independent technical reviewers and external developers.

It is intentionally separated from the private VectorRail engineering repository.

## Purpose

The External Review Room exists to support reproducible review of explicitly frozen candidates without exposing unrelated private engineering material.

Each review package must declare:

- the review purpose;
- the frozen source tag and source commit;
- the allowed claims;
- the prohibited claims;
- the files included in the external package;
- known limitations;
- whether execution is reproducible from this public package.

## Security and disclosure rules

1. No private repository access is implied by material published here.
2. Only the minimum material required for the stated review may be exported.
3. Secrets, credentials, private keys, internal roadmaps and unrelated engineering work must never be included.
4. A public review package must not silently expand the scope of the frozen candidate.
5. Any difference between the private source candidate and the exported review package must be explicitly documented.
6. Review findings must be tied to the package manifest and frozen baseline.
7. A reviewer may challenge implementation, specification, abstraction, threat model and system boundary.
8. A critical PASS is treated as a request for falsification, not confirmation.

## Current review packages

- `glory/rc1/` — Glory CRM Discount POC V1.2 external review package metadata and review boundary.

Future external reviews should receive their own subdirectory and manifest.

Project: VectorRail  
Website: https://vectorrail.cloud
