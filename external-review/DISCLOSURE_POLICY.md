# External Review Disclosure Policy

The VectorRail External Review Room is a deliberately bounded public surface.

## Default rule

Public review metadata does not imply publication of proprietary implementation.

Executable material may be published only when all of the following are true:

1. the review purpose requires execution;
2. the exported dependency closure has been identified;
3. unrelated private engineering material has been removed;
4. secrets, credentials and private keys are absent;
5. the export does not expose Token T4, private roadmap material or unrelated POCs;
6. the package manifest identifies the frozen private-source tag and commit;
7. known differences between source and export are documented;
8. the publication has been explicitly classified as safe to disclose.

## Reviewer access principle

Reviewers should receive the minimum material necessary to falsify the stated claim.

No reviewer needs access to the complete private engineering repository merely because a bounded POC is under review.

## Intellectual-property boundary

Material published in this repository remains subject to the repository's stated copyright terms. Publication for review does not imply that unpublished VectorRail engineering, architecture, trade secrets or future work are disclosed or licensed.

Before any proprietary executable package is made public, intellectual-property and disclosure implications should be considered separately from technical reproducibility.
