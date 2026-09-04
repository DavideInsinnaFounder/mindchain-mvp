# VectorRail Permanent Review Rule — Tenth Man / Assumption Breaker

Status: NORMATIVE / PERMANENT

## Mandatory Adversarial Reversal Rule

Whenever a critical invariant, architecture property, security property, recovery property, economic property, or Gate obtains PASS, at least one independent review MUST have the explicit objective of producing FAIL.

A PASS supported only by confirmatory review is insufficient for final closure.

## Tenth-Man Assumption Challenge Rule

The Tenth Man / Assumption Breaker MUST NOT limit review to whether the implementation correctly follows the specification.

The reviewer MUST also challenge:
- the specification itself;
- the abstractions selected by the specification;
- the categories used to represent the problem;
- the threat model;
- the system boundary;
- the authority, state, and economic models;
- the mental model from which implementation decisions were derived.

Mandatory questions:

1. Does the code correctly implement the rule?
2. Is the rule itself complete and correct?
3. Is the abstraction used by the rule the right abstraction for the real-world property being protected?
4. What would have to be true for the current PASS to be wrong?
5. Can that alternative hypothesis be converted into a reproducible adversarial test?

## Closure Reversal Rule

A Tenth-Man review MAY reopen a Gate that previously obtained PASS when it demonstrates credible evidence that the underlying model, specification, or abstraction is incomplete.

## Failure Taxonomy

- Implementation Failure: implementation does not satisfy the current specification.
- Specification Failure: specification is incomplete, inconsistent, ambiguous, or insufficient.
- Model Failure: the abstraction or mental model underlying the specification does not correctly represent the real problem.

Model Failure is the deepest class because all implementation tests can remain green while the real invariant is still false.

## Required Review Sequence

Implementation
→ Test
→ Independent Review
→ Red Team
→ Tenth Man / Assumption Breaker
→ Regression
→ Closure

Reviewer: "Does the code satisfy the specification?"

Red Team: "Can the implementation be bypassed?"

Tenth Man: "What if the specification or the underlying model is wrong?"

## Falsification Before Modification

Preferred order:

Repository checkpoint
→ Gap analysis
→ Adversarial test
→ Failure classification
→ Smallest sufficient change
→ Targeted regression
→ Full relevant regression
→ Separate commit

Where practicable, the adversarial test SHOULD demonstrate RED before the corrective implementation is applied.

## Evidence Standard

The Tenth Man MUST try to falsify the claim, but MUST NOT create complexity merely for the sake of disagreement.

A finding should be based on at least one of:
- a reproducible counterexample;
- a failing adversarial test;
- a demonstrable invariant violation;
- a concrete execution path;
- a technically plausible causal chain showing why the claimed property cannot currently be proven.

If no such evidence can be established, the existing PASS remains valid.

## Permanent Operating Principle

**A critical PASS is not a request for confirmation. It is a request for falsification.**

**The Tenth Man must not only ask whether the solution is wrong. The Tenth Man must ask whether the problem has been modelled incorrectly.**
