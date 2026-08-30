# Project Status

**Public status — 30 August 2026**

Mindchain is the experimental implementation foundation of the VectorRail authorization architecture. The project is under active development and is **not production-ready**.

## Validated foundations

At a public, non-sensitive level, the current implementation has validated foundations for authenticated authorization requests, separation between authorization/admission/execution, protected execution boundaries, replay-resistant handling, deterministic evidence and result handling, durable authority state, concurrency/restart behavior and controlled failure handling.

## Validation

**960 deterministic lifecycle tests — PASS**

Additional focused suites cover gateway, protected-service, integration and durability behavior. Detailed test code, fixtures, failure injection, race conditions and internal validation methods are intentionally maintained privately.

## Current engineering focus

Current private engineering work is focused on durable protected execution and formal economic/accounting architecture validation across concurrency, restart, controlled failure and recovery boundaries.

## Token / economic architecture status

The Token track remains architecture-only and does **not** represent a live Token, wallet, blockchain, payment rail or settlement system.

Current public-safe milestone status:

- T1 — Token Architecture Gate: **Closed**
- T1.5 — Token Architecture Convergence Gate: **Closed**
- T2 — Economic Lifecycle Architecture: **Closed**
- T3 — Wallet and Balance Authority Architecture: **Closed**
- T4 — Accounting / handoff architecture: **In formalization and adversarial validation; not implemented**
- T5 — Token Transfer Protocol: **Not started**

The current T4 work is specifically aimed at proving that the architecture can be represented as a deterministic, mechanically checkable specification before any implementation is authorized. Internal formal-kernel, authority, conflict, recovery and validation details remain private.

See [Token Architecture Status](docs/TOKEN_ARCHITECTURE_STATUS.md).

## Explicit limits

The current system should not be described as production-ready, a universal exactly-once execution system, a blockchain, a payment or settlement network, a legal/clinical/regulatory authority, a replacement for agent communication protocols, or a general-purpose identity provider.

The Token architecture must also not be described as an issued crypto asset, investment product, deployed blockchain, live wallet system, provider-payment rail or settlement mechanism.

## Website

https://www.vectorrail.cloud/
