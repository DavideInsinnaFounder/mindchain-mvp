# Architecture Overview

This document intentionally describes Mindchain / VectorRail at a **high level**. It is not an implementation specification.

## Core thesis

> **AI Decision ≠ Authorization to Execute**

A model, agent or machine may determine that an action is useful or desirable. VectorRail treats the authority to execute that action as a separate concern.

## Conceptual lifecycle

```text
Intent
  ↓
Policy Evaluation
  ↓
Authorization
  ↓
Admission
  ↓
Protected Execution
  ↓
Evidence
```

## Core separation principles

- Capability ≠ Authority
- Identity ≠ Authority
- Agent ≠ Principal
- Authorization ≠ Admission
- Authorization ≠ Execution
- Authorization ≠ Settlement
- Success ≠ Compliance

## Neutrality goals

VectorRail is designed to remain model-agnostic, hardware-agnostic, protocol-agnostic, infrastructure-agnostic, domain-agnostic and partner-integrable.

## What VectorRail is not

VectorRail is not intended to be an AI model, agent marketplace, blockchain, payment rail, identity provider, or replacement for MCP, A2A or similar communication standards.

Its focus is the authorization and protected-execution boundary across independently operated systems.

## Public disclosure boundary

Implementation-level details — including internal schemas, lock ordering, security hardening, exhaustive tests, failure injection and transaction mechanics — are intentionally not part of this public architecture overview.

Website: https://www.vectorrail.cloud/
