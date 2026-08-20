# Architecture Overview

This document intentionally describes Mindchain / VectorRail at a **high level**. It is not an implementation specification.

## Core thesis

> **AI Decision ≠ Authorization to Execute**

A model, agent or machine may determine that an action is useful or desirable. VectorRail treats the authority to execute that action as a separate concern.

> **VectorRail is not another agent communication protocol. It is intended to sit between the intent to act and the protected execution of that action.**

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

## Conceptual position in a typical stack

```text
AI Model / Agent
       |
       | proposes an action
       v
Application / Orchestrator
       |
       | execution request
       v
+------------------------------+
|       VectorRail Boundary    |
|                              |
|     Authority + Policy       |
|            |                 |
|       Authorization          |
|            |                 |
|         Admission            |
+-------------+----------------+
              |
              | admitted protected action
              v
       Protected Service
              |
              v
           Evidence
```

| Layer | Primary role |
| --- | --- |
| AI model / agent | Decides or proposes what to do |
| Application / orchestrator | Coordinates workflow and requests actions |
| MCP / A2A / tool protocols | Enable communication, interoperability and tool invocation |
| IAM / identity systems | Establish who or what is authenticated |
| VectorRail | Governs whether a specific protected action may be authorized and admitted to execution |
| Protected service | Performs the protected action |
| Payment / settlement systems | Handle any resulting economic transfer or settlement |

## Abstract example

- An agent proposes a protected action.
- The surrounding application submits the request.
- VectorRail evaluates whether that action may be authorized and admitted under the applicable authority and policy context.
- Only an admitted action reaches protected execution.
- Resulting evidence remains distinct from the authorization decision.

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
