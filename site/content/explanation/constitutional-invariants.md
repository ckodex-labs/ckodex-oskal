---
title: "The Ten Constitutional Invariants"
description: "Exhaustive breakdown of the ten non-negotiable architectural invariants governing the OSKAL continuous assurance runtime."
quadrant: "explanation"
tier: "E5"
invariant: "Hard invariants dominate scores: never average away critical contradictions"
---

## Overview

The OSKAL architecture is governed by ten constitutional invariants (I-01 through I-10). These invariants are enforced across the pure Semantic Kernel, the hexagonal adapters, and the gRPC API. Any violation is treated as a fatal state corruption and triggers immediate quarantine.

---

## The Invariants Matrix

| ID | Name | Core Mandate | Architectural Realization |
| :--- | :--- | :--- | :--- |
| **I-01** | **Mapping Is Not Compliance** | Writing a mapping between a control and a resource does not make the resource compliant. | Requires active `EvidenceContract` evaluation against authentic runtime observations. |
| **I-02** | **Absence of Evidence is UNKNOWN** | Missing evidence or unobserved metrics must NEVER evaluate to `PASS`. Fake claims are strictly prohibited. | Querying unobserved subjects returns `UNKNOWN` and empty Merkle roots. |
| **I-03** | **Contextual Evidence** | Evidence is valid only within its bound context: Subject + Epoch + Policy + Timestamp. | Changing any dimension invalidates the active `AssuranceEpoch`. |
| **I-04** | **Explainability Mandate** | Every assurance claim must be decomposable into machine-verifiable atomic proofs. | Section 51 Explain Graph exposed via `ExplainClaim` RPC and CLI. |
| **I-05** | **Bounded Exceptions** | Derogations must be explicitly authorized, temporally bounded, and carry active compensating controls. Permanent exceptions are rejected. | `ControlException` CRD enforces mandatory expiration and approver SPIFFE IDs. |
| **I-06** | **Derived Projections** | OSCAL documents must be projected from the evidence graph, never hand-edited as truth. | OSCAL 1.2.3 Assessment Results generated dynamically from `ClaimEvaluation` records. |
| **I-07** | **Temporal Assurance** | Workload mutations immediately invalidate assurance (`ASSURED -> STALE`). | Kubernetes generation tracking triggers immediate epoch drift invalidation. |
| **I-08** | **Separation of Concerns** | Enforcement mechanisms (CEL admission) and assessment mechanisms (evidence evaluation) must remain distinct. | Independent preventive admission and detective runtime adapters. |
| **I-09** | **Runtime Truth Outranks Intent** | In case of conflict between declarative configuration and runtime telemetry, runtime observation dominates. | Tetragon kernel telemetry overrides declared PodSecurityContext. |
| **I-10** | **Explicit Authority** | Evidence producers must establish cryptographic identity before their observations can be admitted. | SPIFFE/SPIRE X.509 SVID authentication and trust domain validation. |

---

## Invariant Dominance Law

In scoring and compliance calculations, hard invariants dominate:

$$\text{If } \exists \text{ Invariant Violation} \implies \text{State} = \text{NON-CONFORMANT}$$

A system with 99 passing checks and 1 mandatory invariant violation does not score 99%; it is immediately flagged as non-conformant.
