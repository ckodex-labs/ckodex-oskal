# ADR-001: Bounded Contexts for OSKAL, XOSCAL, and Assurance Core

**Status:** Accepted  
**Date:** 2026-09-23  
**Authors:** Codex Architectural Guild  
**Classification:** CKODEX Architecture Decision Record  

---

## 1. Context

In cloud-native security and compliance automation, frameworks frequently collapse standards interoperability, domain assurance semantics, and platform-specific realization into a single monolithic layer. This leads to severe architectural debt:
- OSCAL generation tools become tightly coupled to Kubernetes APIs (e.g. reading CRDs directly to spit out JSON).
- Policy engines (Kyverno, Gatekeeper, OPA) become conflated with control satisfaction (e.g. equating "policy passed" with "control implemented and verified").
- The domain semantics of assurance cannot be reused for non-Kubernetes targets such as AI agents, Linux hosts, or CI/CD pipelines.

## 2. Decision

We establish three strictly decoupled bounded contexts with unidirectional dependency flow:

```text
Kubernetes Runtime / Substrate
      │
      ▼
OSKAL Adapters & Controllers
      │
      ▼
CKODEX Assurance Core (Pure Domain Semantics)
      │
      ▼
XOSCAL Projection (Standards Mapping & Serialization)
      │
      ▼
OSCAL v1.2.3 Specification Artifacts
```

### Context 1: XOSCAL (Standards Interoperability)
- **Scope:** OSCAL v1.2.3 parsing, schema validation, serialization, profiles, catalogs, component definitions, system security plans (SSP), assessment plans, assessment results, POA&Ms, and cross-framework mapping definitions.
- **Invariants:** XOSCAL MUST NOT import or require Kubernetes APIs or runtime substrates. It is a pure standards interoperability engine.

### Context 2: CKODEX Assurance Core (Pure Domain Semantics)
- **Scope:** The technology-neutral semantic kernel of continuous assurance. Owns aggregates and value objects: `SubjectRef`, `ControlRef`, `ControlObjective`, `AtomicControl`, `ImplementationBinding`, `EvidenceContract`, `Observation`, `Evidence`, `EvidenceRef`, `EvidenceProducer`, `Claim`, `ClaimEvaluation`, `Finding`, `ControlException`, `AssuranceEpoch`, `AssuranceState`, `AssuranceVector`, and `ControlReceipt`.
- **Invariants:** The Assurance Core MUST NOT import Kubernetes packages (`k8s.io/*`), cloud SDKs, or database drivers. It operates purely on domain invariants, state machines, and cryptographic digests.

### Context 3: OSKAL (Kubernetes Realization)
- **Scope:** Discovers Kubernetes workload subjects, digests manifest and runtime states, reconciles control bindings and evidence contracts, ingests observations from admission controllers (CEL), runtime telemetry (Tetragon, Cilium), workload identity (SPIFFE/SPIRE), and supply chain (Sigstore/Cosign), calculates assurance epochs, invalidates stale state, and projects summarized assurance status back into Kubernetes custom resources.
- **Invariants:** OSKAL acts as an adapter and orchestrator. It does not reinvent assurance domain logic; it adapts Kubernetes reality into Assurance Core primitives.

## 3. Consequences

### Positive:
- **Portability:** The Assurance Core can be reused across Kubernetes, bare metal Linux, cloud VMs, AI models (via SHIELD), and serverless environments without rewriting evaluation rules.
- **Stability:** Changes in Kubernetes API versions or admission mechanisms do not break the assurance domain model or OSCAL export pipelines.
- **Clarity:** Clear division of authority between what is observed, what is evaluated, and how it is formatted for auditors.

### Negative / Trade-offs:
- Requires explicit mapping adapters between Kubernetes resources and canonical subjects.
- Requires conversion layers between internal claim evaluations and OSCAL Assessment Results.
